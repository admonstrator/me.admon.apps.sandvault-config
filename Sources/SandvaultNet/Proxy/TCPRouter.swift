import NIOCore
import SandvaultCore

/// What the transparent TCP listener saw of the client's first bytes before deciding.
struct TCPPeek: Sendable, Equatable {
    var encryption: AskEncryption
    var serverName: String?
    var nameSource: AskName.Source?

    static let unknown = TCPPeek(encryption: .unknown)

    static let httpMethods = ["GET", "POST", "PUT", "HEAD", "DELETE", "OPTIONS", "PATCH", "CONNECT", "TRACE"].map { Array("\($0) ".utf8) }

    /// The verdict on `bytes`, or `nil` while more could still tell. `final`: nothing more will come in time.
    static func classify(_ bytes: [UInt8], final: Bool) -> TCPPeek? {
        guard let first = bytes.first else { return final ? .unknown : nil }
        if first == 0x16 {
            switch ClientHelloParser.parse(bytes) {
            case .needMoreData:
                return final ? TCPPeek(encryption: .tls) : nil
            case .invalid:
                return .unknown
            case .complete(let name):
                let host = name.map(HostName.normalize)
                guard let host, HostName.isValid(host) else { return TCPPeek(encryption: .tls) }
                return TCPPeek(encryption: .tls, serverName: host, nameSource: .tls)
            }
        }
        if httpMethods.contains(where: { bytes.starts(with: $0) }) {
            let end = bytes.firstRange(of: Array("\r\n\r\n".utf8))
            if end == nil, !final { return nil }
            let head = String(decoding: bytes[..<(end?.lowerBound ?? bytes.endIndex)], as: UTF8.self)
            guard let host = hostHeader(head) else { return TCPPeek(encryption: .plain) }
            return TCPPeek(encryption: .plain, serverName: host, nameSource: .http)
        }
        // A prefix of a method may still become a request line.
        if !final, httpMethods.contains(where: { $0.starts(with: bytes) }) { return nil }
        return .unknown
    }

    /// The `Host` header of a request head, without its port; `nil` when missing or not a valid name.
    static func hostHeader(_ head: String) -> String? {
        for line in head.split(separator: "\r\n").dropFirst() {
            guard let colon = line.firstIndex(of: ":"), line[..<colon].lowercased() == "host" else { continue }
            let value = line[line.index(after: colon)...].trimmingCharacters(in: .whitespaces)
            guard let host = HostName.splitHostPort(value).map({ HostName.normalize($0.host) }), HostName.isValid(host) else { return nil }
            return host
        }
        return nil
    }

    /// What goes to `NetRuntime.authorize` for the connection to `address`.
    func hint(address: String) -> ConnectionHint {
        ConnectionHint(address: address, serverName: serverName, nameSource: nameSource, encryption: encryption)
    }
}

/// Transparent TCP listener for every port other than 53, 80 and 443 (D37). Peeks at what the client sends for at
/// most `peekTime` (TLS ClientHello, HTTP request line, or nothing for server-speaks-first protocols like SSH), finds
/// the original destination by the client's port, decides, then connects to that address and port and splices.
/// The host it decides on is the SNI name when there is one, else the address.
final class TCPRouter: ChannelInboundHandler, RemovableChannelHandler {
    typealias InboundIn = ByteBuffer

    static let peekTime = TimeAmount.milliseconds(300)
    static let peekLimit = 16 * 1024

    private enum State { case peeking, deciding, done }

    private let runtime: NetRuntime
    private let counter: ByteCounter
    private var buffer: ByteBuffer?
    private var state = State.peeking
    private var timer: Scheduled<Void>?

    init(runtime: NetRuntime, counter: ByteCounter) {
        self.runtime = runtime
        self.counter = counter
    }

    func handlerAdded(context: ChannelHandlerContext) {
        if context.channel.isActive { startTimer(context: context) }
    }

    func channelActive(context: ChannelHandlerContext) {
        startTimer(context: context)
        context.fireChannelActive()
    }

    func channelRead(context: ChannelHandlerContext, data: NIOAny) {
        var incoming = unwrapInboundIn(data)
        if buffer == nil { buffer = incoming } else { buffer!.writeBuffer(&incoming) }
        guard state == .peeking, let buffer else { return }
        let bytes = Array(buffer.readableBytesView)
        if let peek = TCPPeek.classify(bytes, final: bytes.count >= Self.peekLimit) {
            decide(peek, context: context)
        }
    }

    func channelInactive(context: ChannelHandlerContext) {
        timer?.cancel()
        if state == .peeking, let buffer, buffer.readableBytes > 0 {
            state = .done
            record(host: "(unknown destination)", port: 0, reason: "closed before netd decided")
        }
        context.fireChannelInactive()
    }

    // MARK: - Internals

    private func startTimer(context: ChannelHandlerContext) {
        guard timer == nil, state == .peeking else { return }
        let loopBound = NIOLoopBound((self, context), eventLoop: context.eventLoop)
        timer = context.eventLoop.scheduleTask(in: Self.peekTime) {
            let (me, context) = loopBound.value
            guard me.state == .peeking else { return }
            let bytes = me.buffer.map { Array($0.readableBytesView) } ?? []
            me.decide(TCPPeek.classify(bytes, final: true) ?? .unknown, context: context)
        }
    }

    private func decide(_ peek: TCPPeek, context: ChannelHandlerContext) {
        state = .deciding
        timer?.cancel()
        try? context.channel.syncOptions?.setOption(ChannelOptions.autoRead, value: false)
        let runtime = self.runtime
        let clientPort = context.channel.remoteAddress?.port.map { UInt16(truncatingIfNeeded: $0) }
        context.eventLoop.makeFutureWithTask { () -> GateResult? in
            guard let destination = await runtime.originalDestination(ofPort: clientPort, proto: .tcp) else { return nil }
            let address = HostName.normalize(destination.address)
            guard HostName.isIPLiteral(address) else { return nil }
            guard !PrivateNetworks.loopback.contains(where: { $0.contains(address) }) else {
                return GateResult(
                    verdict: .deny, host: address, port: destination.port, decision: .denied,
                    reason: "original destination \(address) is loopback"
                )
            }
            let host = peek.encryption == .tls ? peek.serverName ?? address : address
            let kind = Self.kind(peek)
            return await runtime.authorize(
                host: host, port: destination.port, kind: kind, clientPort: clientPort, hint: peek.hint(address: address), destination: address
            )
        }
        .assumeIsolated()
        .whenSuccess { result in
            guard let result else {
                return self.reject(host: "(unknown destination)", port: 0, reason: "original destination unknown", context: context)
            }
            let tracker = runtime.track(result, kind: Self.kind(peek))
            switch result.verdict {
            case .deny, .fail:
                if result.verdict == .fail { tracker.fail(result.reason) }
                tracker.finish(bytesIn: 0, bytesOut: Int64(self.buffer?.readableBytes ?? 0))
                self.state = .done
                context.close(promise: nil)
            case .allow:
                let addresses = runtime.transparentTCPUpstream.map { [$0] } ?? result.addresses
                self.tunnel(host: result.host, addresses: addresses, tracker: tracker, context: context)
            }
        }
    }

    static func kind(_ peek: TCPPeek) -> ConnectionKind {
        peek.encryption == .tls ? .transparentTLS : .transparentTCP
    }

    private func tunnel(host: String, addresses: [SocketAddress], tracker: ConnectionTracker, context: ChannelHandlerContext) {
        Tunnel.connect(on: context.eventLoop, addresses: addresses, host: host, port: addresses.first?.port ?? 0)
            .assumeIsolated()
            .whenComplete { outcome in
                self.state = .done
                switch outcome {
                case .failure(let error):
                    tracker.fail("cannot connect: \(error)")
                    tracker.finish(bytesIn: 0, bytesOut: 0)
                    context.close(promise: nil)
                case .success(let upstream):
                    guard context.channel.isActive else {
                        upstream.close(promise: nil)
                        tracker.finish(bytesIn: 0, bytesOut: 0)
                        return
                    }
                    if let peeked = self.buffer, peeked.readableBytes > 0 { upstream.writeAndFlush(peeked, promise: nil) }
                    self.buffer = nil
                    do {
                        try Tunnel.glue(client: context.channel, upstream: upstream, tracker: tracker)
                        Tunnel.finish(tracker, counter: self.counter, client: context.channel, upstream: upstream)
                        _ = context.pipeline.syncOperations.removeHandler(context: context)
                    } catch {
                        upstream.close(promise: nil)
                        context.close(promise: nil)
                        tracker.finish(bytesIn: 0, bytesOut: 0)
                    }
                }
            }
    }

    private func reject(host: String, port: UInt16, reason: String, context: ChannelHandlerContext) {
        state = .done
        record(host: host, port: port, reason: reason)
        context.close(promise: nil)
    }

    private func record(host: String, port: UInt16, reason: String) {
        runtime.logger("transparent TCP denied: \(reason)")
        let result = GateResult(verdict: .deny, host: host, port: port, decision: .denied, reason: reason)
        let totals = counter.totals
        runtime.track(result, kind: .transparentTCP).finish(bytesIn: totals.sent, bytesOut: totals.received)
    }
}
