import NIOCore
import NIOHTTP1
import NIOPosix
import NIOSSL
import SandvaultCore

/// Forwards HTTP/1.1 requests from a client channel to upstream servers, one exchange at a time.
///
/// - `explicitProxy`: absolute-form requests, sent upstream in origin-form; one decision and record per request.
/// - `transparent`: origin-form requests redirected by pf; the host comes from the `Host` header.
/// - `inspected`: decrypted requests inside an allowed tunnel; fixed TLS upstream, summaries go to the tunnel's record.
///
/// Requests that arrive while an exchange is running are queued and read is paused, so pipelined requests
/// are answered in order. The upstream connection is reused while the target stays the same.
final class HTTPForwardHandler: ChannelInboundHandler, RemovableChannelHandler {
    typealias InboundIn = HTTPServerRequestPart
    typealias OutboundOut = HTTPServerResponsePart

    enum Mode {
        case explicitProxy
        case transparent
        case inspected(host: String, port: Int, addresses: [SocketAddress], tracker: ConnectionTracker)
    }

    struct Target: Equatable, Sendable {
        var host: String
        var port: Int
        var tls: Bool
    }

    private struct Exchange {
        var head: HTTPRequestHead
        var summary: HTTPSummary
        /// Per-request record (explicit and transparent modes).
        var tracker: ConnectionTracker?
        var startCounts: (received: Int64, sent: Int64)
        var responseStarted = false
        var upstreamKeepAlive = true
        var clientKeepAlive: Bool { head.isKeepAlive }
    }

    private enum State { case idle, waiting, streaming, responding, closed }

    private let runtime: NetRuntime
    private let mode: Mode
    private let counter: ByteCounter
    private var context: ChannelHandlerContext?
    private var state = State.idle
    private var queue = CircularBuffer<HTTPServerRequestPart>()
    private var upstream: (target: Target, channel: Channel)?
    private var exchange: Exchange?
    /// Byte totals when the previous exchange ended; the next record counts from here (its request head included).
    private var boundary: (received: Int64, sent: Int64) = (0, 0)

    init(runtime: NetRuntime, mode: Mode, counter: ByteCounter) {
        self.runtime = runtime
        self.mode = mode
        self.counter = counter
    }

    private var kind: ConnectionKind {
        switch mode {
        case .explicitProxy: .explicitProxy
        case .transparent: .transparentHTTP
        case .inspected: .transparentTLS
        }
    }

    // MARK: - Client side

    func handlerAdded(context: ChannelHandlerContext) {
        self.context = context
    }

    func handlerRemoved(context: ChannelHandlerContext) {
        self.context = nil
    }

    func channelRead(context: ChannelHandlerContext, data: NIOAny) {
        queue.append(unwrapInboundIn(data))
        drain(context: context)
    }

    func channelInactive(context: ChannelHandlerContext) {
        state = .closed
        upstream?.channel.close(promise: nil)
        upstream = nil
        finishExchange()
        context.fireChannelInactive()
    }

    func errorCaught(context: ChannelHandlerContext, error: Error) {
        context.close(promise: nil)
    }

    func channelWritabilityChanged(context: ChannelHandlerContext) {
        // Download backpressure: stop reading upstream while the client cannot keep up.
        upstream?.channel.setOption(ChannelOptions.autoRead, value: context.channel.isWritable).whenFailure { _ in }
        context.fireChannelWritabilityChanged()
    }

    private func drain(context: ChannelHandlerContext) {
        while true {
            switch state {
            case .idle:
                guard let part = queue.popFirst() else { return }
                // Body parts of a request that was already answered are dropped.
                if case .head(let head) = part { begin(head, context: context) }
            case .streaming:
                guard let part = queue.popFirst(), let channel = upstream?.channel else { return }
                switch part {
                case .head:
                    break
                case .body(let buffer):
                    channel.write(HTTPClientRequestPart.body(.byteBuffer(buffer)), promise: nil)
                case .end(let trailers):
                    channel.writeAndFlush(HTTPClientRequestPart.end(trailers), promise: nil)
                    state = .responding
                    setReading(false, context: context)
                }
            case .waiting, .responding, .closed:
                return
            }
        }
    }

    private func begin(_ head: HTTPRequestHead, context: ChannelHandlerContext) {
        state = .waiting
        setReading(false, context: context)
        let redact = Set(runtime.policy.snapshot.policy.inspection.redactHeaders.map { $0.lowercased() })
        let startCounts = boundary

        switch mode {
        case .explicitProxy:
            if head.method == .CONNECT {
                return fail(.badRequest, "CONNECT must be the first request on a proxy connection\n", context: context)
            }
            guard let url = HTTPRewrite.parseAbsolute(head.uri) else {
                return fail(.badRequest, "sandvault-config proxy expects absolute http:// URLs (use CONNECT for https)\n", context: context)
            }
            let outgoing = Self.outgoingHead(head, uri: url.originForm, host: url.authority)
            let summary = HTTPSummary(method: head.method.rawValue, url: url.display, requestHeaders: HTTPRewrite.summarize(head.headers, redact: redact))
            exchange = Exchange(head: head, summary: summary, startCounts: startCounts)
            authorize(host: url.host, port: url.port, outgoing: outgoing, context: context)

        case .transparent:
            guard let hostHeader = head.headers.first(name: "host"),
                  let (rawHost, _) = HostName.splitHostPort(hostHeader), HostName.isValid(HostName.normalize(rawHost))
            else {
                return fail(.badRequest, "missing or invalid Host header\n", context: context)
            }
            let host = HostName.normalize(rawHost)
            let outgoing = Self.outgoingHead(head, uri: head.uri, host: nil)
            let summary = HTTPSummary(
                method: head.method.rawValue, url: "http://\(hostHeader)\(head.uri)",
                requestHeaders: HTTPRewrite.summarize(head.headers, redact: redact)
            )
            exchange = Exchange(head: head, summary: summary, startCounts: startCounts)
            authorize(host: host, port: runtime.transparentHTTPPort, outgoing: outgoing, context: context)

        case .inspected(let host, let port, let addresses, _):
            let outgoing = Self.outgoingHead(head, uri: head.uri, host: nil)
            let authority = port == 443 ? host : "\(host):\(port)"
            let summary = HTTPSummary(
                method: head.method.rawValue, url: "https://\(authority)\(head.uri)",
                requestHeaders: HTTPRewrite.summarize(head.headers, redact: redact)
            )
            exchange = Exchange(head: head, summary: summary, startCounts: startCounts)
            send(outgoing, to: Target(host: host, port: port, tls: true), addresses: addresses, context: context)
        }
    }

    /// Policy decision for explicit and transparent requests; the policy port is the request's port.
    private func authorize(host: String, port: Int, outgoing: HTTPRequestHead, context: ChannelHandlerContext) {
        let runtime = self.runtime
        let kind = self.kind
        let clientPort = context.channel.remoteAddress?.port.map { UInt16(truncatingIfNeeded: $0) }
        let policyPort = UInt16(clamping: kind == .transparentHTTP ? 80 : port)
        context.eventLoop.makeFutureWithTask {
            await runtime.authorize(host: host, port: policyPort, kind: kind, clientPort: clientPort)
        }
        .assumeIsolated()
        .whenSuccess { result in
            guard self.state == .waiting, self.context != nil else { return }
            let tracker = runtime.track(result, kind: kind)
            self.exchange?.tracker = tracker
            switch result.verdict {
            case .deny:
                self.fail(.forbidden, NetRuntime.denialMessage(result), context: context)
            case .fail:
                self.fail(.badGateway, "sandvault-config could not reach \(host):\(port): \(result.reason)\n", context: context)
            case .allow:
                let addresses = result.addresses.map { (try? $0.withPort(port)) ?? $0 }
                self.send(outgoing, to: Target(host: host, port: port, tls: false), addresses: addresses, context: context)
            }
        }
    }

    private func send(_ head: HTTPRequestHead, to target: Target, addresses: [SocketAddress], context: ChannelHandlerContext) {
        if let upstream, upstream.target == target, upstream.channel.isActive {
            startStreaming(head, channel: upstream.channel, context: context)
            return
        }
        upstream?.channel.close(promise: nil)
        upstream = nil
        connect(to: target, addresses: addresses, context: context).assumeIsolated().whenComplete { result in
            guard self.state == .waiting, self.context != nil else {
                if case .success(let channel) = result { channel.close(promise: nil) }
                return
            }
            switch result {
            case .success(let channel):
                self.upstream = (target, channel)
                self.startStreaming(head, channel: channel, context: context)
            case .failure(let error):
                self.fail(.badGateway, "sandvault-config could not connect to \(target.host):\(target.port): \(error)\n", context: context)
            }
        }
    }

    private func startStreaming(_ head: HTTPRequestHead, channel: Channel, context: ChannelHandlerContext) {
        channel.write(HTTPClientRequestPart.head(head), promise: nil)
        state = .streaming
        setReading(true, context: context)
        drain(context: context)
    }

    private func connect(to target: Target, addresses: [SocketAddress], context: ChannelHandlerContext) -> EventLoopFuture<Channel> {
        let me = NIOLoopBound(self, eventLoop: context.eventLoop)
        let tls: NIOSSLContext? = target.tls ? runtime.inspection.upstreamContext : nil
        return ClientBootstrap(group: context.eventLoop)
            .connectTimeout(.seconds(10))
            .resolver(FixedAddressResolver(eventLoop: context.eventLoop, addresses: addresses))
            .channelInitializer { channel in
                channel.eventLoop.makeCompletedFuture {
                    let sync = channel.pipeline.syncOperations
                    if let tls {
                        try sync.addHandler(NIOSSLClientHandler(context: tls, serverHostname: target.host))
                    }
                    try sync.addHandler(HTTPRequestEncoder())
                    try sync.addHandler(
                        ByteToMessageHandler(HTTPResponseDecoder(leftOverBytesStrategy: .dropBytes, informationalResponseStrategy: .forward))
                    )
                    try sync.addHandler(UpstreamResponseHandler(forwarder: me.value))
                }
            }
            .connect(host: target.host, port: target.port)
    }

    // MARK: - Upstream side (called by UpstreamResponseHandler on the same event loop)

    fileprivate func upstreamRead(_ part: HTTPClientResponsePart, from channel: Channel) {
        guard let context, upstream?.channel === channel, var current = exchange else { return }
        switch part {
        case .head(let head):
            let informational = (100..<200).contains(head.status.code) && head.status.code != 101
            var out = HTTPResponseHead(version: .http1_1, status: head.status, headers: HTTPRewrite.stripHopByHop(head.headers))
            if !informational {
                let redact = Set(runtime.policy.snapshot.policy.inspection.redactHeaders.map { $0.lowercased() })
                current.summary.status = Int(head.status.code)
                current.summary.responseHeaders = HTTPRewrite.summarize(head.headers, redact: redact)
                current.upstreamKeepAlive = head.isKeepAlive
                current.responseStarted = true
                if !current.clientKeepAlive { out.headers.replaceOrAdd(name: "Connection", value: "close") }
            }
            exchange = current
            context.write(wrapOutboundOut(.head(out)), promise: nil)
        case .body(let buffer):
            context.write(wrapOutboundOut(.body(.byteBuffer(buffer))), promise: nil)
        case .end(let trailers):
            // A HEAD response has no body; the unpaired encoder would otherwise emit a chunk terminator.
            if current.head.method != .HEAD {
                context.write(wrapOutboundOut(.end(trailers)), promise: nil)
            }
            context.flush()
            completeExchange(context: context)
        }
    }

    fileprivate func upstreamReadComplete() {
        context?.flush()
    }

    fileprivate func upstreamClosed(_ channel: Channel) {
        guard upstream?.channel === channel else { return }
        upstream = nil
        guard let context, let current = exchange, state == .streaming || state == .responding else { return }
        if current.responseStarted {
            context.close(promise: nil)
        } else {
            fail(.badGateway, "sandvault-config: upstream closed the connection\n", context: context)
        }
    }

    private func completeExchange(context: ChannelHandlerContext) {
        guard let current = exchange else { return }
        finishExchange()
        if !current.upstreamKeepAlive {
            upstream?.channel.close(promise: nil)
            upstream = nil
        }
        guard current.clientKeepAlive else {
            state = .closed
            context.close(promise: nil)
            return
        }
        state = .idle
        setReading(true, context: context)
        drain(context: context)
    }

    /// Hands the summary to the right record and finishes a per-request record.
    private func finishExchange() {
        guard let current = exchange else { return }
        exchange = nil
        if case .inspected(_, _, _, let tunnel) = mode {
            tunnel.add(current.summary)
        } else if let tracker = current.tracker {
            let now = counter.totals
            boundary = now
            tracker.add(current.summary)
            tracker.finish(bytesIn: now.sent - current.startCounts.sent, bytesOut: now.received - current.startCounts.received)
        }
    }

    /// Answers with a plain-text error and closes the client connection.
    private func fail(_ status: HTTPResponseStatus, _ message: String, context: ChannelHandlerContext) {
        exchange?.summary.status = Int(status.code)
        if status == .badGateway { exchange?.tracker?.fail(message.trimmingCharacters(in: .whitespacesAndNewlines)) }
        let (head, body) = HTTPRewrite.errorResponse(status, body: message)
        context.write(wrapOutboundOut(.head(head)), promise: nil)
        context.write(wrapOutboundOut(.body(.byteBuffer(context.channel.allocator.buffer(string: body)))), promise: nil)
        context.writeAndFlush(wrapOutboundOut(.end(nil))).assumeIsolated().whenComplete { _ in
            context.close(promise: nil)
        }
        finishExchange()
        state = .closed
    }

    private func setReading(_ enabled: Bool, context: ChannelHandlerContext) {
        guard let options = context.channel.syncOptions else { return }
        try? options.setOption(ChannelOptions.autoRead, value: enabled)
        if enabled { context.read() }
    }

    static func outgoingHead(_ head: HTTPRequestHead, uri: String, host: String?) -> HTTPRequestHead {
        var headers = HTTPRewrite.stripHopByHop(head.headers)
        if let host, !headers.contains(name: "host") { headers.add(name: "Host", value: host) }
        return HTTPRequestHead(version: .http1_1, method: head.method, uri: uri, headers: headers)
    }
}

/// Last handler of an upstream pipeline; hands response parts to the forwarder.
final class UpstreamResponseHandler: ChannelInboundHandler {
    typealias InboundIn = HTTPClientResponsePart

    private let forwarder: HTTPForwardHandler

    init(forwarder: HTTPForwardHandler) {
        self.forwarder = forwarder
    }

    func channelRead(context: ChannelHandlerContext, data: NIOAny) {
        forwarder.upstreamRead(unwrapInboundIn(data), from: context.channel)
    }

    func channelReadComplete(context: ChannelHandlerContext) {
        forwarder.upstreamReadComplete()
    }

    func channelInactive(context: ChannelHandlerContext) {
        forwarder.upstreamClosed(context.channel)
    }

    func errorCaught(context: ChannelHandlerContext, error: Error) {
        context.close(promise: nil)
    }
}

extension SocketAddress {
    func withPort(_ port: Int) throws -> SocketAddress {
        guard let ip = ipAddress else { return self }
        return try SocketAddress(ipAddress: ip, port: port)
    }
}
