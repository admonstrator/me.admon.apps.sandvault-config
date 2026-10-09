import NIOCore
import SandvaultCore

/// Transparent TLS listener: buffers the ClientHello, decides on its SNI, then replays the buffered bytes
/// to `<sni>:443` (tunnel) or into a local TLS server (inspection). Without SNI (`curl https://1.1.1.1`) the host
/// is the address the sandbox socket connects to, as lsof sees it; when that is unknown, the connection is refused.
final class SNIRouter: ChannelInboundHandler, RemovableChannelHandler {
    typealias InboundIn = ByteBuffer

    private enum State { case collecting, deciding, done }

    private let runtime: NetRuntime
    private let counter: ByteCounter
    private var buffer: ByteBuffer?
    private var state = State.collecting

    init(runtime: NetRuntime, counter: ByteCounter) {
        self.runtime = runtime
        self.counter = counter
    }

    func channelRead(context: ChannelHandlerContext, data: NIOAny) {
        var incoming = unwrapInboundIn(data)
        if buffer == nil { buffer = incoming } else { buffer!.writeBuffer(&incoming) }
        guard state == .collecting, let buffer else { return }

        switch ClientHelloParser.parse(Array(buffer.readableBytesView)) {
        case .needMoreData:
            return
        case .invalid(let why):
            reject(host: "(unknown)", reason: "not a TLS ClientHello: \(why)", context: context)
        case .complete(nil):
            decideWithoutSNI(context: context)
        case .complete(let name?):
            let host = HostName.normalize(name)
            guard HostName.isValid(host) else {
                return reject(host: "(invalid SNI)", reason: "invalid server name", context: context)
            }
            decide(host: host, context: context)
        }
    }

    func channelInactive(context: ChannelHandlerContext) {
        if state == .collecting, let buffer, buffer.readableBytes > 0 {
            record(host: "(incomplete ClientHello)", reason: "closed before the ClientHello was complete")
        }
        context.fireChannelInactive()
    }

    private func decide(host: String, context: ChannelHandlerContext) {
        state = .deciding
        try? context.channel.syncOptions?.setOption(ChannelOptions.autoRead, value: false)
        let runtime = self.runtime
        let clientPort = context.channel.remoteAddress?.port.map { UInt16(truncatingIfNeeded: $0) }
        let upstreamPort = runtime.transparentTLSPort
        context.eventLoop.makeFutureWithTask {
            await runtime.authorize(host: host, port: 443, kind: .transparentTLS, clientPort: clientPort)
        }
        .assumeIsolated()
        .whenSuccess { result in
            let tracker = runtime.track(result, kind: .transparentTLS)
            let addresses = result.addresses.map { (try? $0.withPort(upstreamPort)) ?? $0 }
            switch result.verdict {
            case .deny, .fail:
                if result.verdict == .fail { runtime.logger("transparent TLS \(host): \(result.reason)") }
                tracker.finish(bytesIn: 0, bytesOut: Int64(self.buffer?.readableBytes ?? 0))
                self.state = .done
                context.close(promise: nil)
            case .allow where result.inspect:
                self.inspect(host: host, port: upstreamPort, addresses: addresses, tracker: tracker, context: context)
            case .allow:
                self.tunnel(host: host, port: upstreamPort, addresses: addresses, tracker: tracker, context: context)
            }
        }
    }

    private func decideWithoutSNI(context: ChannelHandlerContext) {
        state = .deciding
        try? context.channel.syncOptions?.setOption(ChannelOptions.autoRead, value: false)
        let runtime = self.runtime
        let clientPort = context.channel.remoteAddress?.port.map { UInt16(truncatingIfNeeded: $0) }
        context.eventLoop.makeFutureWithTask {
            await runtime.originalDestination(ofPort: clientPort, proto: .tcp)
        }
        .assumeIsolated()
        .whenSuccess { destination in
            guard let destination, destination.port == 443, HostName.isIPLiteral(destination.address),
                  !PrivateNetworks.loopback.contains(where: { $0.contains(destination.address) })
            else {
                return self.reject(host: "(no SNI)", reason: "ClientHello without server name, original destination unknown", context: context)
            }
            self.decide(host: HostName.normalize(destination.address), context: context)
        }
    }

    private func tunnel(host: String, port: Int, addresses: [SocketAddress], tracker: ConnectionTracker, context: ChannelHandlerContext) {
        Tunnel.connect(on: context.eventLoop, addresses: addresses, host: host, port: port)
            .assumeIsolated()
            .whenComplete { outcome in
                self.state = .done
                switch outcome {
                case .failure(let error):
                    self.runtime.logger("transparent TLS \(host):\(port): \(error)")
                    tracker.finish(bytesIn: 0, bytesOut: 0)
                    context.close(promise: nil)
                case .success(let upstream):
                    guard context.channel.isActive, let hello = self.buffer else {
                        upstream.close(promise: nil)
                        tracker.finish(bytesIn: 0, bytesOut: 0)
                        return
                    }
                    self.buffer = nil
                    upstream.writeAndFlush(hello, promise: nil)
                    do {
                        try Tunnel.glue(client: context.channel, upstream: upstream)
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

    private func inspect(host: String, port: Int, addresses: [SocketAddress], tracker: ConnectionTracker, context: ChannelHandlerContext) {
        state = .done
        do {
            try Tunnel.addInspection(
                to: context.channel, host: host, port: port, addresses: addresses, runtime: runtime, counter: counter, tracker: tracker
            )
            Tunnel.finish(tracker, counter: counter, client: context.channel, upstream: nil)
            if let hello = buffer {
                buffer = nil
                context.fireChannelRead(NIOAny(hello))
                context.fireChannelReadComplete()
            }
            _ = context.pipeline.syncOperations.removeHandler(context: context)
            try context.channel.syncOptions?.setOption(ChannelOptions.autoRead, value: true)
            context.channel.read()
        } catch {
            runtime.logger("inspect \(host): \(error)")
            context.close(promise: nil)
            tracker.finish(bytesIn: 0, bytesOut: 0)
        }
    }

    private func reject(host: String, reason: String, context: ChannelHandlerContext) {
        state = .done
        record(host: host, reason: reason)
        context.close(promise: nil)
    }

    private func record(host: String, reason: String) {
        runtime.logger("transparent TLS denied: \(reason)")
        let result = GateResult(verdict: .deny, host: host, port: 443, decision: .denied, reason: reason)
        let totals = counter.totals
        runtime.track(result, kind: .transparentTLS).finish(bytesIn: totals.sent, bytesOut: totals.received)
    }
}
