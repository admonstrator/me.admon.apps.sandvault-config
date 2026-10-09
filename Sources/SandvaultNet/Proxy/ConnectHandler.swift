import NIOCore
import NIOHTTP1
import SandvaultCore

/// Handles `CONNECT host:port` as the first request of an explicit-proxy connection; passes every other
/// request on to the `HTTPForwardHandler` behind it. After an allowed CONNECT the HTTP handlers leave the
/// pipeline and the connection becomes a byte tunnel (or a decrypting one when the rule inspects).
final class ConnectHandler: ChannelInboundHandler, RemovableChannelHandler {
    typealias InboundIn = HTTPServerRequestPart
    typealias OutboundOut = HTTPServerResponsePart

    private enum State { case first, passthrough, awaitingEnd(HTTPRequestHead), deciding, done }

    private let runtime: NetRuntime
    private let counter: ByteCounter
    private var state = State.first

    init(runtime: NetRuntime, counter: ByteCounter) {
        self.runtime = runtime
        self.counter = counter
    }

    func channelRead(context: ChannelHandlerContext, data: NIOAny) {
        let part = unwrapInboundIn(data)
        switch state {
        case .first:
            if case .head(let head) = part, head.method == .CONNECT {
                state = .awaitingEnd(head)
                return
            }
            state = .passthrough
            context.fireChannelRead(data)
        case .passthrough:
            context.fireChannelRead(data)
        case .awaitingEnd(let head):
            if case .end = part { decide(head, context: context) }
        case .deciding, .done:
            break
        }
    }

    private func decide(_ head: HTTPRequestHead, context: ChannelHandlerContext) {
        state = .deciding
        try? context.channel.syncOptions?.setOption(ChannelOptions.autoRead, value: false)
        guard let (host, port) = HTTPRewrite.parseAuthority(head.uri) else {
            return respond(.badRequest, "invalid CONNECT target '\(head.uri)'\n", context: context)
        }
        let runtime = self.runtime
        let clientPort = context.channel.remoteAddress?.port.map { UInt16(truncatingIfNeeded: $0) }
        context.eventLoop.makeFutureWithTask {
            await runtime.authorize(host: host, port: UInt16(port), kind: .explicitProxy, clientPort: clientPort)
        }
        .assumeIsolated()
        .whenSuccess { result in
            let tracker = runtime.track(result, kind: .explicitProxy)
            switch result.verdict {
            case .deny:
                self.respond(.forbidden, NetRuntime.denialMessage(result), context: context, finishing: tracker)
            case .fail:
                tracker.fail(result.reason)
                self.respond(.badGateway, "sandvault-config could not reach \(host):\(port): \(result.reason)\n", context: context, finishing: tracker)
            case .allow where result.inspect:
                self.inspect(host: host, port: port, result: result, tracker: tracker, context: context)
            case .allow:
                self.tunnel(host: host, port: port, result: result, tracker: tracker, context: context)
            }
        }
    }

    private func tunnel(host: String, port: Int, result: GateResult, tracker: ConnectionTracker, context: ChannelHandlerContext) {
        Tunnel.connect(on: context.eventLoop, addresses: result.addresses, host: host, port: port)
            .assumeIsolated()
            .whenComplete { outcome in
                switch outcome {
                case .failure(let error):
                    tracker.fail("cannot connect: \(error)")
                    self.respond(
                        .badGateway, "sandvault-config could not connect to \(host):\(port): \(error)\n", context: context, finishing: tracker
                    )
                case .success(let upstream):
                    guard context.channel.isActive else {
                        upstream.close(promise: nil)
                        tracker.finish(bytesIn: 0, bytesOut: 0)
                        return
                    }
                    do {
                        try self.becomeRaw(context: context)
                        try Tunnel.glue(client: context.channel, upstream: upstream, tracker: tracker)
                        Tunnel.finish(tracker, counter: self.counter, client: context.channel, upstream: upstream)
                        try self.removeHTTPDecoder(context: context)
                    } catch {
                        self.runtime.logger("CONNECT \(host):\(port): \(error)")
                        upstream.close(promise: nil)
                        context.close(promise: nil)
                        tracker.finish(bytesIn: 0, bytesOut: 0)
                    }
                }
            }
    }

    private func inspect(host: String, port: Int, result: GateResult, tracker: ConnectionTracker, context: ChannelHandlerContext) {
        do {
            try becomeRaw(context: context)
            try Tunnel.addInspection(
                to: context.channel, host: host, port: port, addresses: result.addresses, runtime: runtime, counter: counter, tracker: tracker
            )
            Tunnel.finish(tracker, counter: counter, client: context.channel, upstream: nil)
            try context.channel.syncOptions?.setOption(ChannelOptions.autoRead, value: true)
            try removeHTTPDecoder(context: context)
            context.channel.read()
        } catch {
            runtime.logger("inspect \(host):\(port): \(error)")
            context.close(promise: nil)
            tracker.finish(bytesIn: 0, bytesOut: 0)
        }
    }

    /// Drops the forwarder and the response encoder, then answers `200` as raw bytes (the encoder would add
    /// body framing to a CONNECT response).
    private func becomeRaw(context: ChannelHandlerContext) throws {
        state = .done
        let sync = context.pipeline.syncOperations
        if let forwarder = try? sync.handler(type: HTTPForwardHandler.self) { _ = sync.removeHandler(forwarder) }
        if let encoder = try? sync.handler(type: HTTPResponseEncoder.self) { _ = sync.removeHandler(encoder) }
        let established = context.channel.allocator.buffer(string: "HTTP/1.1 200 Connection established\r\n\r\n")
        context.writeAndFlush(NIOAny(established), promise: nil)
    }

    /// Removes this handler and then the request decoder, whose buffered bytes (data the client sent right
    /// behind the CONNECT head) flow on to the handlers added behind it once the removal completes.
    /// The extra read-complete makes the glue flush them upstream.
    private func removeHTTPDecoder(context: ChannelHandlerContext) throws {
        let pipeline = context.pipeline
        let sync = pipeline.syncOperations
        let decoder = try sync.context(handlerType: ByteToMessageHandler<HTTPRequestDecoder>.self)
        _ = sync.removeHandler(context: context)
        sync.removeHandler(context: decoder).assumeIsolated().whenSuccess {
            pipeline.fireChannelReadComplete()
        }
    }

    /// Answers with a plain-text error, closes, and finishes `tracker` with the bytes of the exchange.
    private func respond(_ status: HTTPResponseStatus, _ message: String, context: ChannelHandlerContext, finishing tracker: ConnectionTracker? = nil) {
        state = .done
        let (head, body) = HTTPRewrite.errorResponse(status, body: message)
        context.write(wrapOutboundOut(.head(head)), promise: nil)
        context.write(wrapOutboundOut(.body(.byteBuffer(context.channel.allocator.buffer(string: body)))), promise: nil)
        let counter = self.counter
        context.writeAndFlush(wrapOutboundOut(.end(nil))).assumeIsolated().whenComplete { _ in
            let totals = counter.totals
            tracker?.finish(bytesIn: totals.sent, bytesOut: totals.received)
            context.close(promise: nil)
        }
    }
}
