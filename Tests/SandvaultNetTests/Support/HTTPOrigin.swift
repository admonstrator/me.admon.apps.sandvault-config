import Foundation
import NIOCore
import NIOHTTP1
import NIOPosix

/// HTTP/1.1 origin on 127.0.0.1 on NIO's server pipeline, so it reads chunked requests: answers each request with
/// `reply`'s body, in `pieces` body parts and without Content-Length when `chunked` (the encoder then frames it in
/// chunks), and closes. Records the request bodies it received, after the transfer encoding.
struct HTTPOrigin {
    struct Reply: Sendable {
        var contentType: String
        var body: [UInt8]
        var chunked = false
        var pieces = 1
        var headers: [(String, String)] = []
    }

    let channel: Channel
    let port: Int
    let bodies: Recorded<[UInt8]>

    static func start(_ reply: Reply) async throws -> HTTPOrigin {
        let bodies = Recorded<[UInt8]>()
        let channel = try await ServerBootstrap(group: MultiThreadedEventLoopGroup.singleton)
            .childChannelInitializer { channel in
                channel.eventLoop.makeCompletedFuture {
                    try channel.pipeline.syncOperations.configureHTTPServerPipeline(withPipeliningAssistance: false)
                    try channel.pipeline.syncOperations.addHandler(HTTPOriginHandler(reply: reply, bodies: bodies))
                }
            }
            .bind(host: "127.0.0.1", port: 0)
            .get()
        return HTTPOrigin(channel: channel, port: channel.localAddress!.port!, bodies: bodies)
    }

    func stop() async {
        try? await channel.close()
    }
}

private final class HTTPOriginHandler: ChannelInboundHandler {
    typealias InboundIn = HTTPServerRequestPart
    typealias OutboundOut = HTTPServerResponsePart

    let reply: HTTPOrigin.Reply
    let bodies: Recorded<[UInt8]>
    var body: [UInt8] = []

    init(reply: HTTPOrigin.Reply, bodies: Recorded<[UInt8]>) {
        self.reply = reply
        self.bodies = bodies
    }

    func channelRead(context: ChannelHandlerContext, data: NIOAny) {
        switch unwrapInboundIn(data) {
        case .head:
            body = []
        case .body(let buffer):
            body += buffer.readableBytesView
        case .end:
            bodies.append(body)
            var headers = HTTPHeaders([("Content-Type", reply.contentType), ("Connection", "close")] + reply.headers)
            if !reply.chunked { headers.add(name: "Content-Length", value: String(reply.body.count)) }
            context.write(wrapOutboundOut(.head(HTTPResponseHead(version: .http1_1, status: .ok, headers: headers))), promise: nil)
            let size = max(1, (reply.body.count + reply.pieces - 1) / max(1, reply.pieces))
            var start = 0
            while start < reply.body.count {
                let piece = reply.body[start..<min(reply.body.count, start + size)]
                context.writeAndFlush(wrapOutboundOut(.body(.byteBuffer(context.channel.allocator.buffer(bytes: piece)))), promise: nil)
                start += size
            }
            context.writeAndFlush(wrapOutboundOut(.end(nil))).assumeIsolated().whenComplete { _ in context.close(promise: nil) }
        }
    }

    func errorCaught(context: ChannelHandlerContext, error: Error) {
        context.close(promise: nil)
    }
}
