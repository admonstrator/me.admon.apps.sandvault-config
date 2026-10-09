import Foundation
import NIOCore
import NIOPosix
import NIOSSL
import SandvaultCore
@testable import SandvaultNet

/// Thread-safe list for things test servers and loggers observe.
final class Recorded<Element: Sendable>: @unchecked Sendable {
    private let lock = NSLock()
    private var items: [Element] = []

    func append(_ item: Element) { lock.withLock { items.append(item) } }
    var all: [Element] { lock.withLock { items } }
}

/// Minimal HTTP/1.1 origin on 127.0.0.1: reads one request, answers `<name> saw <method> <target>` and closes.
struct TestOrigin {
    let channel: Channel
    let port: Int
    /// Raw request heads as received.
    let heads: Recorded<String>

    static func start(name: String, tls: NIOSSLContext? = nil) async throws -> TestOrigin {
        let heads = Recorded<String>()
        let channel = try await ServerBootstrap(group: MultiThreadedEventLoopGroup.singleton)
            .childChannelInitializer { channel in
                channel.eventLoop.makeCompletedFuture {
                    if let tls { try channel.pipeline.syncOperations.addHandler(NIOSSLServerHandler(context: tls)) }
                    try channel.pipeline.syncOperations.addHandler(OriginHandler(name: name, heads: heads))
                }
            }
            .bind(host: "127.0.0.1", port: 0)
            .get()
        return TestOrigin(channel: channel, port: channel.localAddress!.port!, heads: heads)
    }

    func stop() async {
        try? await channel.close()
    }
}

/// Accepts on 127.0.0.1 and closes every connection at once without a byte: with `reset`, by an RST (SO_LINGER 0),
/// as a network filter does that drops a flow.
struct SilentOrigin {
    let channel: Channel
    let port: Int

    static func start(reset: Bool) async throws -> SilentOrigin {
        let channel = try await ServerBootstrap(group: MultiThreadedEventLoopGroup.singleton)
            .childChannelInitializer { channel in
                channel.eventLoop.makeCompletedFuture {
                    try channel.pipeline.syncOperations.addHandler(HangUpHandler(reset: reset))
                }
            }
            .bind(host: "127.0.0.1", port: 0)
            .get()
        return SilentOrigin(channel: channel, port: channel.localAddress!.port!)
    }

    func stop() async {
        try? await channel.close()
    }
}

private final class HangUpHandler: ChannelInboundHandler {
    typealias InboundIn = ByteBuffer

    let reset: Bool

    init(reset: Bool) {
        self.reset = reset
    }

    func channelRead(context: ChannelHandlerContext, data: NIOAny) {
        guard reset, let provider = context.channel as? SocketOptionProvider else { return context.close(promise: nil) }
        provider.setSoLinger(linger(l_onoff: 1, l_linger: 0)).assumeIsolated().whenComplete { _ in context.close(promise: nil) }
    }
}

private final class OriginHandler: ChannelInboundHandler {
    typealias InboundIn = ByteBuffer
    typealias OutboundOut = ByteBuffer

    let name: String
    let heads: Recorded<String>
    var received: [UInt8] = []
    var answered = false

    init(name: String, heads: Recorded<String>) {
        self.name = name
        self.heads = heads
    }

    func channelRead(context: ChannelHandlerContext, data: NIOAny) {
        received += unwrapInboundIn(data).readableBytesView
        guard !answered, let end = received.firstRange(of: Array("\r\n\r\n".utf8)) else { return }
        let head = String(decoding: received[..<end.lowerBound], as: UTF8.self)
        let length = head.split(separator: "\r\n")
            .first { $0.lowercased().hasPrefix("content-length:") }
            .flatMap { Int($0.split(separator: ":")[1].trimmingCharacters(in: .whitespaces)) } ?? 0
        guard received.count >= end.upperBound + length else { return }
        answered = true
        heads.append(head)
        let requestLine = head.split(separator: "\r\n").first.map(String.init) ?? ""
        let parts = requestLine.split(separator: " ")
        let body = "\(name) saw \(parts.first ?? "") \(parts.dropFirst().first ?? "")"
        let response = "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: \(body.utf8.count)\r\n"
            + "Set-Cookie: session=abc\r\nConnection: close\r\n\r\n\(body)"
        context.writeAndFlush(wrapOutboundOut(context.channel.allocator.buffer(string: response))).assumeIsolated().whenComplete { _ in
            context.close(promise: nil)
        }
    }

    func errorCaught(context: ChannelHandlerContext, error: Error) {
        context.close(promise: nil)
    }
}

/// Plain TCP (optionally TLS) client: sends bytes, returns everything received until the peer closes.
enum RawClient {
    static func exchange(
        port: Int, send: [UInt8], tls: NIOSSLContext? = nil, serverName: String? = nil, timeout: Int64 = 15
    ) async throws -> String {
        let loop = MultiThreadedEventLoopGroup.singleton.next()
        let promise = loop.makePromise(of: [UInt8].self)
        let channel: Channel
        do {
            channel = try await ClientBootstrap(group: loop)
                .channelInitializer { channel in
                    channel.eventLoop.makeCompletedFuture {
                        if let tls {
                            try channel.pipeline.syncOperations.addHandler(NIOSSLClientHandler(context: tls, serverHostname: serverName))
                        }
                        try channel.pipeline.syncOperations.addHandler(CollectHandler(promise: promise))
                    }
                }
                .connect(host: "127.0.0.1", port: port)
                .get()
        } catch {
            promise.fail(error)
            throw error
        }
        let timer = loop.scheduleTask(in: .seconds(timeout)) { channel.close(promise: nil) }
        defer { timer.cancel() }
        try await channel.writeAndFlush(channel.allocator.buffer(bytes: send)).get()
        return String(decoding: try await promise.futureResult.get(), as: UTF8.self)
    }

    static func exchange(port: Int, _ text: String, tls: NIOSSLContext? = nil, serverName: String? = nil) async throws -> String {
        try await exchange(port: port, send: Array(text.utf8), tls: tls, serverName: serverName)
    }
}

private final class CollectHandler: ChannelInboundHandler {
    typealias InboundIn = ByteBuffer

    let promise: EventLoopPromise<[UInt8]>
    var received: [UInt8] = []

    init(promise: EventLoopPromise<[UInt8]>) {
        self.promise = promise
    }

    func channelRead(context: ChannelHandlerContext, data: NIOAny) {
        received += unwrapInboundIn(data).readableBytesView
    }

    func channelInactive(context: ChannelHandlerContext) {
        promise.succeed(received)
    }

    func errorCaught(context: ChannelHandlerContext, error: Error) {
        // An unclean TLS shutdown still delivers what was received.
        context.close(promise: nil)
    }
}

/// DNS test client over UDP or TCP.
enum DNSClient {
    static func query(port: Int, name: String, type: UInt16 = DNSRecordType.a, tcp: Bool = false) async throws -> DNSMessage {
        let query = DNSMessage(id: UInt16.random(in: 1...0xFFFF), flags: 0x0100, questions: [DNSQuestion(name: name, type: type)]).encoded()
        let server = try SocketAddress(ipAddress: "127.0.0.1", port: port)
        let upstream = DNSUpstream(server: server, group: MultiThreadedEventLoopGroup.singleton)
        return try DNSMessage(bytes: try await upstream.forward(query, transport: tcp ? .tcp : .udp))
    }
}

/// Fake upstream resolver on UDP and TCP: answers every A query with 192.0.2.10.
struct FakeResolver {
    let udp: Channel
    let tcp: Channel
    let queries: Recorded<String>
    var address: String { "127.0.0.1:\(udp.localAddress!.port!)" }

    static func start() async throws -> FakeResolver {
        let queries = Recorded<String>()
        let group = MultiThreadedEventLoopGroup.singleton
        for _ in 0..<10 {
            let udp = try await DatagramBootstrap(group: group)
                .channelInitializer { channel in
                    channel.eventLoop.makeCompletedFuture { try channel.pipeline.syncOperations.addHandler(FakeResolverUDP(queries: queries)) }
                }
                .bind(host: "127.0.0.1", port: 0)
                .get()
            // The same number for TCP; it may be taken by another test's connection, so retry.
            guard let tcp = try? await ServerBootstrap(group: group)
                .childChannelInitializer({ channel in
                    channel.eventLoop.makeCompletedFuture {
                        try channel.pipeline.syncOperations.addHandler(ByteToMessageHandler(DNSLengthFrameDecoder()))
                        try channel.pipeline.syncOperations.addHandler(FakeResolverTCP(queries: queries))
                    }
                })
                .bind(host: "127.0.0.1", port: udp.localAddress!.port!)
                .get()
            else {
                try? await udp.close()
                continue
            }
            return FakeResolver(udp: udp, tcp: tcp, queries: queries)
        }
        throw SandvaultError.io("no free UDP/TCP port pair")
    }

    static func answer(_ bytes: [UInt8], queries: Recorded<String>) -> [UInt8]? {
        guard let query = try? DNSMessage(bytes: bytes), let question = query.questions.first else { return nil }
        queries.append(question.name)
        let answers = question.type == DNSRecordType.a ? [DNSRecord.address(name: question.name, address: "192.0.2.10", ttl: 30)!] : []
        return DNSMessage.response(to: query, rcode: .noError, answers: answers).encoded()
    }

    func stop() async {
        try? await udp.close()
        try? await tcp.close()
    }
}

private final class FakeResolverUDP: ChannelInboundHandler {
    typealias InboundIn = AddressedEnvelope<ByteBuffer>
    typealias OutboundOut = AddressedEnvelope<ByteBuffer>
    let queries: Recorded<String>

    init(queries: Recorded<String>) {
        self.queries = queries
    }

    func channelRead(context: ChannelHandlerContext, data: NIOAny) {
        let envelope = unwrapInboundIn(data)
        guard let reply = FakeResolver.answer(Array(envelope.data.readableBytesView), queries: queries) else { return }
        let out = AddressedEnvelope(remoteAddress: envelope.remoteAddress, data: context.channel.allocator.buffer(bytes: reply))
        context.writeAndFlush(wrapOutboundOut(out), promise: nil)
    }
}

private final class FakeResolverTCP: ChannelInboundHandler {
    typealias InboundIn = ByteBuffer
    typealias OutboundOut = ByteBuffer
    let queries: Recorded<String>

    init(queries: Recorded<String>) {
        self.queries = queries
    }

    func channelRead(context: ChannelHandlerContext, data: NIOAny) {
        guard let reply = FakeResolver.answer(Array(unwrapInboundIn(data).readableBytesView), queries: queries) else { return }
        var frame = context.channel.allocator.buffer(capacity: reply.count + 2)
        frame.writeInteger(UInt16(reply.count))
        frame.writeBytes(reply)
        context.writeAndFlush(wrapOutboundOut(frame), promise: nil)
    }
}

enum Curl {
    static let path = "/usr/bin/curl"
    static var available: Bool { FileManager.default.isExecutableFile(atPath: path) }

    /// Runs curl with a clean environment (no proxy variables from the test host).
    static func run(_ arguments: [String]) async throws -> CommandResult {
        try await ProcessCommandRunner().run(CommandInvocation(
            path, ["-sS", "--max-time", "15"] + arguments,
            environment: ["PATH": "/usr/bin:/bin", "HOME": NSTemporaryDirectory()], timeout: 30
        ))
    }
}
