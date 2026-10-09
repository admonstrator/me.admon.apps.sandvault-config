import Foundation
import NIOCore
import NIOPosix
import SandvaultCore

/// Answers one control request (implemented by `NetDaemon`).
protocol ControlService: Sendable {
    func handle(_ request: ControlRequest, client: UUID) async -> ControlEvent
}

/// Unix domain socket server speaking `ControlRequest` / `ControlEvent` lines.
enum ControlServer {
    /// Binds `path` (mode 0600, parent directory 0700). A stale socket file is removed; a live one
    /// (another netd answering) is an error.
    static func bind(path: String, group: EventLoopGroup, hub: ControlHub, service: ControlService) async throws -> Channel {
        let directory = (path as NSString).deletingLastPathComponent
        try FileManager.default.createDirectory(atPath: directory, withIntermediateDirectories: true, attributes: [.posixPermissions: 0o700])
        if FileManager.default.fileExists(atPath: path), await ControlClient.isReachable(socketPath: path) {
            throw SandvaultError.invalidInput("another sandvault-netd is already listening on \(path)")
        }
        let channel = try await ServerBootstrap(group: group)
            .childChannelInitializer { channel in
                channel.eventLoop.makeCompletedFuture {
                    try channel.pipeline.syncOperations.addHandler(ByteToMessageHandler(LineFrameDecoder()))
                    try channel.pipeline.syncOperations.addHandler(ControlConnectionHandler(hub: hub, service: service))
                }
            }
            .bind(unixDomainSocketPath: path, cleanupExistingSocketFile: true)
            .get()
        guard chmod(path, 0o600) == 0 else {
            channel.close(promise: nil)
            throw SandvaultError.io("cannot set mode 0600 on \(path) (errno \(errno))")
        }
        return channel
    }
}

/// One control connection: requests are handled in order; subscribed events are pushed in between.
private final class ControlConnectionHandler: ChannelInboundHandler {
    typealias InboundIn = String

    private let id = UUID()
    private let hub: ControlHub
    private let service: ControlService
    private var requests: AsyncStream<ControlRequest>.Continuation?

    init(hub: ControlHub, service: ControlService) {
        self.hub = hub
        self.service = service
    }

    func channelActive(context: ChannelHandlerContext) {
        let channel = context.channel
        hub.add(id) { event in Self.send(event, on: channel) }
        requests = Self.serve(service: service, client: id, channel: channel)
        context.fireChannelActive()
    }

    func channelRead(context: ChannelHandlerContext, data: NIOAny) {
        let line = unwrapInboundIn(data)
        guard !line.trimmingCharacters(in: .whitespaces).isEmpty else { return }
        do {
            requests?.yield(try ControlCodec.decode(ControlRequest.self, line: line))
        } catch {
            Self.send(.error("cannot decode request: \(error)"), on: context.channel)
        }
    }

    func channelInactive(context: ChannelHandlerContext) {
        hub.remove(id)
        requests?.finish()
        requests = nil
        context.fireChannelInactive()
    }

    func errorCaught(context: ChannelHandlerContext, error: Error) {
        context.close(promise: nil)
    }

    /// Handles requests one after another and writes each response.
    private static func serve(service: ControlService, client: UUID, channel: Channel) -> AsyncStream<ControlRequest>.Continuation {
        let (stream, continuation) = AsyncStream.makeStream(of: ControlRequest.self)
        Task {
            for await request in stream {
                send(await service.handle(request, client: client), on: channel)
            }
        }
        return continuation
    }

    static func send(_ event: ControlEvent, on channel: Channel) {
        guard let data = try? ControlCodec.encode(event) else { return }
        channel.writeAndFlush(channel.allocator.buffer(bytes: data), promise: nil)
    }
}
