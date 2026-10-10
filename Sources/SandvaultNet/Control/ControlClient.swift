import Foundation
import NIOCore
import NIOPosix
import SandvaultCore

/// Client of the netd control socket, shared by svctl and the app.
///
/// `request` sends one `ControlRequest` and returns its response; events of subscribed topics
/// (`.connection`, `.ask`, `.askResolved`, periodic `.status`) arrive on `events`.
public final class ControlClient: @unchecked Sendable {
    public let socketPath: String
    /// Pushed events, in arrival order. Finishes when the connection closes.
    public let events: AsyncStream<ControlEvent>

    private struct Waiter {
        var id: UUID
        var accepts: @Sendable (ControlEvent) -> Bool
        var continuation: CheckedContinuation<ControlEvent, Error>
    }

    private let lock = NSLock()
    private var channel: Channel?
    private var waiters: [Waiter] = []
    private var closed = false
    private let eventSink: AsyncStream<ControlEvent>.Continuation

    private init(socketPath: String) {
        self.socketPath = socketPath
        (events, eventSink) = AsyncStream.makeStream(of: ControlEvent.self, bufferingPolicy: .bufferingNewest(10_000))
    }

    /// Connects to netd; throws `notInstalled` when nothing listens on `socketPath`.
    public static func connect(socketPath: String, group: EventLoopGroup = MultiThreadedEventLoopGroup.singleton) async throws -> ControlClient {
        let client = ControlClient(socketPath: socketPath)
        do {
            let channel = try await ClientBootstrap(group: group)
                .connectTimeout(.seconds(3))
                .channelInitializer { channel in
                    channel.eventLoop.makeCompletedFuture {
                        // A served content can be up to `ContentStore.maxBodyBytes`, base64 in one line.
                        try channel.pipeline.syncOperations.addHandler(ByteToMessageHandler(LineFrameDecoder(maxLength: 32 << 20)))
                        try channel.pipeline.syncOperations.addHandler(ControlClientHandler(client: client))
                    }
                }
                .connect(unixDomainSocketPath: socketPath)
                .get()
            client.lock.withLock { client.channel = channel }
        } catch {
            guard FileManager.default.fileExists(atPath: socketPath) else {
                throw SandvaultError.notInstalled("sandvault-netd is not running (no control socket at \(socketPath))")
            }
            throw SandvaultError.notInstalled("sandvault-netd is not answering at \(socketPath) (\(error))")
        }
        return client
    }

    /// Whether a netd answers on `socketPath`.
    public static func isReachable(socketPath: String) async -> Bool {
        guard let client = try? await connect(socketPath: socketPath) else { return false }
        defer { client.close() }
        return (try? await client.request(.hello(client: "probe"), timeout: 2)) != nil
    }

    /// Connects, sends one request, returns its response and disconnects.
    public static func send(_ request: ControlRequest, socketPath: String, timeout: Double = 10) async throws -> ControlEvent {
        let client = try await connect(socketPath: socketPath)
        defer { client.close() }
        return try await client.request(request, timeout: timeout)
    }

    public func request(_ request: ControlRequest, timeout: Double = 10) async throws -> ControlEvent {
        let data = try ControlCodec.encode(request)
        let id = UUID()
        let accepts = Self.responseMatcher(for: request)
        return try await withCheckedThrowingContinuation { continuation in
            let target: Channel? = lock.withLock {
                guard !closed, let channel else { return nil }
                waiters.append(Waiter(id: id, accepts: accepts, continuation: continuation))
                return channel
            }
            guard let channel = target else {
                return continuation.resume(throwing: SandvaultError.io("control connection is closed"))
            }
            channel.eventLoop.scheduleTask(in: .milliseconds(Int64(timeout * 1000))) { [weak self] in
                self?.expire(id)
            }
            channel.writeAndFlush(channel.allocator.buffer(bytes: data)).whenFailure { [weak self] error in
                self?.fail(id, error)
            }
        }
    }

    public func close() {
        let channel = lock.withLock { self.channel }
        channel?.close(promise: nil)
    }

    // MARK: Typed helpers

    public func status() async throws -> NetdStatus {
        guard case .status(let status) = try Self.check(await request(.status)) else { throw Self.unexpected() }
        return status
    }

    public func reloadConfig() async throws {
        _ = try Self.check(await request(.reloadConfig))
    }

    public func subscribe(_ topics: [ControlTopic]) async throws {
        _ = try Self.check(await request(.subscribe(topics: topics)))
    }

    public func answer(_ answer: AskAnswer) async throws {
        _ = try Self.check(await request(.answer(answer)))
    }

    public func pendingAsks() async throws -> [AskRequest] {
        guard case .pending(let asks) = try Self.check(await request(.pendingAsks)) else { throw Self.unexpected() }
        return asks
    }

    public func recent(limit: Int) async throws -> [ConnectionRecord] {
        guard case .recent(let records) = try Self.check(await request(.recent(limit: limit))) else { throw Self.unexpected() }
        return records
    }

    public func content(id: UUID) async throws -> (StoredContent, Data) {
        guard case .content(let meta, let data) = try Self.check(await request(.content(id: id))) else { throw Self.unexpected() }
        return (meta, data)
    }

    public func clearContent() async throws {
        _ = try Self.check(await request(.clearContent))
    }

    // MARK: - Internals

    fileprivate func receive(_ event: ControlEvent) {
        let waiter: Waiter? = lock.withLock {
            // Responses come in request order; anything the oldest waiter does not expect was pushed.
            guard let first = waiters.first, first.accepts(event) else { return nil }
            return waiters.removeFirst()
        }
        if let waiter {
            waiter.continuation.resume(returning: event)
        } else {
            eventSink.yield(event)
        }
    }

    fileprivate func connectionClosed() {
        let pending: [Waiter] = lock.withLock {
            closed = true
            defer { waiters.removeAll() }
            return waiters
        }
        for waiter in pending { waiter.continuation.resume(throwing: SandvaultError.io("netd closed the control connection")) }
        eventSink.finish()
    }

    private func expire(_ id: UUID) {
        fail(id, SandvaultError.timedOut("netd control request"))
    }

    private func fail(_ id: UUID, _ error: Error) {
        let waiter: Waiter? = lock.withLock {
            guard let index = waiters.firstIndex(where: { $0.id == id }) else { return nil }
            return waiters.remove(at: index)
        }
        waiter?.continuation.resume(throwing: error)
    }

    /// Which event answers `request` (responses are not tagged; a pushed `.status` may answer `.status`).
    static func responseMatcher(for request: ControlRequest) -> @Sendable (ControlEvent) -> Bool {
        switch request {
        case .hello: return { if case .hello = $0 { true } else { false } }
        case .status: return { if case .status = $0 { true } else if case .error = $0 { true } else { false } }
        case .recent: return { if case .recent = $0 { true } else if case .error = $0 { true } else { false } }
        case .pendingAsks: return { if case .pending = $0 { true } else if case .error = $0 { true } else { false } }
        case .content: return { if case .content = $0 { true } else if case .error = $0 { true } else { false } }
        case .subscribe, .reloadConfig, .answer, .clearContent:
            return { if case .ack = $0 { true } else if case .error = $0 { true } else { false } }
        }
    }

    static func check(_ event: ControlEvent) throws -> ControlEvent {
        if case .error(let message) = event { throw SandvaultError.io("netd: \(message)") }
        return event
    }

    static func unexpected() -> SandvaultError { .io("netd sent an unexpected response") }
}

private final class ControlClientHandler: ChannelInboundHandler {
    typealias InboundIn = String

    private let client: ControlClient

    init(client: ControlClient) {
        self.client = client
    }

    func channelRead(context: ChannelHandlerContext, data: NIOAny) {
        let line = unwrapInboundIn(data)
        guard let event = try? ControlCodec.decode(ControlEvent.self, line: line) else { return }
        client.receive(event)
    }

    func channelInactive(context: ChannelHandlerContext) {
        client.connectionClosed()
        context.fireChannelInactive()
    }

    func errorCaught(context: ChannelHandlerContext, error: Error) {
        context.close(promise: nil)
    }
}
