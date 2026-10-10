import Foundation
import Observation
import SandvaultCore

/// The app's long-lived connection to sandvault-netd: subscribes to status, connections and asks, keeps the
/// latest status, the recent records and the pending asks, and reconnects with backoff when netd restarts.
/// netd raises asks only while a client subscribes to `.asks` (D22), so this runs as long as the app does.
@MainActor @Observable
public final class NetdLink {
    public enum State: Equatable, Sendable {
        case stopped
        case connecting
        case connected
        /// Not reachable; the next attempt follows after `retryIn` seconds.
        case waiting(retryIn: Double, reason: String)
    }

    public private(set) var state: State = .stopped
    public private(set) var status: NetdStatus?
    /// Most recent connection records, oldest first.
    public private(set) var records: [ConnectionRecord] = []
    public private(set) var pendingAsks: [AskRequest] = []
    /// Successful connections so far (a reconnect after a netd restart counts again).
    public private(set) var connectCount = 0

    public static let topics: [ControlTopic] = [.status, .connections, .asks]
    /// Records kept for Activity; Web traffic lists one row per request, so it holds more than netd's ring.
    public static let recordLimit = 3000
    /// Memory bound besides the count: request summaries over all kept records.
    public static let summaryLimit = 20_000

    @ObservationIgnored private let connector: NetdConnector
    @ObservationIgnored private let clock: AppClock
    @ObservationIgnored private var client: (any NetdClient)?
    @ObservationIgnored private var task: Task<Void, Never>?

    public init(connector: NetdConnector, clock: AppClock) {
        self.connector = connector
        self.clock = clock
    }

    public var isConnected: Bool { state == .connected }

    /// One line for status bars: what netd is doing, or why it is not reachable.
    public var summary: String {
        switch state {
        case .stopped: return "Not connected to sandvault-netd"
        case .connecting: return "Connecting to sandvault-netd..."
        case .waiting(let retryIn, let reason): return "sandvault-netd not reachable (\(reason)); retrying in \(Format.duration(Int(retryIn.rounded(.up))))"
        case .connected:
            guard let status else { return "Connected to sandvault-netd" }
            return "sandvault-netd: \(status.mode.displayName.lowercased()), \(status.activeConnections) active, "
                + "\(status.allowedCount) allowed, \(status.deniedCount) denied since \(Format.time(status.startedAt))"
        }
    }

    public func start() {
        guard task == nil else { return }
        task = Task { [weak self] in await self?.run() }
    }

    public func stop() {
        task?.cancel()
        task = nil
        client?.close()
        client = nil
        state = .stopped
    }

    /// Skips the remaining backoff (after installing or restarting netd).
    public func retryNow() {
        guard case .waiting = state else { return }
        stop()
        start()
    }

    public func answer(_ answer: AskAnswer) async throws {
        guard let client else { throw SandvaultError.notInstalled("sandvault-netd is not connected") }
        try await client.answer(answer)
        pendingAsks.removeAll { $0.id == answer.id }
    }

    /// A body netd kept (D43).
    public func content(id: UUID) async throws -> (StoredContent, Data) {
        guard let client else { throw SandvaultError.notInstalled("sandvault-netd is not connected") }
        return try await client.content(id: id)
    }

    /// Deletes every body netd kept, then asks for the new status (its `storedContentBytes`).
    public func clearContent() async throws {
        guard let client else { throw SandvaultError.notInstalled("sandvault-netd is not connected") }
        try await client.clearContent()
        await refreshStatus()
    }

    public func refreshStatus() async {
        guard let client, let status = try? await client.status() else { return }
        self.status = status
    }

    /// Every state change happens on the main actor right after a cancellation check, so a run that `stop()`
    /// cancelled never overwrites the state of the run that replaced it.
    func run() async {
        var backoff = Backoff()
        while !Task.isCancelled {
            state = .connecting
            var reason = "netd closed the connection"
            do {
                let client = try await connector.connect()
                guard !Task.isCancelled else {
                    client.close()
                    return
                }
                self.client = client
                try await client.subscribe(Self.topics)
                let status = try? await client.status()
                let asks = try await client.pendingAsks()
                let recent = try await client.recent(limit: Self.recordLimit)
                try Task.checkCancellation()
                self.status = status
                pendingAsks = asks
                records = Self.trimmed(Array(recent.suffix(Self.recordLimit)))
                state = .connected
                connectCount += 1
                backoff.reset()
                for await event in client.events {
                    guard !Task.isCancelled else { break }
                    handle(event)
                }
            } catch {
                reason = UserMessage.describe(error)
            }
            guard !Task.isCancelled else { return }
            client?.close()
            client = nil
            // A restarted netd has forgotten its asks; a stale status would claim it still runs.
            pendingAsks = []
            status = nil
            let delay = backoff.next()
            state = .waiting(retryIn: delay, reason: reason)
            try? await clock.sleep(delay)
        }
    }

    func handle(_ event: ControlEvent) {
        switch event {
        case .status(let status):
            self.status = status
        case .connection(let record):
            records.append(record)
            records = Self.trimmed(records)
        case .ask(let ask):
            if !pendingAsks.contains(where: { $0.id == ask.id }) { pendingAsks.append(ask) }
        case .askResolved(let id, _):
            pendingAsks.removeAll { $0.id == id }
        case .hello, .recent, .pending, .content, .ack, .error:
            break
        }
    }
}

extension NetdLink {
    /// The newest records within `recordLimit` and `summaryLimit`.
    static func trimmed(_ records: [ConnectionRecord]) -> [ConnectionRecord] {
        var drop = max(0, records.count - recordLimit)
        var summaries = records[drop...].reduce(0) { $0 + $1.http.count }
        while summaries > summaryLimit, drop < records.count - 1 {
            summaries -= records[drop].http.count
            drop += 1
        }
        return drop == 0 ? records : Array(records[drop...])
    }
}

/// Reconnect delays: 0.5 s doubling up to 15 s, back to the start after a successful connection.
public struct Backoff: Sendable, Equatable {
    public var initial: Double
    public var maximum: Double
    private var current: Double?

    public init(initial: Double = 0.5, maximum: Double = 15) {
        self.initial = initial
        self.maximum = maximum
    }

    public mutating func next() -> Double {
        let value = current.map { min($0 * 2, maximum) } ?? initial
        current = value
        return value
    }

    public mutating func reset() {
        current = nil
    }
}
