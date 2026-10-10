import Foundation
import SandvaultCore

/// Allowed and denied counts per host and port, fed by every `ConnectionRecord` netd records and seeded from the
/// connection log on start. Bounded: past `capacity` keys the least recently seen tenth is dropped.
public final class ConnectionHistoryIndex: @unchecked Sendable {
    private struct Key: Hashable {
        var host: String
        var port: UInt16?
    }

    public let capacity: Int
    private let lock = NSLock()
    private var entries: [Key: AskHistory] = [:]

    public init(capacity: Int = 20_000) {
        self.capacity = max(10, capacity)
    }

    public func add(_ record: ConnectionRecord) {
        let key = Key(host: record.host.lowercased(), port: record.kind == .dns ? nil : record.port)
        lock.withLock {
            var entry = entries[key] ?? AskHistory(allowed: 0, denied: 0, lastSeen: nil)
            if record.decision.blocked { entry.denied += 1 } else { entry.allowed += 1 }
            if entry.lastSeen.map({ $0 < record.timestamp }) ?? true { entry.lastSeen = record.timestamp }
            entries[key] = entry
            if entries.count > capacity {
                // Sorting is O(n log n) but runs once per capacity / 10 new keys.
                let drop = entries.count - capacity + capacity / 10
                let oldest = entries.sorted { ($0.value.lastSeen ?? .distantPast) < ($1.value.lastSeen ?? .distantPast) }.prefix(drop)
                for (key, _) in oldest { entries[key] = nil }
            }
        }
    }

    /// Earlier connections to `host` on `port` (`nil`: DNS queries for `host`).
    public func history(host: String, port: UInt16?) -> AskHistory {
        lock.withLock { entries[Key(host: host.lowercased(), port: port)] } ?? AskHistory(allowed: 0, denied: 0, lastSeen: nil)
    }

    /// Adds the newest `limit` records of the log file and its rotations that are older than `before`
    /// (records from then on reach `add` directly, so none is counted twice).
    public func seed(logPath: String, before: Date, limit: Int = 20_000) {
        guard let records = try? ConnectionLog.read(path: logPath, limit: limit) else { return }
        for record in records where record.timestamp < before { add(record) }
    }
}
