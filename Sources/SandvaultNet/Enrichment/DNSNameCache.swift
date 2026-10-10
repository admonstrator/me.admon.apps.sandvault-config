import Foundation

/// Addresses the sandbox got through netd's DNS forwarder and the names it asked for, kept for `retention`
/// seconds and at most `capacity` entries. Gives an ask for a bare address the name that led there.
public final class DNSNameCache: @unchecked Sendable {
    private struct Entry {
        var value: String
        var at: Date
    }

    public let retention: TimeInterval
    public let capacity: Int
    private let now: @Sendable () -> Date
    private let lock = NSLock()
    private var names: [String: Entry] = [:]
    private var addresses: [String: Entry] = [:]

    public init(retention: TimeInterval = 600, capacity: Int = 4096, now: @escaping @Sendable () -> Date = { Date() }) {
        self.retention = retention
        self.capacity = max(1, capacity)
        self.now = now
    }

    /// Remembers that a query for `name` answered `addresses`.
    public func record(name: String, addresses list: [String]) {
        guard !name.isEmpty, let first = list.first else { return }
        let at = now()
        lock.withLock {
            for address in list { names[address.lowercased()] = Entry(value: name, at: at) }
            addresses[name] = Entry(value: first.lowercased(), at: at)
            trim(&names, at: at)
            trim(&addresses, at: at)
        }
    }

    /// The name the sandbox last looked up for `address`, if within `retention`.
    public func name(for address: String) -> String? {
        lookup(\.names, address.lowercased())
    }

    /// The first address the last answer for `name` gave, if within `retention`.
    public func address(for name: String) -> String? {
        lookup(\.addresses, name)
    }

    public var count: Int { lock.withLock { names.count } }

    private func lookup(_ table: ReferenceWritableKeyPath<DNSNameCache, [String: Entry]>, _ key: String) -> String? {
        let at = now()
        return lock.withLock {
            guard let entry = self[keyPath: table][key] else { return nil }
            guard at.timeIntervalSince(entry.at) <= retention else {
                self[keyPath: table][key] = nil
                return nil
            }
            return entry.value
        }
    }

    /// Drops expired entries once the table is full, then the oldest tenth if it still is.
    private func trim(_ table: inout [String: Entry], at: Date) {
        guard table.count > capacity else { return }
        table = table.filter { at.timeIntervalSince($0.value.at) <= retention }
        guard table.count > capacity else { return }
        let drop = table.count - capacity + capacity / 10
        for key in table.sorted(by: { $0.value.at < $1.value.at }).prefix(drop).map(\.key) { table[key] = nil }
    }
}
