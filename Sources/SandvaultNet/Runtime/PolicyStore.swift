import Foundation
import SandvaultCore

/// The live configuration of netd. Readers take a consistent snapshot; `reload` and `persist` swap it atomically.
public final class PolicyStore: @unchecked Sendable {
    public struct Snapshot: Sendable {
        public let config: AppConfig
        public let engine: PolicyEngine
        public var policy: NetworkPolicy { config.network }
    }

    public let store: ConfigStore
    private let lock = NSLock()
    private let writeLock = NSLock()
    private var current: Snapshot

    public init(store: ConfigStore) throws {
        self.store = store
        let config = try store.load()
        current = Snapshot(config: config, engine: PolicyEngine(policy: config.network))
    }

    public var snapshot: Snapshot { lock.withLock { current } }

    /// Re-reads the config file and swaps the policy.
    @discardableResult
    public func reload() throws -> AppConfig {
        let config = try store.load()
        swap(config)
        return config
    }

    /// Re-reads the file, adds or updates the rule for `pattern`, saves, and swaps the policy.
    public func persistRule(pattern: String, action: DomainAction) throws -> DomainRule {
        try writeLock.withLock {
            var config = try store.load()
            let rule = try config.network.upsertDomainRule(pattern: pattern, action: action, note: "added from an ask")
            try store.save(config)
            swap(config)
            return rule
        }
    }

    private func swap(_ config: AppConfig) {
        let snapshot = Snapshot(config: config, engine: PolicyEngine(policy: config.network))
        lock.withLock { current = snapshot }
    }
}
