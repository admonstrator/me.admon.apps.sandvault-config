import Foundation
import Observation
import SandvaultCore

/// The only way the app changes config.json. svctl and netd write the same file, so every edit re-reads it,
/// applies one change, saves, and asks a running netd to reload. Nothing is ever saved from a stale copy.
@MainActor @Observable
public final class ConfigEditor {
    /// The configuration as last read or written; views display it.
    public private(set) var config = AppConfig()
    /// Why the last read failed (a damaged file is never overwritten silently: edits fail too).
    public private(set) var loadError: String?

    @ObservationIgnored private let store: ConfigStore
    @ObservationIgnored private let netd: NetdConnector
    @ObservationIgnored private var loadedModification: Date?

    public init(store: ConfigStore, netd: NetdConnector) {
        self.store = store
        self.netd = netd
    }

    public var path: String { store.url.path }

    public func reload() {
        do {
            loadedModification = modificationDate()
            config = try store.load()
            loadError = nil
        } catch {
            loadError = UserMessage.describe(error)
        }
    }

    /// Re-reads the file only when it changed on disk (polling calls this).
    public func reloadIfChanged() {
        guard modificationDate() != loadedModification || loadError != nil else { return }
        reload()
    }

    public struct Edit<Value> {
        public var value: Value
        /// `nil` when no reload was requested, else whether netd answered.
        public var netdReloaded: Bool?
    }

    /// Fresh read, `change`, save, then `reloadConfig` to netd when `reloadNetd` (netd ignores sandbox-only edits).
    @discardableResult
    public func edit<Value>(reloadNetd: Bool = true, _ change: (inout AppConfig) throws -> Value) async throws -> Edit<Value> {
        var fresh = try store.load()
        let value = try change(&fresh)
        try store.save(fresh)
        config = fresh
        loadedModification = modificationDate()
        loadError = nil
        let reloaded: Bool? = reloadNetd ? await self.reloadNetd() : nil
        return Edit(value: value, netdReloaded: reloaded)
    }

    /// One-shot `reloadConfig` on a separate connection; `false` when netd is not running.
    public func reloadNetd() async -> Bool {
        guard let client = try? await netd.connect() else { return false }
        defer { client.close() }
        return (try? await client.reloadConfig()) != nil
    }

    private func modificationDate() -> Date? {
        (try? FileManager.default.attributesOfItem(atPath: store.url.path))?[.modificationDate] as? Date
    }
}
