import ArgumentParser
import Foundation
import SandvaultCore
import SandvaultNet

enum NetCommands {
    static let all: [any ParsableCommand.Type] = [
        NetProxyCommand.self, NetDnsCommand.self, NetCACommand.self, NetLogCommand.self, NetAsksCommand.self, NetdCommand.self,
    ]
}

/// Helpers shared by the network commands.
enum NetCLI {
    static func socketPath(_ global: GlobalOptions) -> String { global.paths.effectiveControlSocket }

    /// Loads the config, applies `change`, saves it and asks a running netd to reload.
    static func edit<T>(_ global: GlobalOptions, _ change: (inout AppConfig) throws -> T) async throws -> (value: T, reloaded: Bool) {
        let store = global.configStore
        var config = try store.load()
        let value = try change(&config)
        try store.save(config)
        return (value, await reload(global))
    }

    /// `true` when netd answered the reload.
    static func reload(_ global: GlobalOptions) async -> Bool {
        guard let client = try? await ControlClient.connect(socketPath: socketPath(global)) else { return false }
        defer { client.close() }
        return (try? await client.reloadConfig()) != nil
    }

    static func reloadNote(_ reloaded: Bool) -> String {
        reloaded ? "netd reloaded" : "netd is not running; the change applies when it starts"
    }

    static func parseAction(_ text: String) throws -> DomainAction {
        guard let action = DomainAction(rawValue: text.lowercased()) else {
            throw ValidationError("expected allow, deny or ask, not '\(text)'")
        }
        return action
    }

    /// The shared workspace must exist before anything is written into it.
    static func requireSharedWorkspace(_ global: GlobalOptions) throws -> SharedFiles {
        let root = global.environment.sharedWorkspace
        var isDirectory: ObjCBool = false
        guard FileManager.default.fileExists(atPath: root, isDirectory: &isDirectory), isDirectory.boolValue else {
            throw SandvaultError.notInstalled("shared workspace \(root) (run `sv` once to create it)")
        }
        return SharedFiles(root: root)
    }

    static func shortID(_ id: UUID) -> String { String(id.uuidString.prefix(8)).lowercased() }

    static func bytes(_ count: Int64) -> String {
        let units = ["B", "kB", "MB", "GB"]
        var value = Double(count)
        var unit = 0
        while value >= 1000, unit < units.count - 1 {
            value /= 1000
            unit += 1
        }
        return unit == 0 ? "\(count) B" : String(format: "%.1f %@", value, units[unit])
    }

    static func timestamp(_ date: Date) -> String {
        ISO8601DateFormatter().string(from: date)
    }

    /// One line per record for `svctl netlog`.
    static func describe(_ record: ConnectionRecord) -> String {
        let verdict: String
        switch record.decision {
        case .allowed: verdict = "ALLOW"
        case .askedAllowed: verdict = "ALLOW(asked)"
        case .denied: verdict = "DENY"
        case .askedDenied: verdict = "DENY(asked)"
        case .timedOut: verdict = "DENY(unanswered)"
        }
        let target = record.port.map { "\(record.host):\($0)" } ?? record.host
        var parts = [timestamp(record.timestamp), verdict, record.kind.rawValue, target]
        if let process = record.process { parts.append("\(process)(\(record.pid.map(String.init) ?? "?"))") }
        if record.kind == .dns {
            if !record.dnsAnswers.isEmpty { parts.append("-> " + record.dnsAnswers.joined(separator: ",")) }
        } else {
            parts.append("in \(bytes(record.bytesIn)) out \(bytes(record.bytesOut)) \(record.durationMs) ms")
        }
        if record.inspected { parts.append("inspected") }
        for summary in record.http {
            parts.append("\(summary.method) \(summary.url) \(summary.status.map(String.init) ?? "-")")
        }
        return parts.joined(separator: "  ")
    }
}
