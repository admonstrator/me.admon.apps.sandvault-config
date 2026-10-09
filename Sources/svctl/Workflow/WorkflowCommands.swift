import ArgumentParser
import Foundation
import SandvaultCore
import SandvaultWorkflow

enum WorkflowCommands {
    static let all: [any ParsableCommand.Type] = [
        HandoffCommand.self, ReposCommand.self, ToolsCommand.self, MigrateCommand.self, KeysCommand.self, DefaultsCommand.self,
    ]
}

/// Helpers shared by the workflow commands.
enum WorkflowCLI {
    static func requireMacOS(_ what: String) throws {
        guard WorkflowPlatform.isMacOS else { throw SandvaultError.unsupportedPlatform(what) }
    }

    /// `"claude"` -> `AgentKind.claude`, with the allowed values in the error.
    static func parse<T: RawRepresentable & CaseIterable>(_ text: String, as what: String) throws -> T where T.RawValue == String {
        guard let value = T(rawValue: text.lowercased()) else {
            throw SandvaultError.invalidInput("unknown \(what) '\(text)'; one of: \(T.allCases.map(\.rawValue).joined(separator: ", "))")
        }
        return value
    }

    /// A small text input: a file or `-` for stdin.
    static func readInput(_ path: String, limit: Int = 1 << 20) throws -> String {
        let data: Data
        if path == "-" {
            data = FileHandle.standardInput.readDataToEndOfFile()
        } else {
            guard let contents = FileManager.default.contents(atPath: path) else { throw SandvaultError.io("cannot read \(path)") }
            data = contents
        }
        guard data.count <= limit else { throw SandvaultError.invalidInput("\(path) is larger than \(limit) bytes") }
        return String(decoding: data, as: UTF8.self)
    }

    static func severity(_ severity: FindingSeverity) -> String {
        switch severity {
        case .info: "info"
        case .warning: "WARN"
        case .blocker: "BLOCK"
        }
    }

    static func date(_ date: Date?) -> String {
        guard let date else { return "-" }
        let formatter = DateFormatter()
        formatter.dateFormat = "yyyy-MM-dd HH:mm"
        return formatter.string(from: date)
    }

    static func count(_ value: Int?) -> String { value.map(String.init) ?? "-" }
}

extension WorkflowCLI {
    enum DeployKeyArgument: String, ExpressibleByArgument, CaseIterable {
        case none, ro, rw

        var mode: HandoffRequest.DeployKeyMode {
            switch self {
            case .none: .none
            case .ro: .readOnly
            case .rw: .readWrite
            }
        }
    }

    /// Kebab-case names of `MigrationItem`, plus `all`.
    static func migrationItems(_ names: [String]) throws -> [MigrationItem] {
        var items: [MigrationItem] = []
        for name in names {
            if name == "all" { return MigrationItem.allCases }
            guard let item = MigrationItem.allCases.first(where: { migrationName($0) == name }) else {
                throw SandvaultError.invalidInput("unknown item '\(name)'; one of: all, " + MigrationItem.allCases.map(migrationName).joined(separator: ", "))
            }
            if !items.contains(item) { items.append(item) }
        }
        return items
    }

    static func migrationName(_ item: MigrationItem) -> String {
        item.rawValue.replacingOccurrences(of: "([a-z])([A-Z])", with: "$1-$2", options: .regularExpression).lowercased()
    }
}
