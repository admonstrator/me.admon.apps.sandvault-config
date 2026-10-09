import Foundation
import SandvaultCore

/// What the UI shows instead of printing: errors and results become values with an optional command to run.
public struct UserMessage: Identifiable, Equatable, Sendable {
    public enum Kind: String, Sendable, CaseIterable {
        case success, info, warning, error
        /// A feature whose implementation is not in this build yet (`SandvaultError.notImplemented`).
        case notAvailable
    }

    public var id: UUID
    public var kind: Kind
    public var title: String
    public var detail: String?
    /// A command line that fixes or explains the problem (`svctl helper install`).
    public var suggestedCommand: String?

    public init(kind: Kind, title: String, detail: String? = nil, suggestedCommand: String? = nil, id: UUID = UUID()) {
        self.id = id
        self.kind = kind
        self.title = title
        self.detail = detail
        self.suggestedCommand = suggestedCommand
    }

    public static func success(_ title: String, detail: String? = nil) -> UserMessage {
        UserMessage(kind: .success, title: title, detail: detail)
    }

    public static func info(_ title: String, detail: String? = nil) -> UserMessage {
        UserMessage(kind: .info, title: title, detail: detail)
    }

    /// `action` names what was attempted, e.g. "Apply firewall".
    public init(error: Error, action: String) {
        let text = (error as? SandvaultError)?.description ?? "\(error)"
        switch error as? SandvaultError {
        case .notImplemented?:
            self.init(kind: .notAvailable, title: "Not available yet", detail: "\(action) is not part of this build yet.")
        case .unsupportedPlatform(let what)?:
            self.init(kind: .warning, title: "\(action) is not supported here", detail: what)
        case .invalidInput(let why)?:
            self.init(kind: .warning, title: "\(action): invalid input", detail: why, suggestedCommand: Self.command(in: why))
        case .notInstalled(let what)?:
            self.init(kind: .warning, title: "\(action) failed", detail: "Not installed: \(what)", suggestedCommand: Self.command(in: what) ?? Self.installCommand(for: what))
        case .permissionDenied(let why)?:
            self.init(kind: .error, title: "\(action) failed", detail: why, suggestedCommand: Self.command(in: why))
        default:
            self.init(kind: .error, title: "\(action) failed", detail: text, suggestedCommand: Self.command(in: text))
        }
    }

    /// A short form for status lines.
    public static func describe(_ error: Error) -> String {
        (error as? SandvaultError)?.description ?? "\(error)"
    }

    /// The first backtick-quoted `svctl ...` or `sv ...` command in a message.
    static func command(in text: String) -> String? {
        let parts = text.components(separatedBy: "`")
        guard parts.count >= 3 else { return nil }
        return stride(from: 1, to: parts.count - 1, by: 2).map { parts[$0] }.first {
            $0.hasPrefix("svctl ") || $0.hasPrefix("sv ") || $0 == "sv"
        }
    }

    static func installCommand(for what: String) -> String? {
        if what.contains("sandvault-netd") { return "svctl netd install" }
        if what.contains("helper") { return "svctl helper install" }
        return nil
    }
}

extension UserMessage {
    /// One line per control step that failed, plus the processes that survived.
    public init(report: ControlReportSummary) {
        if report.succeeded {
            self.init(kind: .success, title: report.title)
        } else {
            var lines = report.failures
            if !report.remaining.isEmpty {
                lines.append("still running: " + report.remaining.map(String.init).joined(separator: ", "))
            }
            self.init(kind: .error, title: report.title + " (incomplete)", detail: lines.joined(separator: "\n"))
        }
    }
}

/// The parts of Observe's `ControlReport` a message needs (kept separate so the mapping is testable in isolation).
public struct ControlReportSummary: Sendable, Equatable {
    public var title: String
    public var succeeded: Bool
    public var failures: [String]
    public var remaining: [Int32]

    public init(title: String, succeeded: Bool, failures: [String], remaining: [Int32]) {
        self.title = title
        self.succeeded = succeeded
        self.failures = failures
        self.remaining = remaining
    }
}

/// Short note after a config edit.
public func netdReloadNote(_ reloaded: Bool?) -> String? {
    guard let reloaded else { return nil }
    return reloaded ? "netd reloaded" : "netd is not running; the change applies when it starts"
}
