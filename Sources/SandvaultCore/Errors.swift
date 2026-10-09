import Foundation

public enum SandvaultError: Error, Sendable, Equatable, CustomStringConvertible {
    /// A command ran and exited non-zero: (command line, exit code, stderr).
    case commandFailed(String, Int32, String)
    /// A command could not be started: (command line, reason).
    case commandNotRunnable(String, String)
    case timedOut(String)
    /// sandvault (or a part of it) is not installed: what is missing.
    case notInstalled(String)
    /// Input rejected by validation: why.
    case invalidInput(String)
    case permissionDenied(String)
    /// Feature not available on this platform (e.g. pf on Linux).
    case unsupportedPlatform(String)
    case io(String)
    /// Placeholder for contract stubs that an agent has not filled in yet.
    case notImplemented(String)

    public var description: String {
        switch self {
        case let .commandFailed(command, code, stderr):
            let detail = stderr.trimmingCharacters(in: .whitespacesAndNewlines)
            return "command failed (exit \(code)): \(command)" + (detail.isEmpty ? "" : "\n\(detail)")
        case let .commandNotRunnable(command, reason): return "cannot run \(command): \(reason)"
        case let .timedOut(command): return "timed out: \(command)"
        case let .notInstalled(what): return "not installed: \(what)"
        case let .invalidInput(why): return "invalid input: \(why)"
        case let .permissionDenied(why): return "permission denied: \(why)"
        case let .unsupportedPlatform(what): return "unsupported on this platform: \(what)"
        case let .io(why): return "I/O error: \(why)"
        case let .notImplemented(what): return "not implemented yet: \(what)"
        }
    }
}
