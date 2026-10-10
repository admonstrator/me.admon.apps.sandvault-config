import Foundation
import SandvaultCore

/// `activity-record` (D44): runs `eslogger` as root and passes on only the sandbox user's events.
extension PrivilegedHelper {
    public static let esloggerPath = "/usr/bin/eslogger"
    /// Unread eslogger lines held while the helper is behind; newer lines are dropped beyond this.
    public static let activityBufferLimit = 20_000

    public static var esloggerInvocation: CommandInvocation {
        CommandInvocation(esloggerPath, ESLoggerParser.events + ["--format", "json"], timeout: nil)
    }

    /// Emits `.started(uid:)`, then one `.event` per sandbox event until the task is cancelled, `emit` returns
    /// `false` (stdout closed) or eslogger ends. A failure is emitted as `.failed` and returns `false`.
    public func recordActivity(emit: (ActivityStreamLine) -> Bool) async -> Bool {
        let uid: UInt32
        do {
            uid = try await resolveUID(try sudoEnvironment())
        } catch {
            _ = emit(.failed(.unavailable("\(error)")))
            return false
        }
        guard emit(.started(uid: uid)) else { return true }
        do {
            for try await line in context.runner.linesWithStderr(Self.esloggerInvocation, bufferLimit: Self.activityBufferLimit) {
                guard let event = ESLoggerParser.event(fromLine: line, uid: uid) else { continue }
                // Leaving the loop cancels the stream, which terminates eslogger.
                guard emit(.event(event)) else { return true }
            }
            // eslogger exited 0 or by a signal (Ctrl-C reaches the whole process group): a clean stop.
            return true
        } catch SandvaultError.commandFailed(_, let code, let stderr) {
            _ = emit(.failed(Self.esloggerFailure(exitCode: code, stderr: stderr)))
            return false
        } catch {
            _ = emit(.failed(.unavailable("\(error)")))
            return false
        }
    }

    /// macOS refuses an ES client without Full Disk Access with `ES_NEW_CLIENT_RESULT_ERR_NOT_PERMITTED`.
    static func esloggerFailure(exitCode: Int32, stderr: String) -> ActivityRecorderFailure {
        let text = stderr.trimmingCharacters(in: .whitespacesAndNewlines)
        let lower = text.lowercased()
        if lower.contains("not_permitted") || lower.contains("not permitted") || lower.contains("full disk access")
            || lower.contains("tcc") {
            return .needsFullDiskAccess
        }
        let detail = text.split(whereSeparator: \.isNewline).last.map(String.init) ?? ""
        return .unavailable(detail.isEmpty ? "eslogger exited \(exitCode)" : "eslogger exited \(exitCode): \(detail)")
    }
}
