import Foundation
import SandvaultCore

/// The app's recorder (D44, D45): `sudo -n <helper> activity-record --json`, filtered by `ActivityFilter` and
/// appended to `AppPaths.activityLog` before each kept event is yielded.
public struct LiveActivityRecorder: ActivityRecording {
    /// Unread helper lines held while the consumer is behind.
    public static let bufferLimit = 10_000

    public var runner: CommandRunner
    /// `false` for `svctl activity record --no-store`: events are yielded, nothing is written.
    public var stores: Bool
    let store: ActivityStore
    let now: @Sendable () -> Date

    public init(paths: AppPaths, runner: CommandRunner, stores: Bool = true, now: @escaping @Sendable () -> Date = { Date() }) {
        self.runner = runner
        self.stores = stores
        self.store = ActivityStore(path: paths.activityLog)
        self.now = now
    }

    public init(environment: SandvaultEnvironment, runner: CommandRunner) {
        self.init(paths: AppPaths(environment: environment), runner: runner)
    }

    /// Exactly the argv in `PrivilegedHelper.unattendedArguments`, so the sudoers rule allows it.
    public static var invocation: CommandInvocation {
        CommandInvocation("/usr/bin/sudo", ["-n", AppPaths.helperPath, HelperSubcommand.activityRecord.rawValue, "--json"], timeout: nil)
    }

    public func record(settings: ActivityRecordingSettings) -> AsyncThrowingStream<FileActivityEvent, Error> {
        let runner = runner, store = store, stores = stores
        return AsyncThrowingStream { continuation in
            let task = Task {
                var filter = ActivityFilter(settings: settings)
                var reported: ActivityRecorderFailure?
                var heardFromHelper = false
                do {
                    for try await text in runner.linesWithStderr(Self.invocation, bufferLimit: Self.bufferLimit) {
                        switch Self.decode(text) {
                        case .line(.started):
                            heardFromHelper = true
                        case .line(.event(let event)):
                            heardFromHelper = true
                            guard filter.admit(event) else { continue }
                            if stores {
                                do {
                                    try await store.append([event])
                                } catch {
                                    throw ActivityRecorderFailure.unavailable("cannot store activity: \(error)")
                                }
                            }
                            continuation.yield(event)
                        case .line(.failed(let failure)):
                            reported = failure
                        case .helperResult(let message):
                            reported = Self.helperFailure(message)
                        case nil:
                            continue
                        }
                    }
                    if let reported { throw reported }
                    continuation.finish()
                } catch let failure as ActivityRecorderFailure {
                    continuation.finish(throwing: failure)
                } catch SandvaultError.commandFailed(_, let code, let stderr) {
                    continuation.finish(throwing: reported ?? Self.sudoFailure(exitCode: code, stderr: stderr, heardFromHelper: heardFromHelper))
                } catch {
                    continuation.finish(throwing: reported ?? ActivityRecorderFailure.unavailable("\(error)"))
                }
            }
            continuation.onTermination = { _ in task.cancel() }
        }
    }

    public func stored(since: Date?, retentionDays: Int) async throws -> [FileActivityEvent] {
        try await store.read(since: since, retentionDays: retentionDays, now: now())
    }

    public func clear() async throws {
        try await store.clear()
    }

    public func storageBytes() async -> Int64 {
        await store.sizeBytes()
    }

    // MARK: - Helper output

    enum Decoded {
        case line(ActivityStreamLine)
        /// A `HelperResult` instead of stream lines: a helper too old for `activity-record`, or one not run as root.
        case helperResult(String)
    }

    static func decode(_ text: String) -> Decoded? {
        let data = Data(text.utf8)
        if let line = try? JSONCoding.decoder.decode(ActivityStreamLine.self, from: data) { return .line(line) }
        if let result = try? JSONCoding.decoder.decode(HelperResult.self, from: data), !result.ok { return .helperResult(result.message) }
        return nil
    }

    static func helperFailure(_ message: String) -> ActivityRecorderFailure {
        message.contains("unknown subcommand") ? .needsHelper : .unavailable(message)
    }

    /// The helper exited without saying why: sudo refused (no rule for this argv, helper missing) or it crashed.
    static func sudoFailure(exitCode: Int32, stderr: String, heardFromHelper: Bool) -> ActivityRecorderFailure {
        let text = stderr.trimmingCharacters(in: .whitespacesAndNewlines)
        let lower = text.lowercased()
        let sudoRefusals = ["password is required", "a terminal is required", "command not found", "no such file",
                            "not allowed to execute", "is not in the sudoers file", "may not run sudo"]
        if sudoRefusals.contains(where: lower.contains) { return .needsHelper }
        // The plain line stream carries no stderr; nothing at all from the helper means sudo did not run it.
        if text.isEmpty, !heardFromHelper { return .needsHelper }
        let detail = text.split(whereSeparator: \.isNewline).last.map(String.init) ?? ""
        return .unavailable(detail.isEmpty ? "the helper exited \(exitCode)" : detail)
    }
}
