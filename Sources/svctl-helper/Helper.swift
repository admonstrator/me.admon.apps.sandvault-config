import ArgumentParser
import Foundation
#if canImport(Darwin)
import Darwin
#elseif canImport(Glibc)
import Glibc
#endif
import SandvaultCore
import SandvaultEnforce

/// Root helper entry point. Runs only through sudo; see HelperProtocol.swift for the rules.
/// Typed state arrives as `AppliedState` JSON on stdin; the result is one `HelperResult` on stdout; exit 0 iff ok.
@main
struct Helper: AsyncParsableCommand {
    static let configuration = CommandConfiguration(
        commandName: "svctl-helper",
        abstract: "Privileged helper for Sandvault Config (run through sudo).",
        discussion: "Subcommands: \(HelperSubcommand.allCases.map(\.rawValue).joined(separator: ", ")).",
        version: BundleIdentity.version
    )

    @Argument(help: "The subcommand to run.")
    var subcommand: String

    @Flag(name: .long, help: "Print the result as one JSON line.")
    var json = false

    @Option(name: .long, help: "install/uninstall only: the host user (default: SUDO_USER).")
    var user: String?

    @Option(name: .long, help: "install only: the svctl-helper binary to copy (default: this binary).")
    var source: String?

    @Flag(name: .customLong("release-panic"), help: "pf-apply only: a user action that may leave the panic state.")
    var releasePanic = false

    func run() async throws {
        if subcommand == HelperSubcommand.activityRecord.rawValue {
            guard user == nil, source == nil, !releasePanic else {
                _ = ActivityStream.emit(.failed(.unavailable("activity-record takes no options besides --json")))
                throw ExitCode.failure
            }
            guard await ActivityStream.run() else { throw ExitCode.failure }
            return
        }
        let result = await execute()
        if json {
            FileHandle.standardOutput.write((try? JSONCoding.lineEncoder.encode(result)) ?? Data())
            FileHandle.standardOutput.write(Data("\n".utf8))
        } else {
            print(result.message)
            for key in result.details.keys.sorted() { print("  \(key): \(result.details[key] ?? "")") }
        }
        if !result.ok { throw ExitCode.failure }
    }

    func execute() async -> HelperResult {
        guard let command = HelperSubcommand(rawValue: subcommand) else {
            return HelperResult(ok: false, message: "unknown subcommand '\(subcommand)'")
        }
        #if os(macOS)
        guard geteuid() == 0 else { return HelperResult(ok: false, message: "svctl-helper must run as root (through sudo)") }
        let context = HelperContext(
            runner: ProcessCommandRunner(),
            processEnvironment: ProcessInfo.processInfo.environment,
            executablePath: Bundle.main.executableURL?.resolvingSymlinksInPath().path
        )
        let input = [.profileApply, .pfApply, .panic].contains(command) ? Self.readStandardInput() : nil
        let options = HelperOptions(user: user, source: source, releasePanic: releasePanic)
        return await PrivilegedHelper(context: context).run(command, options: options, input: input)
        #else
        return HelperResult(ok: false, message: SandvaultError.unsupportedPlatform("svctl-helper runs on macOS only (\(command.rawValue))").description)
        #endif
    }

    /// Reads at most one byte more than the limit, so oversized input is rejected instead of truncated.
    /// A terminal on stdin means no input (`sudo svctl-helper panic` typed by hand).
    static func readStandardInput() -> Data? {
        guard isatty(STDIN_FILENO) == 0 else { return nil }
        var data = Data()
        while data.count <= PrivilegedHelper.maxInputBytes,
              let chunk = try? FileHandle.standardInput.read(upToCount: 64 * 1024), !chunk.isEmpty {
            data.append(chunk)
        }
        return data
    }
}

/// `activity-record`: one `ActivityStreamLine` per stdout line until SIGTERM/SIGINT/SIGHUP or a closed stdout,
/// always as JSON. Exits non-zero after a `.failed` line.
enum ActivityStream {
    static func run() async -> Bool {
        #if os(macOS)
        guard geteuid() == 0 else {
            _ = emit(.failed(.unavailable("svctl-helper must run as root (through sudo)")))
            return false
        }
        let helper = PrivilegedHelper(context: HelperContext(
            runner: ProcessCommandRunner(), processEnvironment: ProcessInfo.processInfo.environment
        ))
        // Handlers first, so a stop that arrives while eslogger starts is not lost.
        let stop = StopRequest()
        StopSignals.install { stop.request() }
        let task = Task { await helper.recordActivity(emit: emit) }
        stop.attach(task)
        return await task.value
        #else
        _ = emit(.failed(.unavailable("svctl-helper runs on macOS only")))
        return false
        #endif
    }

    /// Writes one line with write(2); `false` once stdout is gone (EPIPE), so the caller stops.
    static func emit(_ line: ActivityStreamLine) -> Bool {
        guard var data = try? JSONCoding.lineEncoder.encode(line) else { return true }
        data.append(0x0A)
        return data.withUnsafeBytes { buffer in
            guard var base = buffer.baseAddress else { return true }
            var remaining = buffer.count
            while remaining > 0 {
                let written = write(STDOUT_FILENO, base, remaining)
                if written < 0 {
                    if errno == EINTR { continue }
                    return false
                }
                remaining -= written
                base += written
            }
            return true
        }
    }
}

/// Cancels the recording task, also when the stop came before the task existed.
final class StopRequest: @unchecked Sendable {
    private let lock = NSLock()
    private var task: Task<Bool, Never>?
    private var requested = false

    func attach(_ task: Task<Bool, Never>) {
        let cancel = lock.withLock {
            self.task = task
            return requested
        }
        if cancel { task.cancel() }
    }

    func request() {
        let task = lock.withLock {
            requested = true
            return self.task
        }
        task?.cancel()
    }
}

/// Stop requests as a callback. Handlers (not SIG_IGN) are used on purpose: caught signals are reset to the
/// default in eslogger after exec, so terminating it still works, and SIGPIPE turns into EPIPE on write.
enum StopSignals {
    nonisolated(unsafe) static var writeEnd: Int32 = -1

    static func install(onStop: @escaping @Sendable () -> Void) {
        var fds: [Int32] = [-1, -1]
        guard pipe(&fds) == 0 else { return }
        writeEnd = fds[1]
        let handler: @convention(c) (Int32) -> Void = { _ in
            var byte: UInt8 = 1
            _ = write(StopSignals.writeEnd, &byte, 1)
        }
        for number in [SIGTERM, SIGINT, SIGHUP] { signal(number, handler) }
        signal(SIGPIPE, { _ in })
        let readEnd = fds[0]
        Thread {
            var byte: UInt8 = 0
            while read(readEnd, &byte, 1) < 0, errno == EINTR {}
            onStop()
        }.start()
    }
}
