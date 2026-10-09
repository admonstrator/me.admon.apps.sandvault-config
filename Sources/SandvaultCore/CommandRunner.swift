import Foundation
#if canImport(Darwin)
import Darwin
#elseif canImport(Glibc)
import Glibc
#endif

/// One external command. The only way any module runs a process is through a `CommandRunner`,
/// so every call is visible, testable with `FakeCommandRunner`, and free of shell interpolation.
public struct CommandInvocation: Sendable, Hashable, Codable, CustomStringConvertible {
    public var executable: String
    public var arguments: [String]
    /// `nil` inherits the caller's environment; a dictionary replaces it.
    public var environment: [String: String]?
    public var stdin: Data?
    /// Seconds before the process is terminated; `nil` waits forever.
    public var timeout: Double?

    public init(
        _ executable: String,
        _ arguments: [String] = [],
        environment: [String: String]? = nil,
        stdin: Data? = nil,
        timeout: Double? = 30
    ) {
        self.executable = executable
        self.arguments = arguments
        self.environment = environment
        self.stdin = stdin
        self.timeout = timeout
    }

    /// argv as a single list, executable first.
    public var argv: [String] { [executable] + arguments }

    public var description: String {
        argv.map { $0.contains(" ") || $0.isEmpty ? "'\($0)'" : $0 }.joined(separator: " ")
    }

    /// Runs `executable` as the sandbox user without a password and without sandbox-exec.
    /// Works because sv's sudoers grants `<host> ALL=(sandvault-<host>) NOPASSWD: /usr/bin/env`.
    /// Use it for inspection of the sandbox user's own processes (ps -E, lsof, kill).
    public static func asSandvault(
        _ environment: SandvaultEnvironment,
        _ executable: String,
        _ arguments: [String] = [],
        timeout: Double? = 30
    ) -> CommandInvocation {
        CommandInvocation(
            "/usr/bin/sudo",
            ["-n", "-u", environment.sandvaultUser, "/usr/bin/env", executable] + arguments,
            timeout: timeout
        )
    }

    /// Runs the privileged helper through its sudoers rule. State goes in on stdin as JSON, never as a path.
    public static func viaHelper(_ subcommand: String, _ arguments: [String] = [], stdin: Data? = nil) -> CommandInvocation {
        CommandInvocation("/usr/bin/sudo", ["-n", AppPaths.helperPath, subcommand] + arguments, stdin: stdin, timeout: 60)
    }
}

public struct CommandResult: Sendable, Hashable, Codable {
    public var exitCode: Int32
    public var stdout: Data
    public var stderr: Data

    public init(exitCode: Int32, stdout: Data = Data(), stderr: Data = Data()) {
        self.exitCode = exitCode
        self.stdout = stdout
        self.stderr = stderr
    }

    public init(exitCode: Int32, stdout: String, stderr: String = "") {
        self.init(exitCode: exitCode, stdout: Data(stdout.utf8), stderr: Data(stderr.utf8))
    }

    public var succeeded: Bool { exitCode == 0 }
    public var stdoutString: String { String(decoding: stdout, as: UTF8.self) }
    public var stderrString: String { String(decoding: stderr, as: UTF8.self) }
}

public protocol CommandRunner: Sendable {
    /// Runs to completion and captures output. Throws only if the process cannot be started or times out;
    /// a non-zero exit is reported in the result.
    func run(_ invocation: CommandInvocation) async throws -> CommandResult

    /// Streams stdout line by line (for `log stream`, `nettop -L 0`). Cancelling the consuming task terminates the process.
    func lines(_ invocation: CommandInvocation) -> AsyncThrowingStream<String, Error>
}

extension CommandRunner {
    /// Runs and throws `SandvaultError.commandFailed` on a non-zero exit.
    public func checked(_ invocation: CommandInvocation) async throws -> CommandResult {
        let result = try await run(invocation)
        guard result.succeeded else {
            throw SandvaultError.commandFailed(invocation.description, result.exitCode, result.stderrString)
        }
        return result
    }
}

/// Real implementation on top of Foundation.Process.
public struct ProcessCommandRunner: CommandRunner {
    public init() {}

    public func run(_ invocation: CommandInvocation) async throws -> CommandResult {
        // Blocking waits run on dedicated threads, never on GCD workers or the cooperative pool:
        // a few slow commands must not delay unrelated tasks.
        try await withCheckedThrowingContinuation { continuation in
            Thread {
                do {
                    continuation.resume(returning: try Self.runBlocking(invocation))
                } catch {
                    continuation.resume(throwing: error)
                }
            }.start()
        }
    }

    public func lines(_ invocation: CommandInvocation) -> AsyncThrowingStream<String, Error> {
        AsyncThrowingStream { continuation in
            let process = Process()
            process.executableURL = URL(fileURLWithPath: invocation.executable)
            process.arguments = invocation.arguments
            if let environment = invocation.environment { process.environment = environment }
            let out = Pipe()
            process.standardOutput = out
            process.standardError = FileHandle.nullDevice
            process.standardInput = FileHandle.nullDevice

            continuation.onTermination = { _ in
                guard process.isRunning else { return }
                process.terminate()
                let pid = process.processIdentifier
                DispatchQueue.global().asyncAfter(deadline: .now() + 1) {
                    if process.isRunning { kill(pid, SIGKILL) }
                }
            }
            do {
                try process.run()
            } catch {
                continuation.finish(throwing: SandvaultError.commandNotRunnable(invocation.description, "\(error)"))
                return
            }

            // A dedicated thread does blocking reads until EOF, then reaps the process, so the last line
            // is always delivered before the stream finishes. Long-running streams do not tie up GCD workers.
            let reader = Thread {
                let buffer = LineBuffer()
                let handle = out.fileHandleForReading
                while true {
                    let chunk = handle.availableData
                    if chunk.isEmpty { break }
                    for line in buffer.append(chunk) { continuation.yield(line) }
                }
                for line in buffer.flush() { continuation.yield(line) }
                process.waitUntilExit()
                if process.terminationStatus == 0 || process.terminationReason == .uncaughtSignal {
                    continuation.finish()
                } else {
                    continuation.finish(throwing: SandvaultError.commandFailed(invocation.description, process.terminationStatus, ""))
                }
            }
            reader.start()
        }
    }

    static func runBlocking(_ invocation: CommandInvocation) throws -> CommandResult {
        let process = Process()
        process.executableURL = URL(fileURLWithPath: invocation.executable)
        process.arguments = invocation.arguments
        if let environment = invocation.environment { process.environment = environment }

        let out = Pipe(), err = Pipe(), input = Pipe()
        process.standardOutput = out
        process.standardError = err
        process.standardInput = invocation.stdin == nil ? FileHandle.nullDevice : input

        do {
            try process.run()
        } catch {
            throw SandvaultError.commandNotRunnable(invocation.description, "\(error)")
        }

        if let stdin = invocation.stdin {
            Thread {
                input.fileHandleForWriting.write(stdin)
                try? input.fileHandleForWriting.close()
            }.start()
        }

        // Drain both pipes concurrently so a chatty process never blocks on a full pipe.
        let group = DispatchGroup()
        let collected = Collected()
        group.enter()
        Thread {
            collected.setStdout(out.fileHandleForReading.readDataToEndOfFile())
            group.leave()
        }.start()
        group.enter()
        Thread {
            collected.setStderr(err.fileHandleForReading.readDataToEndOfFile())
            group.leave()
        }.start()

        var timedOut = false
        if let timeout = invocation.timeout {
            if group.wait(timeout: .now() + timeout) == .timedOut {
                timedOut = true
                process.terminate()
                if group.wait(timeout: .now() + 1) == .timedOut {
                    // SIGTERM can be blocked by an inherited signal mask; SIGKILL cannot.
                    kill(process.processIdentifier, SIGKILL)
                    _ = group.wait(timeout: .now() + 2)
                }
            }
        } else {
            group.wait()
        }
        process.waitUntilExit()
        if timedOut { throw SandvaultError.timedOut(invocation.description) }
        return CommandResult(exitCode: process.terminationStatus, stdout: collected.stdout, stderr: collected.stderr)
    }
}

private final class Collected: @unchecked Sendable {
    private let lock = NSLock()
    private var out = Data()
    private var err = Data()
    var stdout: Data { lock.withLock { out } }
    var stderr: Data { lock.withLock { err } }
    func setStdout(_ data: Data) { lock.withLock { out = data } }
    func setStderr(_ data: Data) { lock.withLock { err = data } }
}

/// Splits a byte stream into UTF-8 lines; the last partial line is kept until more data or `flush`.
public final class LineBuffer: @unchecked Sendable {
    private let lock = NSLock()
    private var pending = Data()

    public init() {}

    public func append(_ chunk: Data) -> [String] {
        lock.withLock {
            pending.append(chunk)
            var lines: [String] = []
            while let newline = pending.firstIndex(of: 0x0A) {
                let line = pending[pending.startIndex..<newline]
                lines.append(String(decoding: line, as: UTF8.self))
                pending.removeSubrange(pending.startIndex...newline)
            }
            return lines
        }
    }

    public func flush() -> [String] {
        lock.withLock {
            defer { pending.removeAll() }
            return pending.isEmpty ? [] : [String(decoding: pending, as: UTF8.self)]
        }
    }
}

/// Test double. Responses match on the full argv first, then on the longest registered argv prefix.
public final class FakeCommandRunner: CommandRunner, @unchecked Sendable {
    public enum Response: Sendable {
        case result(CommandResult)
        case lines([String])
        case failure(SandvaultError)
    }

    private let lock = NSLock()
    private var responses: [[String]: Response] = [:]
    private var recorded: [CommandInvocation] = []

    public init() {}

    /// Registers a response for an exact argv or an argv prefix.
    public func on(_ argv: [String], _ response: Response) {
        lock.withLock { responses[argv] = response }
    }

    public func on(_ argv: [String], stdout: String, exitCode: Int32 = 0, stderr: String = "") {
        on(argv, .result(CommandResult(exitCode: exitCode, stdout: stdout, stderr: stderr)))
    }

    public var invocations: [CommandInvocation] { lock.withLock { recorded } }

    private func response(for invocation: CommandInvocation) -> Response? {
        lock.withLock {
            recorded.append(invocation)
            let argv = invocation.argv
            if let exact = responses[argv] { return exact }
            let prefixes = responses.keys.filter { argv.starts(with: $0) }.sorted { $0.count > $1.count }
            return prefixes.first.flatMap { responses[$0] }
        }
    }

    public func run(_ invocation: CommandInvocation) async throws -> CommandResult {
        switch response(for: invocation) {
        case .result(let result): return result
        case .lines(let lines): return CommandResult(exitCode: 0, stdout: lines.joined(separator: "\n") + "\n")
        case .failure(let error): throw error
        case nil: throw SandvaultError.commandNotRunnable(invocation.description, "no fake response registered")
        }
    }

    public func lines(_ invocation: CommandInvocation) -> AsyncThrowingStream<String, Error> {
        let response = response(for: invocation)
        return AsyncThrowingStream { continuation in
            switch response {
            case .lines(let lines):
                for line in lines { continuation.yield(line) }
                continuation.finish()
            case .result(let result):
                for line in result.stdoutString.split(separator: "\n", omittingEmptySubsequences: false) where !line.isEmpty {
                    continuation.yield(String(line))
                }
                continuation.finish()
            case .failure(let error):
                continuation.finish(throwing: error)
            case nil:
                continuation.finish(throwing: SandvaultError.commandNotRunnable(invocation.description, "no fake response registered"))
            }
        }
    }
}
