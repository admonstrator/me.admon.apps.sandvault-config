import Foundation
import SandvaultCore
@testable import SandvaultObserve

let alice = SandvaultEnvironment(hostUser: "alice", hostHome: "/Users/alice")
let firstSession = "3F2504E0-4F89-11D3-9A0C-0305E82C3301"
let secondSession = "7B1E0C52-0D8A-4C55-9B4E-2E8A1F6C9D10"

struct MissingFixture: Error {
    let name: String
}

func fixture(_ name: String) throws -> String {
    guard let url = Bundle.module.url(forResource: name, withExtension: nil, subdirectory: "Fixtures") else {
        throw MissingFixture(name: name)
    }
    return try String(contentsOf: url, encoding: .utf8)
}

/// A fake runner preloaded with every observe fixture for the sandbox of `alice`.
func observeRunner() throws -> FakeCommandRunner {
    let fake = FakeCommandRunner()
    fake.on(Invocations.psAll.argv, stdout: try fixture("ps-axww.txt"))
    fake.on(Invocations.psEnvironment(alice).argv, stdout: try fixture("ps-environment.txt"))
    fake.on(Invocations.lsof(alice).argv, stdout: try fixture("lsof-sandbox.txt"))
    fake.on(Invocations.nettop.argv, stdout: try fixture("nettop.csv"))
    fake.on(Invocations.logStream.argv, .lines(try fixture("log-violations.ndjson").split(separator: "\n").map(String.init)))
    return fake
}

/// Delegates to `base`, except that `lines` yields the given lines and then stays open like `log stream`.
struct OpenStreamRunner: CommandRunner {
    let base: CommandRunner
    let output: [String]

    func run(_ invocation: CommandInvocation) async throws -> CommandResult { try await base.run(invocation) }

    func lines(_ invocation: CommandInvocation) -> AsyncThrowingStream<String, Error> {
        let (stream, continuation) = AsyncThrowingStream.makeStream(of: String.self, throwing: Error.self)
        for line in output { continuation.yield(line) }
        return stream
    }
}

/// `ps -axww` output with every line of the sandbox user removed (the user is the third column).
func withoutSandboxProcesses(_ ps: String) -> String {
    ps.split(separator: "\n").filter { $0.split(separator: " ").dropFirst(2).first != "sandvault-alice" }.joined(separator: "\n")
}

/// Helper logs in alice's session state directory.
func helperLogs() throws -> HostFiles {
    HostFiles.fixed(files: [
        "\(alice.sessionStateDir)/chrome-\(firstSession).log": try fixture("chrome.log"),
        "\(alice.sessionStateDir)/ios-bridge-\(secondSession).log": try fixture("ios-bridge.log"),
    ])
}

/// Serves a sequence of results per exact argv (the last one repeats) and can delay every call.
final class SequencedRunner: CommandRunner, @unchecked Sendable {
    private let lock = NSLock()
    private var queues: [[String]: [CommandResult]] = [:]
    private var recorded: [CommandInvocation] = []
    let delay: Duration

    init(delay: Duration = .zero) {
        self.delay = delay
    }

    func on(_ argv: [String], _ results: CommandResult...) {
        lock.withLock { queues[argv, default: []] += results }
    }

    func on(_ argv: [String], stdout: String, exitCode: Int32 = 0, stderr: String = "") {
        on(argv, CommandResult(exitCode: exitCode, stdout: stdout, stderr: stderr))
    }

    var invocations: [CommandInvocation] { lock.withLock { recorded } }

    func count(_ argv: [String]) -> Int { invocations.filter { $0.argv == argv }.count }

    func run(_ invocation: CommandInvocation) async throws -> CommandResult {
        if delay > .zero { try await Task.sleep(for: delay) }
        let next: CommandResult? = lock.withLock {
            recorded.append(invocation)
            guard var queue = queues[invocation.argv], let first = queue.first else { return nil }
            if queue.count > 1 { queue.removeFirst() }
            queues[invocation.argv] = queue
            return first
        }
        guard let next else { throw SandvaultError.commandNotRunnable(invocation.description, "no fake response registered") }
        return next
    }

    func lines(_ invocation: CommandInvocation) -> AsyncThrowingStream<String, Error> {
        AsyncThrowingStream { $0.finish(throwing: SandvaultError.commandNotRunnable(invocation.description, "not streamed")) }
    }
}
