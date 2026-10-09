import Foundation
import Testing
@testable import SandvaultCore

@Suite struct CommandRunnerTests {
    let env = SandvaultEnvironment(hostUser: "alice", hostHome: "/Users/alice")

    @Test func asSandvaultUsesTheSudoersEnvRule() {
        let invocation = CommandInvocation.asSandvault(env, "/usr/sbin/lsof", ["-nP", "-i"])
        #expect(invocation.argv == ["/usr/bin/sudo", "-n", "-u", "sandvault-alice", "/usr/bin/env", "/usr/sbin/lsof", "-nP", "-i"])
    }

    @Test func viaHelperPassesStateOnStdin() {
        let invocation = CommandInvocation.viaHelper("pf-apply", ["--json"], stdin: Data("{}".utf8))
        #expect(invocation.argv == ["/usr/bin/sudo", "-n", AppPaths.helperPath, "pf-apply", "--json"])
        #expect(invocation.stdin == Data("{}".utf8))
    }

    @Test func fakeRunnerMatchesExactThenLongestPrefix() async throws {
        let fake = FakeCommandRunner()
        fake.on(["/bin/ps"], stdout: "prefix")
        fake.on(["/bin/ps", "-ax"], stdout: "longer")
        fake.on(["/bin/ps", "-ax", "-o", "pid"], stdout: "exact")
        #expect(try await fake.run(CommandInvocation("/bin/ps", ["-ax", "-o", "pid"])).stdoutString == "exact")
        #expect(try await fake.run(CommandInvocation("/bin/ps", ["-ax", "-o", "user"])).stdoutString == "longer")
        #expect(try await fake.run(CommandInvocation("/bin/ps", ["-e"])).stdoutString == "prefix")
        #expect(fake.invocations.count == 3)
        await #expect(throws: SandvaultError.self) { try await fake.run(CommandInvocation("/bin/ls")) }
    }

    @Test func fakeRunnerStreamsLines() async throws {
        let fake = FakeCommandRunner()
        fake.on(["/usr/bin/log", "stream"], .lines(["a", "b"]))
        var seen: [String] = []
        for try await line in fake.lines(CommandInvocation("/usr/bin/log", ["stream"])) { seen.append(line) }
        #expect(seen == ["a", "b"])
    }

    @Test func processRunnerCapturesOutputAndExitCode() async throws {
        let runner = ProcessCommandRunner()
        let echo = try await runner.run(CommandInvocation("/bin/sh", ["-c", "echo out; echo err >&2; exit 3"]))
        #expect(echo.exitCode == 3)
        #expect(echo.stdoutString == "out\n")
        #expect(echo.stderrString == "err\n")
        await #expect(throws: SandvaultError.self) { try await runner.checked(CommandInvocation("/bin/sh", ["-c", "exit 1"])) }
    }

    @Test func processRunnerFeedsStdin() async throws {
        let result = try await ProcessCommandRunner().run(CommandInvocation("/bin/cat", stdin: Data("hello".utf8)))
        #expect(result.stdoutString == "hello")
    }

    @Test func processRunnerTimesOut() async throws {
        await #expect(throws: SandvaultError.timedOut("/bin/sleep 5")) {
            try await ProcessCommandRunner().run(CommandInvocation("/bin/sleep", ["5"], timeout: 0.3))
        }
    }

    @Test func processRunnerStreamsLines() async throws {
        var seen: [String] = []
        for try await line in ProcessCommandRunner().lines(CommandInvocation("/bin/sh", ["-c", "printf 'one\\ntwo\\nthree'"])) {
            seen.append(line)
        }
        #expect(seen == ["one", "two", "three"])
    }

    @Test func missingExecutableIsNotRunnable() async {
        await #expect(throws: SandvaultError.self) {
            try await ProcessCommandRunner().run(CommandInvocation("/nonexistent/tool"))
        }
    }

    @Test func lineBufferKeepsPartialLines() {
        let buffer = LineBuffer()
        #expect(buffer.append(Data("ab".utf8)) == [])
        #expect(buffer.append(Data("c\nde".utf8)) == ["abc"])
        #expect(buffer.flush() == ["de"])
        #expect(buffer.flush() == [])
    }
}
