import Foundation
import SandvaultCore
import Testing
@testable import SandvaultObserve

@Suite struct ProcessParserTests {
    @Test func parsesEveryColumnOfPs() throws {
        let processes = ProcessParser.parse(try fixture("ps-axww.txt"))
        #expect(processes.count == 20)
        let node = try #require(processes.first { $0.pid == 4130 })
        #expect(node.ppid == 4121)
        #expect(node.user == "sandvault-alice")
        #expect(node.cpuPercent == 12.5)  // decimal comma from a German locale
        #expect(node.memPercent == 1.1)
        #expect(node.rssKiB == 180_224)
        #expect(node.elapsedSeconds == 45 * 60 + 10)
        #expect(node.state == "R+")
        #expect(node.command == "node /Users/sandvault-alice/.npm-global/bin/vite --port 5173")
        let chrome = try #require(processes.first { $0.pid == 4105 })
        #expect(chrome.command.hasPrefix("/Applications/Google Chrome.app/Contents/MacOS/Google Chrome --headless"))
    }

    @Test func parsesAnIdleSandboxOnMacOS27() throws {
        let processes = ProcessParser.parse(try fixture("ps-axww-idle.txt"))
        #expect(processes.count == 8)
        #expect(processes.allSatisfy { $0.user == "sandvault-alice" && $0.ppid == 1 })
        let trustd = try #require(processes.first { $0.pid == 72858 })
        #expect(trustd.elapsedSeconds == 86_400 + 5 * 3600 + 11 * 60 + 27)
        #expect(trustd.command == "/usr/libexec/trustd --agent")
        // Without a running session, no process carries SV_SESSION_ID; system agents print no environment.
        #expect(ProcessParser.sessionIDs(try fixture("ps-environment-idle.txt")).isEmpty)
    }

    @Test func skipsMalformedLines() {
        #expect(ProcessParser.parse("garbage\n  12 1 root 0.0\n\n").isEmpty)
    }

    @Test(arguments: [
        ("00:03", 3), ("45:10", 2710), ("1:02:03", 3723), ("01:02:03", 3723), ("05-03:12:44", 5 * 86_400 + 11_564),
        ("2-00:00:00", 172_800),
    ])
    func parsesElapsedTime(text: String, seconds: Int) {
        #expect(ProcessParser.elapsedSeconds(text) == seconds)
    }

    @Test(arguments: ["", "12", "a:b", "1:2:3:4", "x-01:00", "-1:00"])
    func rejectsBadElapsedTime(text: String) {
        #expect(ProcessParser.elapsedSeconds(text) == nil)
    }

    @Test func readsSessionIDsFromTheAppendedEnvironment() throws {
        let ids = ProcessParser.sessionIDs(try fixture("ps-environment.txt"))
        #expect(ids == [4121: firstSession, 4130: firstSession, 5221: secondSession, 5222: secondSession, 5223: secondSession])
    }

    @Test func sessionIDIsStrict() {
        #expect(ProcessParser.sessionID(in: "zsh SV_SESSION_ID=3f2504e0-4f89-11d3-9a0c-0305e82c3301") == firstSession)
        #expect(ProcessParser.sessionID(in: "zsh SV_SESSION_ID=not-a-uuid") == nil)
        #expect(ProcessParser.sessionID(in: "zsh SV_SESSION_ID=\(firstSession)x") == nil)
        #expect(ProcessParser.sessionID(in: "zsh XSV_SESSION_ID=\(firstSession)") == nil)
        #expect(ProcessParser.sessionID(in: "zsh SV_SESSION_ID=\(firstSession)-1") == nil)
        // An argument that looks like the variable comes before the real environment; the last one wins.
        #expect(ProcessParser.sessionID(in: "tool SV_SESSION_ID=\(secondSession) HOME=/x SV_SESSION_ID=\(firstSession)") == firstSession)
    }

    @Test func readsHelperPortsFromLogs() throws {
        #expect(HelperLogParser.chromePort(try fixture("chrome.log")) == 52341)
        #expect(HelperLogParser.bridgePort(try fixture("ios-bridge.log")) == 52400)
        #expect(HelperLogParser.chromePort("starting...") == nil)
        #expect(HelperLogParser.bridgePort("Bridge listening on http://127.0.0.1:0") == nil)
    }

    @Test func commandNames() {
        #expect(CommandName.display("-zsh") == "zsh")
        #expect(CommandName.display("node /opt/homebrew/bin/codex") == "codex")
        #expect(CommandName.display("node --max-old-space-size=4096 /x/bin/gemini") == "gemini")
        #expect(CommandName.agent(in: "claude") == "claude")
        #expect(CommandName.agent(in: "/bin/zsh -c npm test") == nil)
    }
}

@Suite struct ProcessMonitorTests {
    func monitor(_ runner: CommandRunner) throws -> ProcessMonitor {
        ProcessMonitor(environment: alice, runner: runner, files: try helperLogs())
    }

    @Test func snapshotGroupsSessionsAndFindsHelpers() async throws {
        let snapshot = try await monitor(try observeRunner()).snapshot()
        #expect(snapshot.environmentReadable)
        // The lsof of a concurrent inspection (pid 6001, child of our own sudo) is not a sandbox process to show.
        #expect(snapshot.processes.map(\.pid) == [320, 4121, 4130, 4140, 5221, 5222, 5223])
        #expect(snapshot.processes.first { $0.pid == 320 }?.sessionID == nil)
        // No SV_SESSION_ID in its own environment: inherited from the parent.
        #expect(snapshot.processes.first { $0.pid == 4140 }?.sessionID == firstSession)

        #expect(snapshot.sessions.map(\.id) == [firstSession, secondSession])
        let first = snapshot.sessions[0], second = snapshot.sessions[1]
        #expect(first.rootPID == 4121)
        #expect(first.processCount == 3)
        #expect(first.command == "claude")
        #expect(first.elapsedSeconds == 3721)
        #expect(first.helpers == [HostHelperProcess(pid: 4105, kind: .chrome, port: 52341, sessionID: firstSession)])
        #expect(second.rootPID == 5221)
        #expect(second.command == "codex")
        #expect(second.helpers == [HostHelperProcess(pid: 5210, kind: .iosBridge, port: 52400, sessionID: secondSession)])
        #expect(snapshot.helpers.count == 2)  // the Chrome renderer is not a helper of its own
    }

    @Test func fallsBackToLauncherAncestryWithoutSudo() async throws {
        let fake = try observeRunner()
        fake.on(Invocations.psEnvironment(alice).argv, stdout: "", exitCode: 1, stderr: "sudo: a password is required\n")
        let snapshot = try await monitor(fake).snapshot()
        #expect(!snapshot.environmentReadable)
        #expect(snapshot.sessions.map(\.id) == [firstSession, secondSession])
        #expect(snapshot.processes.filter { $0.sessionID == nil }.map(\.pid) == [320])
    }

    @Test func noSandboxProcessesIsAnEmptySnapshot() async throws {
        let fake = FakeCommandRunner()
        fake.on(Invocations.psAll.argv, stdout: "    1     0 root  0.0  0.1  14336 05-03:12:44 Ss   /sbin/launchd\n")
        fake.on(Invocations.psEnvironment(alice).argv, stdout: "", exitCode: 1)
        let snapshot = try await ProcessMonitor(environment: alice, runner: fake, files: .fixed()).snapshot()
        #expect(snapshot.processes.isEmpty)
        #expect(snapshot.sessions.isEmpty)
        #expect(snapshot.environmentReadable)
    }

    @Test func psFailureThrows() async {
        let fake = FakeCommandRunner()
        fake.on(Invocations.psAll.argv, stdout: "", exitCode: 1, stderr: "ps: boom")
        await #expect(throws: SandvaultError.self) { try await ProcessMonitor(environment: alice, runner: fake).snapshot() }
    }

    @Test func treeIsDepthFirst() async throws {
        let snapshot = try await monitor(try observeRunner()).snapshot()
        let tree = snapshot.tree().map { "\($0.depth):\($0.process.pid)" }
        #expect(tree == ["0:320", "0:4121", "1:4130", "2:4140", "0:5221", "1:5222", "2:5223"])
    }

    @Test func sessionLookupByPrefix() async throws {
        let snapshot = try await monitor(try observeRunner()).snapshot()
        #expect(try snapshot.session(matching: "3f25").id == firstSession)
        #expect(try snapshot.session(matching: secondSession).id == secondSession)
        #expect(throws: SandvaultError.self) { try snapshot.session(matching: "ffff") }
        #expect(throws: SandvaultError.self) { try snapshot.session(matching: "") }
    }

    @Test func helpersNeedNoSudo() async throws {
        let fake = FakeCommandRunner()
        fake.on(Invocations.psAll.argv, stdout: try fixture("ps-axww.txt"))
        let helpers = try await ProcessMonitor(environment: alice, runner: fake, files: try helperLogs()).helpers()
        #expect(helpers.compactMap(\.port) == [52341, 52400])
        #expect(fake.invocations.map(\.executable) == ["/bin/ps"])
    }
}

@Suite struct ProcessControlTests {
    func controller(_ runner: CommandRunner) -> ProcessController {
        ProcessController(environment: alice, runner: runner, settleDelay: .zero)
    }

    @Test func terminateSendsTermAsTheSandboxUser() async throws {
        let runner = SequencedRunner()
        let ps = try fixture("ps-axww.txt")
        runner.on(Invocations.psAll.argv, stdout: ps)
        runner.on(Invocations.psAll.argv, stdout: ps.split(separator: "\n").filter { !$0.contains(" 4130 ") }.joined(separator: "\n"))
        let kill = ["/usr/bin/sudo", "-n", "-u", "sandvault-alice", "/usr/bin/env", "/bin/kill", "-TERM", "4130"]
        runner.on(kill, stdout: "")
        let report = try await controller(runner).terminate(pid: 4130)
        #expect(runner.count(kill) == 1)
        #expect(report.succeeded)
        #expect(report.remaining.isEmpty)
        #expect(report.targets == [4130])
    }

    @Test func forceSendsKillAndReportsSurvivors() async throws {
        let fake = try observeRunner()
        let kill = ["/usr/bin/sudo", "-n", "-u", "sandvault-alice", "/usr/bin/env", "/bin/kill", "-KILL", "4121"]
        fake.on(kill, stdout: "")
        let report = try await controller(fake).terminate(pid: 4121, force: true)
        #expect(fake.invocations.contains { $0.argv == kill })
        #expect(report.action == "kill")
        #expect(report.remaining == [4121])  // the fake ps still lists it
        #expect(!report.succeeded)
    }

    @Test func refusesProcessesOutsideTheSandbox() async throws {
        let fake = try observeRunner()
        await #expect(throws: SandvaultError.permissionDenied("pid 612 belongs to alice, not sandvault-alice")) {
            try await controller(fake).terminate(pid: 612)
        }
        await #expect(throws: SandvaultError.invalidInput("no process with pid 99999")) {
            try await controller(fake).terminate(pid: 99999)
        }
        // Our own inspection process is not a target either.
        await #expect(throws: SandvaultError.self) { try await controller(fake).terminate(pid: 6001) }
        #expect(!fake.invocations.contains { $0.argv.contains("/bin/kill") })
    }

    @Test func sudoRefusalIsAnError() async throws {
        let fake = try observeRunner()
        fake.on(["/usr/bin/sudo", "-n", "-u", "sandvault-alice", "/usr/bin/env", "/bin/kill"], stdout: "", exitCode: 1,
                stderr: "sudo: a password is required\n")
        await #expect(throws: SandvaultError.sudoMissing(alice)) { try await controller(fake).terminate(pid: 4130) }
    }

    @Test func terminateSessionSignalsAllItsProcesses() async throws {
        let fake = try observeRunner()
        let kill = ["/usr/bin/sudo", "-n", "-u", "sandvault-alice", "/usr/bin/env", "/bin/kill", "-TERM", "5221", "5222", "5223"]
        fake.on(kill, stdout: "")
        let report = try await controller(fake).terminateSession("7b1e")
        #expect(report.targets == [5221, 5222, 5223])
        #expect(fake.invocations.contains { $0.argv == kill })
    }

    @Test func terminateAllUsesSvSudoersRulesVerbatim() async throws {
        let runner = SequencedRunner()
        let ps = try fixture("ps-axww.txt")
        let hostOnly = withoutSandboxProcesses(ps)
        runner.on(Invocations.psAll.argv, CommandResult(exitCode: 0, stdout: ps), CommandResult(exitCode: 0, stdout: ps),
                  CommandResult(exitCode: 0, stdout: hostOnly))
        runner.on(["/usr/bin/dscl", ".", "-read", "/Users/sandvault-alice", "UniqueID"], stdout: "UniqueID: 502\n")
        let bootout = ["/usr/bin/sudo", "-n", "/bin/launchctl", "bootout", "user/502"]
        let pkill = ["/usr/bin/sudo", "-n", "/usr/bin/pkill", "-9", "-u", "sandvault-alice"]
        runner.on(bootout, stdout: "")
        runner.on(pkill, stdout: "")
        let report = try await controller(runner).terminateAll()
        #expect(runner.count(bootout) == 1)
        #expect(runner.count(pkill) == 1)
        #expect(report.steps.map(\.command) == [bootout.joined(separator: " "), pkill.joined(separator: " ")])
        #expect(report.succeeded)
        #expect(report.targets == [320, 4121, 4130, 4140, 5221, 5222, 5223])
    }

    @Test func terminateAllSkipsPkillWhenBootoutSuffices() async throws {
        let runner = SequencedRunner()
        let ps = try fixture("ps-axww.txt")
        let hostOnly = withoutSandboxProcesses(ps)
        runner.on(Invocations.psAll.argv, CommandResult(exitCode: 0, stdout: ps), CommandResult(exitCode: 0, stdout: hostOnly))
        runner.on(["/usr/bin/dscl", ".", "-read", "/Users/sandvault-alice", "UniqueID"], stdout: "UniqueID: 502\n")
        runner.on(["/usr/bin/sudo", "-n", "/bin/launchctl", "bootout", "user/502"], stdout: "")
        let report = try await controller(runner).terminateAll()
        #expect(report.steps.count == 1)
        #expect(report.succeeded)
    }

    @Test func terminateAllReportsARefusedSudoRule() async throws {
        let fake = try observeRunner()
        fake.on(["/usr/bin/dscl", ".", "-read", "/Users/sandvault-alice", "UniqueID"], stdout: "UniqueID: 502\n")
        fake.on(["/usr/bin/sudo", "-n", "/bin/launchctl"], stdout: "", exitCode: 1, stderr: "sudo: a password is required\n")
        fake.on(["/usr/bin/sudo", "-n", "/usr/bin/pkill"], stdout: "", exitCode: 1, stderr: "sudo: a password is required\n")
        let report = try await controller(fake).terminateAll()
        #expect(report.steps.allSatisfy { !$0.ok })
        #expect(!report.remaining.isEmpty)
        #expect(!report.succeeded)
    }

    @Test func throttleRunsReniceAndTaskpolicy() async throws {
        let fake = try observeRunner()
        let renice = ["/usr/bin/sudo", "-n", "-u", "sandvault-alice", "/usr/bin/env", "/usr/bin/renice", "+15", "-p", "4130"]
        let taskpolicy = ["/usr/bin/sudo", "-n", "-u", "sandvault-alice", "/usr/bin/env", "/usr/sbin/taskpolicy", "-b", "-p", "4130"]
        fake.on(renice, stdout: "4130: old priority 0, new priority 15\n")
        fake.on(taskpolicy, stdout: "", exitCode: 1, stderr: "taskpolicy: setpriority: Operation not permitted\n")
        let report = try await controller(fake).throttle(pid: 4130, nice: 15, background: true)
        #expect(report.steps.map(\.ok) == [true, false])
        #expect(report.steps[1].detail == "taskpolicy: setpriority: Operation not permitted")
        #expect(!report.succeeded)
    }

    @Test func throttleValidatesInput() async throws {
        let fake = try observeRunner()
        await #expect(throws: SandvaultError.self) { try await controller(fake).throttle(pid: 4130, nice: 0) }
        await #expect(throws: SandvaultError.self) { try await controller(fake).throttle(pid: 4130, nice: 21) }
        await #expect(throws: SandvaultError.self) { try await controller(fake).throttle(pid: 4130, nice: nil, background: false) }
        await #expect(throws: SandvaultError.self) { try await controller(fake).throttle(pid: 612) }
    }
}
