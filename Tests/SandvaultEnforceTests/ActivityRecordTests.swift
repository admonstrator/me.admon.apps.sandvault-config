import Foundation
import Testing
@testable import SandvaultCore
@testable import SandvaultEnforce

/// `activity-record`: the eslogger parser and the helper's stream with a fake eslogger.
@Suite struct ActivityRecordTests {
    static let dscl = ["/usr/bin/dscl", ".", "-read", "/Users/sandvault-alice", "UniqueID"]
    static let notes = "/Users/Shared/sv-alice/notes.txt"

    func lines() throws -> [String] {
        try Fixture.text("eslogger-activity.ndjson").components(separatedBy: "\n")
    }

    func events() throws -> [FileActivityEvent] {
        try lines().compactMap { ESLoggerParser.event(fromLine: $0, uid: 601) }
    }

    // MARK: - Parser

    @Test func parsesEveryEventKindOfTheSandboxUser() throws {
        let events = try events()
        #expect(events.map(\.kind) == [.exec, .open, .open, .write, .close, .close, .create, .create, .rename, .rename, .delete, .open])

        let exec = events[0]
        #expect(exec.path == "/usr/bin/git")
        #expect(exec.arguments == ["git", "status", "--short"])
        #expect(exec.process == "zsh" && exec.executable == "/bin/zsh" && exec.pid == 9100)
        #expect(exec.timestamp == Date(timeIntervalSince1970: 1_791_620_101))

        #expect(events[1].path == Self.notes && !events[1].forWriting)
        #expect(events[1].process == "claude" && events[1].executable == "/Users/sandvault-alice/.local/bin/claude")
        #expect(abs(events[1].timestamp.timeIntervalSince1970 - 1_791_620_102.123456789) < 0.000_01)
        #expect(events[2].forWriting)
        #expect(events[3].path == Self.notes)
        #expect(events[4].modified && !events[5].modified)
        #expect(events[6].path == "/Users/Shared/sv-alice/draft.md")
        #expect(events[7].path == "/Users/Shared/sv-alice/existing.txt")
        #expect(events[8].path == "/Users/Shared/sv-alice/draft.md" && events[8].destination == "/Users/Shared/sv-alice/docs/final.md")
        #expect(events[9].destination == Self.notes)
        #expect(events[10].path == "/Users/Shared/sv-alice/old.log")
    }

    @Test func keepsProcessesWhoseRealUIDIsTheSandbox() throws {
        // sudo started by the sandbox: euid 0, ruid 601.
        let sudo = try #require(try events().last)
        #expect(sudo.process == "sudo" && sudo.path == "/private/etc/sudoers")
    }

    @Test func dropsOtherUsersUnsubscribedEventsAndGarbage() throws {
        let all = try lines()
        let paths = try events().map(\.path)
        #expect(!paths.contains("/Users/alice/.zshrc"))
        // uid 6010 contains the digits of 601 but is another user.
        #expect(try events().filter { $0.process == "python3" }.isEmpty)
        #expect(all.filter { ESLoggerParser.event(fromLine: $0, uid: 601) == nil }.count == all.count - 12)
        #expect(ESLoggerParser.event(fromLine: "", uid: 601) == nil)
        #expect(ESLoggerParser.event(fromLine: "{\"time\":\"x\",\"process\":601}", uid: 601) == nil)
        // The host user's own event is found when asked for its uid.
        #expect(all.compactMap { ESLoggerParser.event(fromLine: $0, uid: 501) }.map(\.path) == ["/Users/alice/.zshrc"])
    }

    @Test func parsesTimestamps() {
        #expect(ESLoggerParser.parseTime("1970-01-01T00:00:00Z") == Date(timeIntervalSince1970: 0))
        #expect(ESLoggerParser.parseTime("2026-10-10T10:15:01+02:00") == Date(timeIntervalSince1970: 1_791_620_101))
        #expect(ESLoggerParser.parseTime("2026-10-10 08:15:01") == nil)
        #expect(ESLoggerParser.parseTime("2026-10-10T08:15:01") == nil)
    }

    // MARK: - Helper stream

    func helper(_ fake: FakeCommandRunner, _ environment: [String: String] = ["SUDO_USER": "alice", "SUDO_UID": "501"]) -> PrivilegedHelper {
        PrivilegedHelper(context: HelperContext(root: "/nonexistent", runner: fake, processEnvironment: environment, setsRootOwnership: false))
    }

    func record(_ helper: PrivilegedHelper, acceptingAtMost limit: Int = .max) async -> (ok: Bool, lines: [ActivityStreamLine]) {
        let output = Collector()
        let ok = await helper.recordActivity { line in
            output.append(line)
            return output.count < limit
        }
        return (ok, output.lines)
    }

    func fake(eslogger: FakeCommandRunner.Response) -> FakeCommandRunner {
        let fake = FakeCommandRunner()
        fake.on(Self.dscl, stdout: "UniqueID: 601\n")
        fake.on(PrivilegedHelper.esloggerInvocation.argv, eslogger)
        return fake
    }

    @Test func streamsStartedThenOnlySandboxEvents() async throws {
        let fake = fake(eslogger: .lines(try lines()))
        let (ok, lines) = await record(helper(fake))
        #expect(ok)
        #expect(lines.first == .started(uid: 601))
        let events = lines.dropFirst().compactMap { line -> FileActivityEvent? in
            if case .event(let event) = line { return event }
            return nil
        }
        #expect(events.count == 12 && lines.count == 13)
        #expect(!events.contains { $0.path == "/Users/alice/.zshrc" })
        #expect(fake.invocations.last?.argv == [
            "/usr/bin/eslogger", "exec", "open", "close", "create", "write", "rename", "unlink", "--format", "json",
        ])
        #expect(fake.invocations.last?.timeout == nil)
    }

    @Test func stopsWhenTheOutputIsClosed() async throws {
        let (ok, lines) = await record(helper(fake(eslogger: .lines(try lines()))), acceptingAtMost: 3)
        #expect(ok)
        #expect(lines.count == 3)
    }

    @Test func reportsMissingFullDiskAccess() async throws {
        let stderr = try Fixture.text("eslogger-not-permitted.stderr.txt")
        let (ok, lines) = await record(helper(fake(eslogger: .stream(lines: [], exitCode: 71, stderr: stderr))))
        #expect(!ok)
        #expect(lines == [.started(uid: 601), .failed(.needsFullDiskAccess)])
    }

    @Test func reportsOtherEsloggerFailuresAsUnavailable() async throws {
        let failing = fake(eslogger: .stream(lines: [], exitCode: 64, stderr: "usage: eslogger [--format json] event ...\nunknown event: frob\n"))
        let (ok, lines) = await record(helper(failing))
        #expect(!ok)
        #expect(lines.last == .failed(.unavailable("eslogger exited 64: unknown event: frob")))

        let silent = await record(helper(fake(eslogger: .stream(lines: [], exitCode: 1, stderr: ""))))
        #expect(silent.lines.last == .failed(.unavailable("eslogger exited 1")))

        let missing = await record(helper(fake(eslogger: .failure(.commandNotRunnable("/usr/bin/eslogger", "No such file")))))
        #expect(missing.lines.last == .failed(.unavailable("cannot run /usr/bin/eslogger: No such file")))
    }

    @Test func needsSudoAndASandboxAccount() async throws {
        let noSudo = await record(helper(fake(eslogger: .lines([])), [:]))
        #expect(!noSudo.ok)
        #expect(noSudo.lines == [.failed(.unavailable("permission denied: SUDO_USER is not set; run the helper through sudo"))])

        let own = await record(helper(fake(eslogger: .lines([])), ["SUDO_USER": "alice", "SUDO_UID": "601"]))
        #expect(own.lines == [.failed(.unavailable("invalid input: uid 601 of sandvault-alice is the caller's own uid"))])
    }

    @Test func runRefersToTheStreamingEntryPoint() async {
        let result = await helper(FakeCommandRunner()).run(.activityRecord)
        #expect(!result.ok && result.message.contains("recordActivity"))
    }

    @Test func failureMapping() {
        #expect(PrivilegedHelper.esloggerFailure(exitCode: 1, stderr: "Not permitted to create an ES client") == .needsFullDiskAccess)
        #expect(PrivilegedHelper.esloggerFailure(exitCode: 1, stderr: "ES_NEW_CLIENT_RESULT_ERR_NOT_PRIVILEGED\n") == .unavailable("eslogger exited 1: ES_NEW_CLIENT_RESULT_ERR_NOT_PRIVILEGED"))
    }

    @Test func activityRecordIsUnattendedButTakesNoOtherFlags() {
        #expect(PrivilegedHelper.unattendedArguments.contains(["activity-record", "--json"]))
        #expect(PrivilegedHelper.sudoersRule(user: "alice").contains("\(AppPaths.helperPath) activity-record --json"))
    }
}

final class Collector: @unchecked Sendable {
    private let lock = NSLock()
    private var stored: [ActivityStreamLine] = []

    func append(_ line: ActivityStreamLine) { lock.withLock { stored.append(line) } }
    var lines: [ActivityStreamLine] { lock.withLock { stored } }
    var count: Int { lock.withLock { stored.count } }
}
