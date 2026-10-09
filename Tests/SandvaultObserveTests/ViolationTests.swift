import Foundation
import SandvaultCore
import Testing
@testable import SandvaultObserve

@Suite struct ViolationParserTests {
    @Test func parsesTheKernelMessage() throws {
        let message = try #require(ViolationParser.parseMessage("Sandbox: touch(4242) deny(1) file-write-create /Users/alice/x"))
        #expect(message == .init(process: "touch", pid: 4242, operation: "file-write-create", target: "/Users/alice/x", occurrences: 1))
    }

    @Test func parsesDuplicateReports() throws {
        #expect(ViolationParser.parseMessage("3 duplicate reports for Sandbox: a(5) deny(1) mach-lookup com.apple.x")?.occurrences == 3)
        #expect(ViolationParser.parseMessage("1 duplicate report for Sandbox: a(5) deny(1) mach-lookup com.apple.x")?.occurrences == 1)
        #expect(ViolationParser.parseMessage("0 duplicate reports for Sandbox: a(5) deny(1) mach-lookup com.apple.x") == nil)
    }

    @Test func toleratesAwkwardProcessNamesAndMissingTargets() throws {
        let chrome = try #require(ViolationParser.parseMessage(
            "Sandbox: Google Chrome Helper (Renderer)(4106) deny(1) file-read-data /Users/alice/My Files/a b.txt"
        ))
        #expect(chrome.process == "Google Chrome Helper (Renderer)")
        #expect(chrome.pid == 4106)
        #expect(chrome.target == "/Users/alice/My Files/a b.txt")
        #expect(ViolationParser.parseMessage("Sandbox: launchd(1) deny(1) system-fsctl")?.target == nil)
    }

    @Test(arguments: [
        "Sandbox: x(5) allow file-read-data /y",
        "Sandbox: com.apple.WebKit(1234) System Policy: deny(1) file-read-data /x",
        "Sandbox reporting: 2 violations suppressed",
        "random text",
        "Sandbox: (5) deny(1) file-read-data /x",
        "Sandbox: x(abc) deny(1) file-read-data /x",
    ])
    func rejectsOtherMessages(text: String) {
        #expect(ViolationParser.parseMessage(text) == nil)
    }

    @Test func parsesTimestamps() throws {
        let utc = try #require(ISO8601DateFormatter().date(from: "2026-10-09T10:00:01Z"))
        let parsed = try #require(ViolationParser.parseTimestamp("2026-10-09 12:00:01.123456+0200"))
        #expect(abs(parsed.timeIntervalSince(utc) - 0.123456) < 0.000_001)
        #expect(ViolationParser.parseTimestamp("2026-10-09 03:00:01-0700") == utc)
        #expect(ViolationParser.parseTimestamp("2026-10-09 12:00:01+02:00") == utc)
        #expect(ViolationParser.parseTimestamp("2024-02-29 00:00:00+0000") == ISO8601DateFormatter().date(from: "2024-02-29T00:00:00Z"))
        #expect(ViolationParser.parseTimestamp("yesterday") == nil)
    }

    @Test func parsesMacOS27Output() throws {
        // `log show` on macOS 27 ends with a summary object and reports duplicates of host processes.
        let lines = try fixture("log-violations-host-only.ndjson").split(separator: "\n").map(String.init)
        let violations = lines.compactMap(ViolationParser.parse(line:))
        #expect(violations.map(\.process) == ["duetexpertd", "logd_helper"])
        #expect(violations.map(\.occurrences) == [301, 1])
        #expect(violations[0].operation == "system-info")
        #expect(violations[0].target == "vfs.disk-space")
        #expect(ViolationParser.parse(line: try #require(lines.last)) == nil)
        #expect(try fixture("log-violations-none.ndjson").split(separator: "\n").compactMap { ViolationParser.parse(line: String($0)) }.isEmpty)
    }

    @Test func parsesALiveDenialOnMacOS27() throws {
        // `log stream` while the session ran `touch /Users/Shared/sv-probe; ls /Library/Keychains`. `log show`
        // with --info --debug a moment later had none of these: the kernel's reports are not stored.
        let lines = try fixture("log-stream-denials.ndjson").split(separator: "\n").map(String.init)
        let violations = lines.compactMap(ViolationParser.parse(line:))
        #expect(violations.map(\.raw) == [
            "Sandbox: touch(87299) deny(1) file-write-create /Users/Shared/sv-probe",
            "Sandbox: ls(87300) deny(1) file-read-metadata /Library/Keychains",
            "1 duplicate report for Sandbox: ls(87300) deny(1) file-read-metadata /Library/Keychains",
        ])
        #expect(violations[0].operation == "file-write-create")
        #expect(violations[0].target == "/Users/Shared/sv-probe")
        #expect(violations.map(\.occurrences) == [1, 1, 1])
    }

    @Test func skipsNonJSONAndForeignLines() throws {
        let lines = try fixture("log-violations.ndjson").split(separator: "\n").map(String.init)
        #expect(ViolationParser.parse(line: lines[0]) == nil)  // "Filtering the log data using ..."
        let first = try #require(ViolationParser.parse(line: lines[1]))
        #expect(first.raw == "Sandbox: claude(4121) deny(1) file-read-data /Users/alice/Documents/a.txt")
        #expect(!first.attributedToSandbox)
        // Only the first line of a multi-line message counts.
        #expect(ViolationParser.parse(line: lines[2])?.raw == first.raw)
        #expect(lines.compactMap(ViolationParser.parse(line:)).count == 12)
    }
}

@Suite struct ViolationMonitorTests {
    @Test func streamedViolationsAreAttributedAndDeduplicated() async throws {
        var violations: [SandboxViolation] = []
        for try await violation in ViolationMonitor(environment: alice, runner: try observeRunner()).stream() { violations.append(violation) }
        #expect(violations.count == 11)
        #expect(violations.filter(\.attributedToSandbox).count == 9)
        #expect(Set(violations.filter { !$0.attributedToSandbox }.map(\.pid)) == [999, 4150])
        #expect(violations.map(\.occurrences).reduce(0, +) == 13)
        let duplicate = try #require(violations.first { $0.raw.hasPrefix("3 duplicate") })
        #expect(duplicate.occurrences == 3)
        #expect(duplicate.target == "/Users/alice/Documents/a.txt")
    }

    @Test func runsLogStreamWithThePredicate() {
        #expect(Invocations.logStream.argv == [
            "/usr/bin/log", "stream", "--style", "ndjson", "--predicate",
            #"((processID == 0) AND (senderImagePath CONTAINS "/Sandbox")) OR (subsystem == "com.apple.sandbox.reporting")"#,
        ])
    }

    @Test func collectEndsWithTheStream() async throws {
        final class Seen: @unchecked Sendable {
            let lock = NSLock()
            var pids: [Int32] = []
            func add(_ pid: Int32) { lock.withLock { pids.append(pid) } }
        }
        let seen = Seen()
        let found = try await ViolationMonitor(environment: alice, runner: try observeRunner())
            .collect(for: .seconds(30)) { seen.add($0.pid) }
        #expect(found.count == 11)
        #expect(seen.lock.withLock { seen.pids } == found.map(\.pid))
    }

    @Test func collectStopsWhenTheTimeIsUp() async throws {
        let runner = OpenStreamRunner(base: try observeRunner(), output: try fixture("log-stream-denials.ndjson").split(separator: "\n").map(String.init))
        let found = try await ViolationMonitor(environment: alice, runner: runner).collect(for: .milliseconds(300))
        #expect(found.map(\.pid) == [87299, 87300, 87300])
    }

    @Test func streamFailureExplainsTheAdminRequirement() async throws {
        let fake = try observeRunner()
        fake.on(Invocations.logStream.argv, .failure(.commandFailed("/usr/bin/log stream", 64, "")))
        await #expect(throws: SandvaultError.self) {
            for try await _ in ViolationMonitor(environment: alice, runner: fake).stream() {}
        }
        do {
            for try await _ in ViolationMonitor(environment: alice, runner: fake).stream() {}
        } catch let error as SandvaultError {
            guard case .permissionDenied(let text) = error else { Issue.record("unexpected \(error)"); return }
            #expect(text.contains("administrator"))
        }
    }

    @Test(arguments: [("30s", 30), ("10m", 600), ("2h", 7200), ("120m", 7200)])
    func acceptsDurations(text: String, seconds: Int) throws {
        #expect(try ViolationMonitor.duration(text) == .seconds(seconds))
    }

    @Test(arguments: ["", "m", "10", "0m", "1d", "1.5h", "-1m", "10 m", "١٠m"])
    func rejectsDurations(text: String) {
        #expect(throws: SandvaultError.self) { try ViolationMonitor.duration(text) }
    }
}

@Suite struct RuleSuggesterTests {
    func violations(all: Bool) async throws -> [SandboxViolation] {
        let found = try await ViolationMonitor(environment: alice, runner: try observeRunner()).collect(for: .seconds(30))
        return all ? found : found.filter(\.attributedToSandbox)
    }

    @Test func groupsIntoTheSmallestSensibleRules() async throws {
        let suggestions = RuleSuggester.suggestions(for: try await violations(all: false), environment: alice)
        #expect(suggestions.map(\.id) == [
            "file:subpath:/Users/alice/Documents", "mach:com.apple.pasteboard.1", "exec:/usr/bin/osascript",
            "file:literal:/Volumes/Backup/old.txt",
        ])

        let documents = suggestions[0]
        guard case .file(let rule) = documents.proposal else { Issue.record("not a file rule"); return }
        #expect(rule.path == "/Users/alice/Documents")
        #expect(rule.match == .subpath)
        #expect(rule.access == .readWrite)
        #expect(rule.effect == .allow)
        #expect(rule.note?.contains("POSIX permissions") == true)
        #expect(documents.occurrences == 6)
        #expect(documents.processes == ["claude", "node"])
        #expect(documents.examples == ["file-read-data /Users/alice/Documents/a.txt", "file-write-create /Users/alice/Documents/c.txt", "file-read-data /Users/alice/Documents/b.txt"])
        #expect(documents.lastSeen == ViolationParser.parseTimestamp("2026-10-09 12:00:04.000000+0200"))

        guard case .mach(let mach) = suggestions[1].proposal else { Issue.record("not a mach rule"); return }
        #expect(mach.name == "com.apple.pasteboard.1")
        #expect(mach.effect == .allow)
        #expect(suggestions[1].occurrences == 2)

        guard case .exec(let exec) = suggestions[2].proposal else { Issue.record("not an exec rule"); return }
        #expect(exec.path == "/usr/bin/osascript")
        #expect(exec.effect == .allow)

        guard case .file(let single) = suggestions[3].proposal else { Issue.record("not a file rule"); return }
        #expect(single.match == .literal)
        #expect(single.access == .write)
        #expect(single.note == nil)
    }

    @Test func networkDenialsProduceNoRule() async throws {
        let suggestions = RuleSuggester.suggestions(for: try await violations(all: true), environment: alice)
        #expect(!suggestions.contains { $0.examples.contains { $0.hasPrefix("network") } })
    }

    @Test func broadDirectoriesStayLiteral() async throws {
        // With unattributed violations, two files under /Volumes/Backup are hit; a two-level directory is never a subpath.
        let ids = RuleSuggester.suggestions(for: try await violations(all: true), environment: alice).map(\.id)
        #expect(ids.contains("file:literal:/Volumes/Backup/old.txt"))
        #expect(ids.contains("file:literal:/Volumes/Backup/out.txt"))
        #expect(!ids.contains("file:subpath:/Volumes/Backup"))
    }

    @Test func suggestionsAreStable() async throws {
        let input = try await violations(all: false)
        #expect(RuleSuggester.suggestions(for: input, environment: alice) == RuleSuggester.suggestions(for: input, environment: alice))
        #expect(RuleSuggester.stableUUID("a") != RuleSuggester.stableUUID("b"))
    }

    @Test func notesOnlyForOtherHomes() {
        #expect(RuleSuggester.foreignHomeNote("/Users/bob/x", alice) != nil)
        #expect(RuleSuggester.foreignHomeNote("/Users/sandvault-alice/x", alice) == nil)
        #expect(RuleSuggester.foreignHomeNote("/Users/Shared/sv-alice/x", alice) == nil)
        #expect(RuleSuggester.foreignHomeNote("/opt/homebrew/bin/x", alice) == nil)
    }
}
