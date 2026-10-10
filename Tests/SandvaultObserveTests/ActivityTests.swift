import Foundation
import Testing
@testable import SandvaultCore
@testable import SandvaultObserve

private let start = Date(timeIntervalSince1970: 1_791_620_100)
private let notes = "/Users/Shared/sv-alice/notes.txt"

private func event(
    _ kind: FileActivityEvent.Kind, _ path: String = notes, at seconds: TimeInterval = 0, process: String = "claude",
    forWriting: Bool = false, modified: Bool = false
) -> FileActivityEvent {
    FileActivityEvent(
        timestamp: start.addingTimeInterval(seconds), kind: kind, path: path, pid: 812, process: process,
        executable: "/Users/sandvault-alice/.local/bin/\(process)", forWriting: forWriting, modified: modified
    )
}

private func settings(openAndClose: Bool = false, hideSystemFiles: Bool = true) -> ActivityRecordingSettings {
    ActivityRecordingSettings(enabled: true, openAndClose: openAndClose, hideSystemFiles: hideSystemFiles)
}

private func admitted(_ events: [FileActivityEvent], _ settings: ActivityRecordingSettings) -> [Bool] {
    var filter = ActivityFilter(settings: settings)
    return events.map { filter.admit($0) }
}

@Suite struct ActivityFilterTests {
    @Test func defaultKeepsChangesAndOneOpenPerFileAndMinute() {
        let events = [
            event(.exec, "/usr/bin/git"), event(.create), event(.rename), event(.delete),
            event(.close, modified: true), event(.close),
            event(.open, at: 1), event(.open, at: 30), event(.open, at: 61),
            event(.open, at: 31, forWriting: true),
            event(.write, at: 32), event(.write, at: 40),
            event(.open, at: 35, process: "node"),
        ]
        #expect(admitted(events, settings()) == [
            true, true, true, true,
            true, false,
            true, false, true,
            true,
            true, false,
            true,
        ])
    }

    @Test func openAndCloseKeepsEverythingButHiddenSystemReads() {
        let events = [event(.close), event(.open), event(.open, at: 1), event(.open, "/usr/lib/libz.dylib"), event(.write), event(.write)]
        #expect(admitted(events, settings(openAndClose: true)) == [true, true, true, false, true, true])
        #expect(admitted(events, settings(openAndClose: true, hideSystemFiles: false)) == [true, true, true, true, true, true])
    }

    @Test func systemFilesAreHiddenOnlyWhenRead() {
        let system = [
            event(.open, "/System/Library/Frameworks/Foundation.framework/Foundation"),
            event(.open, "/usr/share/zoneinfo/Europe/Zurich"), event(.open, "/Library/Preferences/com.apple.x.plist"),
            event(.open, "/private/var/db/timezone/zoneinfo"), event(.open, "/dev/null"),
            event(.open, "/System/Volumes/Preboot/Cryptexes/OS/System/Library/dyld/dyld_shared_cache_arm64e"),
            event(.close, "/usr/lib/libSystem.B.dylib"),
        ]
        #expect(admitted(system, settings()).allSatisfy { !$0 })
        let kept = [
            event(.open, "/dev/null", forWriting: true), event(.exec, "/usr/bin/git"), event(.create, "/Library/x"),
            event(.close, "/usr/local/x", modified: true), event(.open, "/Users/sandvault-alice/Library/Preferences/x.plist"),
            event(.open, "/Users/Shared/System/notes"),
        ]
        #expect(admitted(kept, settings()).allSatisfy { $0 })
        #expect(admitted(system.dropLast(), settings(hideSystemFiles: false)).allSatisfy { $0 })
    }

    @Test func helpers() {
        #expect(ActivityFilter.isRead(event(.open)) && ActivityFilter.isRead(event(.close)))
        #expect(!ActivityFilter.isRead(event(.open, forWriting: true)) && !ActivityFilter.isRead(event(.close, modified: true)))
        #expect(!ActivityFilter.isRead(event(.exec)))
        #expect(ActivityFilter.isSystemPath("/usr/bin/true") && !ActivityFilter.isSystemPath("/usrlocal"))
    }
}

@Suite struct ActivityStoreTests {
    let directory = FileManager.default.temporaryDirectory.appendingPathComponent("svctl-activity-\(UUID().uuidString)").path

    var paths: AppPaths { AppPaths(environment: SandvaultEnvironment(hostUser: "alice", hostHome: directory)) }

    func cleanup() { try? FileManager.default.removeItem(atPath: directory) }

    @Test func roundTripWithModesAndSince() async throws {
        defer { cleanup() }
        let store = ActivityStore(path: paths.activityLog)
        let events = [event(.exec, "/usr/bin/git"), event(.create, at: 10), event(.rename, at: 20)]
        try await store.append(Array(events.prefix(2)))
        try await store.append([events[2]])

        let back = try await store.read(since: nil, retentionDays: 7, now: start)
        #expect(back == events)
        #expect(try await store.read(since: start.addingTimeInterval(10), retentionDays: 7, now: start) == [events[2]])
        #expect(mode(paths.activityLog) == 0o600)
        #expect(mode((paths.activityLog as NSString).deletingLastPathComponent) == 0o700)
        #expect(await store.sizeBytes() > 0)

        try await store.clear()
        #expect(await store.sizeBytes() == 0)
        #expect(try await store.read(since: nil, retentionDays: 7, now: start).isEmpty)
        try await store.clear()
    }

    @Test func retentionRewritesTheFile() async throws {
        defer { cleanup() }
        let store = ActivityStore(path: paths.activityLog)
        let old = event(.create, at: -8 * 86_400), recent = event(.delete, at: -86_400)
        try await store.append([old, recent])
        let handle = try #require(FileHandle(forWritingAtPath: paths.activityLog))
        try handle.seekToEnd()
        try handle.write(contentsOf: Data("not json\n".utf8))
        try handle.close()

        #expect(try await store.read(since: nil, retentionDays: 0, now: start).count == 2)
        #expect(try await store.read(since: nil, retentionDays: 7, now: start) == [recent])
        let text = try String(contentsOfFile: paths.activityLog, encoding: .utf8)
        #expect(text.split(separator: "\n").count == 1)
        #expect(mode(paths.activityLog) == 0o600)
    }

    func mode(_ path: String) -> Int? {
        ((try? FileManager.default.attributesOfItem(atPath: path))?[.posixPermissions] as? NSNumber)?.intValue
    }
}

@Suite struct LiveActivityRecorderTests {
    let directory = FileManager.default.temporaryDirectory.appendingPathComponent("svctl-recorder-\(UUID().uuidString)").path

    var paths: AppPaths { AppPaths(environment: SandvaultEnvironment(hostUser: "alice", hostHome: directory)) }

    func cleanup() { try? FileManager.default.removeItem(atPath: directory) }

    func encode(_ line: ActivityStreamLine) throws -> String {
        String(decoding: try JSONCoding.lineEncoder.encode(line), as: UTF8.self)
    }

    func recorder(_ response: FakeCommandRunner.Response, stores: Bool = true) -> (LiveActivityRecorder, FakeCommandRunner) {
        let fake = FakeCommandRunner()
        fake.on(LiveActivityRecorder.invocation.argv, response)
        return (LiveActivityRecorder(paths: paths, runner: fake, stores: stores, now: { start }), fake)
    }

    func collect(_ recorder: LiveActivityRecorder, _ settings: ActivityRecordingSettings = settings()) async -> ([FileActivityEvent], Error?) {
        var events: [FileActivityEvent] = []
        do {
            for try await event in recorder.record(settings: settings) { events.append(event) }
            return (events, nil)
        } catch {
            return (events, error)
        }
    }

    @Test func runsTheSudoersArgvFiltersAndStores() async throws {
        defer { cleanup() }
        let kept = [event(.exec, "/usr/bin/git"), event(.open, at: 1), event(.close, at: 2, modified: true)]
        let lines = [
            try encode(.started(uid: 601)), try encode(.event(kept[0])), try encode(.event(kept[1])),
            try encode(.event(event(.open, at: 5))), try encode(.event(event(.close, at: 6))),
            try encode(.event(event(.open, "/usr/lib/dyld"))), "garbage", try encode(.event(kept[2])),
        ]
        let (recorder, fake) = recorder(.lines(lines))
        let (events, error) = await collect(recorder)
        #expect(error == nil)
        #expect(events == kept)
        #expect(try await recorder.stored(since: nil, retentionDays: 7) == kept)
        #expect(await recorder.storageBytes() > 0)
        #expect(fake.invocations.map(\.argv) == [["/usr/bin/sudo", "-n", AppPaths.helperPath, "activity-record", "--json"]])
        #expect(fake.invocations.first?.timeout == nil)

        try await recorder.clear()
        #expect(try await recorder.stored(since: nil, retentionDays: 7).isEmpty)
    }

    @Test func noStoreOnlyYields() async throws {
        defer { cleanup() }
        let (recorder, _) = recorder(.lines([try encode(.started(uid: 601)), try encode(.event(event(.delete)))]), stores: false)
        let (events, _) = await collect(recorder)
        #expect(events.count == 1)
        #expect(await recorder.storageBytes() == 0)
    }

    @Test func passesOnTheHelpersFailure() async throws {
        defer { cleanup() }
        let failed = [try encode(.started(uid: 601)), try encode(.failed(.needsFullDiskAccess))]
        let (recorder, _) = recorder(.stream(lines: failed, exitCode: 1, stderr: ""))
        let (_, error) = await collect(recorder)
        #expect(error as? ActivityRecorderFailure == .needsFullDiskAccess)
    }

    @Test(arguments: [
        ("sudo: a password is required\n", ActivityRecorderFailure.needsHelper),
        ("sudo: /Library/PrivilegedHelperTools/me.admon.apps.sandvault-config.helper: command not found\n", .needsHelper),
        ("", .needsHelper),
        ("Segmentation fault: 11\n", .unavailable("Segmentation fault: 11")),
    ])
    func mapsSudoFailures(stderr: String, expected: ActivityRecorderFailure) async throws {
        defer { cleanup() }
        let (recorder, _) = recorder(.stream(lines: [], exitCode: 1, stderr: stderr))
        let (_, error) = await collect(recorder)
        #expect(error as? ActivityRecorderFailure == expected)
    }

    @Test func aHelperWithoutTheSubcommandNeedsAReinstall() async throws {
        defer { cleanup() }
        let old = String(decoding: try JSONCoding.lineEncoder.encode(HelperResult(ok: false, message: "unknown subcommand 'activity-record'")), as: UTF8.self)
        let (recorder, _) = recorder(.stream(lines: [old], exitCode: 1, stderr: ""))
        let (_, error) = await collect(recorder)
        #expect(error as? ActivityRecorderFailure == .needsHelper)
    }

    @Test func helperExitAfterStartWithoutStderrIsUnavailable() async throws {
        defer { cleanup() }
        let (recorder, _) = recorder(.stream(lines: [try encode(.started(uid: 601))], exitCode: 1, stderr: ""))
        let (_, error) = await collect(recorder)
        #expect(error as? ActivityRecorderFailure == .unavailable("the helper exited 1"))
    }

    @Test func plainLineStreamWithoutStderrStillNeedsHelper() {
        #expect(LiveActivityRecorder.sudoFailure(exitCode: 1, stderr: "", heardFromHelper: false) == .needsHelper)
        #expect(LiveActivityRecorder.sudoFailure(exitCode: 1, stderr: "Sorry, user alice is not allowed to execute '...' as root", heardFromHelper: false) == .needsHelper)
    }
}

/// The real runner's stream the recorder and the helper use.
@Suite struct LinesWithStderrTests {
    let runner = ProcessCommandRunner()

    @Test func failsWithTheEndOfStderr() async throws {
        let invocation = CommandInvocation("/bin/sh", ["-c", "echo a; echo b; echo first >&2; echo last >&2; exit 3"], timeout: nil)
        var lines: [String] = []
        do {
            for try await line in runner.linesWithStderr(invocation, bufferLimit: 100) { lines.append(line) }
            Issue.record("expected a failure")
        } catch SandvaultError.commandFailed(_, let code, let stderr) {
            #expect(code == 3)
            #expect(stderr == "first\nlast\n")
        }
        #expect(lines == ["a", "b"])
    }

    @Test func holdsAtMostTheBufferLimit() async throws {
        let stream = runner.linesWithStderr(CommandInvocation("/usr/bin/seq", ["1", "1000"], timeout: nil), bufferLimit: 10)
        try await Task.sleep(for: .milliseconds(500))
        var lines: [String] = []
        for try await line in stream { lines.append(line) }
        #expect(lines == (1...10).map(String.init))
    }

    @Test func cancellingTerminatesTheProcess() async throws {
        let marker = FileManager.default.temporaryDirectory.appendingPathComponent("svctl-term-\(UUID().uuidString)").path
        defer { try? FileManager.default.removeItem(atPath: marker) }
        let script = "trap 'echo terminated > \"$0\"; exit 0' TERM; echo ready; sleep 30 & wait"
        let task = Task {
            for try await _ in runner.linesWithStderr(CommandInvocation("/bin/sh", ["-c", script, marker], timeout: nil), bufferLimit: 10) {}
        }
        try await Task.sleep(for: .milliseconds(300))
        task.cancel()
        _ = await task.result
        for _ in 0..<50 where !FileManager.default.fileExists(atPath: marker) { try await Task.sleep(for: .milliseconds(100)) }
        #expect((try? String(contentsOfFile: marker, encoding: .utf8)) == "terminated\n")
    }
}
