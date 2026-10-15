import Foundation
import Testing
@testable import SandvaultCore
@testable import SandvaultEnforce

/// The lab's helper logic against a temporary root. Off macOS `clonefileat` is replaced by a plain copy.
/// Serialized: the engine does blocking file work on the calling task, which in parallel starves the timing tests.
@Suite(.serialized) struct LabEngineTests {
    let root: TempRoot
    let fake = FakeCommandRunner()
    var home: String { root.path + "/Users/sandvault-alice" }
    var workspace: String { root.path + "/Users/Shared/sv-alice" }

    init() throws {
        root = try TempRoot()
        fake.on(["/usr/bin/dscl"], stdout: "UniqueID: 601\n")
        fake.on(["/bin/launchctl"], stdout: "")
        fake.on(["/usr/bin/pkill"], stdout: "", exitCode: 1)
        fake.on(["/usr/bin/pgrep"], stdout: "", exitCode: 1)
        try put("home", ".zshrc", "export PATH=/bin\n")
        try put("home", "notes/a.txt", "one\n")
        try put("workspace", "repos/app/README", "hello\n")
        try put("workspace", "android/sdk/platform-tools/adb", "binary")
        try put("workspace", "android/avd/pixel.ini", "avd\n")
    }

    func put(_ which: String, _ path: String, _ text: String) throws {
        let full = (which == "home" ? home : workspace) + "/" + path
        try FileManager.default.createDirectory(atPath: URL(fileURLWithPath: full).deletingLastPathComponent().path, withIntermediateDirectories: true)
        if FileManager.default.fileExists(atPath: full) { try FileManager.default.removeItem(atPath: full) }
        try Data(text.utf8).write(to: URL(fileURLWithPath: full))
    }

    func text(_ which: String, _ path: String) -> String? {
        FileManager.default.contents(atPath: (which == "home" ? home : workspace) + "/" + path).map { String(decoding: $0, as: UTF8.self) }
    }

    func helper(seconds: TimeInterval = 0) -> PrivilegedHelper {
        PrivilegedHelper(context: HelperContext(
            root: root.path, runner: fake, processEnvironment: ["SUDO_USER": "alice", "SUDO_UID": "501"], setsRootOwnership: false,
            now: { Date(timeIntervalSince1970: 1_700_000_000 + seconds) }
        ))
    }

    func send(_ request: LabRequest) async throws -> LabResponse {
        let response = await helper().lab(try JSONCoding.lineEncoder.encode(request))
        guard response.ok else { throw SandvaultError.io(response.message) }
        return response
    }

    static let settings = LabSettings(minFreeBytes: 0)

    @Test func startTakesTheFirstCheckpointWithoutExcludedPaths() async throws {
        defer { root.cleanup() }
        let response = try await send(.start(Self.settings))
        let session = try #require(response.session)
        #expect(session.roots == [.home, .workspace])
        #expect(session.checkpoints.map(\.reason) == [.start])
        let store = root.path + AppPaths.rootStateDir + "/lab/checkpoints/0"
        #expect(FileManager.default.fileExists(atPath: store + "/home/.zshrc"))
        #expect(FileManager.default.fileExists(atPath: store + "/workspace/android/avd/pixel.ini"))
        #expect(!FileManager.default.fileExists(atPath: store + "/workspace/android/sdk"))
        await #expect(throws: SandvaultError.self) { try await send(.start(Self.settings)) }
    }

    @Test func intervalCheckpointsOnlyWhenSomethingChanged() async throws {
        defer { root.cleanup() }
        _ = try await send(.start(Self.settings))
        let unchanged = try await send(.checkpoint(reason: .interval, label: nil, onlyIfChanged: true))
        #expect(unchanged.checkpoint == nil)

        try put("home", ".ssh/id_ed25519", "-----BEGIN OPENSSH PRIVATE KEY-----\nabc\n-----END OPENSSH PRIVATE KEY-----\n")
        try put("home", ".zshrc", "export PATH=/bin\neval \"$(tool init)\"\n")
        try FileManager.default.removeItem(atPath: home + "/notes/a.txt")
        try put("workspace", "android/sdk/platform-tools/adb", "changed in the excluded tree")
        let taken = try #require(try await send(.checkpoint(reason: .interval, label: nil, onlyIfChanged: true)).checkpoint)
        #expect(taken.parent == 0 && taken.label == "Automatic")
        #expect(taken.created == 2 && taken.changed == 1 && taken.deleted == 1) // .ssh, its key, .zshrc, notes/a.txt
        #expect(taken.findings == 2)

        let comparison = try #require(try await send(.compare(from: 0, to: nil)).comparison)
        #expect(comparison.changes.map(\.path.display) == ["~/.ssh", "~/.ssh/id_ed25519", "~/.zshrc", "~/notes/a.txt"])
        #expect(comparison.changes.first { $0.path.path == ".ssh/id_ed25519" }?.secret?.contains("private key") == true)
        let findings = LabFindings.findings(in: comparison.changes)
        #expect(Set(findings.map(\.kind)) == [.key, .shellStartup])
    }

    @Test func rewindPutsFilesBackAndKeepsTheStateBefore() async throws {
        defer { root.cleanup() }
        _ = try await send(.start(Self.settings))
        try put("home", "Library/LaunchAgents/com.evil.plist", "<plist/>")
        try put("workspace", "repos/app/README", "changed\n")
        try put("workspace", "android/sdk/new-tool", "host update")
        let marked = try #require(try await send(.checkpoint(reason: .manual, label: "after install", onlyIfChanged: false)).checkpoint)
        #expect(marked.label == "after install")
        try put("home", ".zshrc", "later\n")

        let rewound = try await send(.rewind(to: 0))
        let session = try #require(rewound.session)
        #expect(session.head == 0)
        #expect(session.rewinds.count == 1 && session.rewinds[0].savedAs == 2)
        #expect(session.checkpoint(2)?.reason == .beforeRewind)
        #expect(text("home", ".zshrc") == "export PATH=/bin\n")
        #expect(text("home", "notes/a.txt") == "one\n")
        #expect(!FileManager.default.fileExists(atPath: home + "/Library/LaunchAgents/com.evil.plist"))
        #expect(text("workspace", "repos/app/README") == "hello\n")
        // Excluded paths keep what they hold now.
        #expect(text("workspace", "android/sdk/new-tool") == "host update")
        #expect(fake.invocations.map(\.argv).contains(["/usr/bin/pkill", "-TERM", "-u", "sandvault-alice"]))

        // Forward again to the state before the rewind.
        _ = try await send(.rewind(to: 2))
        #expect(text("home", ".zshrc") == "later\n")
        #expect(text("workspace", "repos/app/README") == "changed\n")
        let afterwards = try #require(try await send(.compare(from: 1, to: nil)).comparison)
        #expect(afterwards.changes.map(\.path.display) == ["~/.zshrc"])
    }

    @Test func fileShowsTextAtACheckpointAndNow() async throws {
        defer { root.cleanup() }
        _ = try await send(.start(Self.settings))
        try put("home", ".zshrc", "now\n")
        let then = try #require(try await send(.file(LabPath(root: .home, path: ".zshrc"), at: 0)).file)
        let now = try #require(try await send(.file(LabPath(root: .home, path: ".zshrc"), at: nil)).file)
        #expect(then.text == "export PATH=/bin\n" && now.text == "now\n")
        let missing = try #require(try await send(.file(LabPath(root: .home, path: "nope"), at: 0)).file)
        #expect(!missing.exists)
        await #expect(throws: SandvaultError.self) { try await send(.file(LabPath(root: .home, path: "../alice/.ssh/id"), at: nil)) }
    }

    @Test func symlinksAreKeptAsLinksAndNeverFollowed() async throws {
        defer { root.cleanup() }
        try put("home", "secret-outside", "host secret\n")
        let outside = home + "/secret-outside"
        try FileManager.default.createSymbolicLink(atPath: home + "/link", withDestinationPath: outside)
        _ = try await send(.start(Self.settings))
        let file = try #require(try await send(.file(LabPath(root: .home, path: "link"), at: 0)).file)
        #expect(!file.exists)
        let store = root.path + AppPaths.rootStateDir + "/lab/checkpoints/0/home/link"
        #expect((try? FileManager.default.destinationOfSymbolicLink(atPath: store)) == outside)
    }

    @Test func pruningKeepsTheStartAndTheHead() async throws {
        defer { root.cleanup() }
        var settings = Self.settings
        settings.maxCheckpoints = 3
        _ = try await send(.start(settings))
        for index in 1...4 {
            try put("home", "notes/a.txt", "version \(index)\n")
            _ = try await send(.checkpoint(reason: .interval, label: nil, onlyIfChanged: true))
        }
        let session = try #require(try await send(.status).session)
        #expect(session.checkpoints.map(\.id) == [0, 3, 4])
        #expect(session.pruned == 2)
        #expect(session.checkpoint(3)?.parent == 0)
        // Composed changes still describe start -> 3.
        let comparison = try #require(try await send(.compare(from: 0, to: 3)).comparison)
        #expect(comparison.changes.map(\.path.display) == ["~/notes/a.txt"])
        #expect(!FileManager.default.fileExists(atPath: root.path + AppPaths.rootStateDir + "/lab/checkpoints/1"))
    }

    @Test func finishDiscardGoesBackToTheStartAndRemovesTheStore() async throws {
        defer { root.cleanup() }
        _ = try await send(.start(Self.settings))
        try put("home", "new.txt", "x")
        _ = try await send(.finish(keep: false))
        #expect(!FileManager.default.fileExists(atPath: home + "/new.txt"))
        #expect(try await send(.status).session == nil)
        #expect(!FileManager.default.fileExists(atPath: root.path + AppPaths.rootStateDir + "/lab/checkpoints"))

        _ = try await send(.start(Self.settings))
        try put("home", "kept.txt", "x")
        _ = try await send(.finish(keep: true))
        #expect(text("home", "kept.txt") == "x")
    }

    @Test func refusesBadInput() async {
        defer { root.cleanup() }
        #expect(await helper().lab(Data("{}".utf8)).ok == false)
        #expect(await helper().lab(nil).ok == false)
        var bad = Self.settings
        bad.excludes = [LabPath(root: .home, path: "../../etc")]
        let response = await helper().lab(try? JSONCoding.lineEncoder.encode(LabRequest.start(bad)))
        #expect(!response.ok && response.message.contains("invalid lab path"))
        #expect(PrivilegedHelper.unattendedArguments.contains(["lab", "--json"]))
    }
}

extension LabEngineTests {
    @Test func homeOnlySessionsLeaveTheWorkspaceAlone() async throws {
        defer { root.cleanup() }
        var settings = Self.settings
        settings.includeWorkspace = false
        let session = try #require(try await send(.start(settings)).session)
        #expect(session.roots == [.home])
        try put("workspace", "repos/app/README", "changed\n")
        try put("home", ".zshrc", "changed\n")
        _ = try await send(.rewind(to: 0))
        #expect(text("workspace", "repos/app/README") == "changed\n")
        #expect(text("home", ".zshrc") == "export PATH=/bin\n")
    }
}

extension LabEngineTests {
    @Test func touchedButUnchangedFilesAreNotChanges() async throws {
        defer { root.cleanup() }
        _ = try await send(.start(Self.settings))
        // sv copies the dotfiles in again at a session start: same bytes, new time.
        let later = Date(timeIntervalSinceNow: 3600)
        try FileManager.default.setAttributes([.modificationDate: later], ofItemAtPath: home + "/.zshrc")
        #expect(try await send(.checkpoint(reason: .interval, label: nil, onlyIfChanged: true)).checkpoint == nil)
        #expect(try #require(try await send(.compare(from: 0, to: nil)).comparison).changes.isEmpty)
        try put("home", ".zshrc", "export PATH=/usr\n") // same size, other bytes
        let taken = try #require(try await send(.checkpoint(reason: .interval, label: nil, onlyIfChanged: true)).checkpoint)
        #expect(taken.changed == 1)
    }
}
