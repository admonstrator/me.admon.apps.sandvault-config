import Foundation
import SandvaultCore
import Testing
@testable import SandvaultAppModel

@Suite struct FileActivitySummaryTests {
    static let environment = SandvaultEnvironment(hostUser: "alice", hostHome: "/Users/alice")
    static let start = Date(timeIntervalSince1970: 1_800_000_000)
    static let shop = "/Users/Shared/sv-alice/repos/shop"

    static func event(
        _ kind: FileActivityEvent.Kind, _ path: String, process: String = "claude", at offset: Double = 0, forWriting: Bool = false,
        modified: Bool = false, arguments: [String] = [], destination: String? = nil
    ) -> FileActivityEvent {
        FileActivityEvent(
            timestamp: start.addingTimeInterval(offset), kind: kind, path: path, destination: destination, pid: 42, process: process,
            forWriting: forWriting, modified: modified, arguments: arguments
        )
    }

    @Test func tilesCountDistinctFilesAndCreatedFilesAreNotAlsoChanged() {
        let events = [
            Self.event(.open, "\(Self.shop)/package.json"),
            Self.event(.open, "\(Self.shop)/package.json", at: 70),
            Self.event(.open, "\(Self.shop)/src/cart.ts", forWriting: true),
            Self.event(.close, "\(Self.shop)/src/cart.ts", modified: true),
            Self.event(.close, "\(Self.shop)/src/api.ts"),
            Self.event(.create, "\(Self.shop)/src/cart.test.ts"),
            Self.event(.write, "\(Self.shop)/src/cart.test.ts"),
            Self.event(.delete, "\(Self.shop)/.env.local"),
            Self.event(.exec, "/usr/bin/git", arguments: ["git", "status"]),
            Self.event(.exec, "/usr/bin/git", arguments: ["git", "diff"]),
        ]
        let report = ActivityReport.make(events, environment: Self.environment)
        #expect(report.tiles == ActivityTiles(read: 1, changed: 1, created: 1, deleted: 1, programs: 1))
    }

    @Test func sentencesPerKindAndFolderWithBulkFoldersFolded() throws {
        var events = (0..<2341).map { index in
            Self.event(.create, "\(Self.shop)/node_modules/pkg\(index % 40)/file\(index).js", process: "node", at: Double(index) / 100)
        }
        events.append(Self.event(.close, "\(Self.shop)/package-lock.json", process: "node", at: 30, modified: true))
        events += ["cart.ts", "checkout.ts", "api.ts", "index.ts"].map { Self.event(.write, "\(Self.shop)/src/\($0)", at: 5) }
        events += (0..<63).map { Self.event(.open, "\(Self.shop)/lib/f\($0).ts", at: 3) }
        events.append(Self.event(.open, "/Users/sandvault-alice/.ssh/config", at: 1))
        events += [
            Self.event(.exec, "/usr/bin/git", at: 2, arguments: ["git", "status"]),
            Self.event(.exec, "/usr/bin/git", at: 2, arguments: ["git", "diff", "--stat", "HEAD"]),
            Self.event(.exec, "/usr/bin/git", at: 2, arguments: ["git", "status"]),
            Self.event(.exec, "/opt/homebrew/bin/node", at: 2, arguments: ["node", "test.js"]),
        ]
        let report = ActivityReport.make(events, environment: Self.environment)

        // The group with a sensitive place comes first, and inside it the sensitive line.
        #expect(report.groups.map(\.process) == ["claude", "node"])
        let claude = report.groups[0]
        #expect(claude.sensitive)
        let ssh = claude.lines[0]
        #expect(ssh.sentence == "Read your SSH keys and settings")
        #expect(ssh.detail == "~sandvault-alice/.ssh/config")
        #expect(ssh.sensitive?.kind == .ssh)

        let changed = try #require(claude.lines.first { $0.action == .change })
        #expect(changed.sentence == "Changed 4 files in src")
        #expect(changed.detail == "cart.ts, checkout.ts, api.ts, index.ts")
        #expect(!changed.folded)

        let read = try #require(claude.lines.first { $0.action == .read && $0.sensitive == nil })
        #expect(read.sentence == "Read 63 files in lib")
        #expect(read.folded && read.detail == "\(Self.shop)/lib")
        #expect(read.folder == "\(Self.shop)/lib")

        let run = try #require(claude.lines.first { $0.action == .run })
        #expect(run.sentence == "Started git 3 times and node")
        #expect(run.detail == "git status, git diff --stat, node test.js")

        let node = report.groups[1]
        let created = try #require(node.lines.first { $0.action == .create })
        #expect(created.sentence == "Created 2,341 files in node_modules")
        #expect(created.folded && created.count == 2341 && created.files.count == ActivityReport.filesPerLine)
        #expect(created.folder == "\(Self.shop)/node_modules")
        #expect(node.folder == "\(Self.shop)/node_modules")
        let lock = try #require(node.lines.first { $0.action == .change })
        #expect(lock.sentence == "Changed package-lock.json")
        #expect(lock.detail == "\(Self.shop)/package-lock.json")
    }

    @Test func sensitivePlaces() {
        func kind(_ path: String, hostHome: Bool = true) -> SensitivePlace.Kind? {
            SensitivePlace.classify(path, environment: Self.environment, includeHostHome: hostHome)?.kind
        }
        #expect(kind("/Users/alice/.ssh/id_ed25519") == .ssh)
        #expect(kind("/Users/sandvault-alice/.ssh") == .ssh)
        #expect(kind("/Users/alice/Library/Keychains/login.keychain-db") == .keychain)
        #expect(kind("/Library/Keychains/System.keychain") == .keychain)
        #expect(kind("/Users/sandvault-alice/.aws/credentials") == .cloudCredentials)
        #expect(kind("/Users/sandvault-alice/.config/gcloud/application_default_credentials.json") == .cloudCredentials)
        #expect(kind("/Users/sandvault-alice/.docker/config.json") == .cloudCredentials)
        #expect(kind("/Users/sandvault-alice/.docker/run.sock") == nil)
        #expect(kind("/Users/sandvault-alice/.npmrc") == .cloudCredentials)
        #expect(kind("/Users/sandvault-alice/.gnupg/pubring.kbx") == .gnupg)
        #expect(kind("/Users/sandvault-alice/Library/Application Support/Google/Chrome/Default/Cookies") == .browserProfile)
        #expect(kind("/Users/sandvault-alice/Library/Safari/History.db") == .browserProfile)
        #expect(kind("\(Self.shop)/.env") == .envFile)
        #expect(kind("\(Self.shop)/.env.production") == .envFile)
        #expect(kind("\(Self.shop)/.env.example") == nil)
        #expect(kind("/Users/bob/Documents/a.txt") == .otherHome)
        #expect(kind("/Users/alice/Documents/a.txt") == .otherHome)
        #expect(kind("/Users/alice/Documents/a.txt", hostHome: false) == nil)
        #expect(kind("/Users/Shared/sv-alice/repos/shop/a.txt") == nil)
        #expect(kind("/Users/sandvault-alice/.zshrc") == nil)
        #expect(SensitivePlace.classify("/Users/bob", environment: Self.environment)?.title == "the home folder of bob")
    }

    @Test func pathsWithTilde() {
        #expect(PathDisplay.short("/Users/alice/Documents/Notes", Self.environment) == "~/Documents/Notes")
        #expect(PathDisplay.short("/Users/alice", Self.environment) == "~")
        #expect(PathDisplay.short("/Users/alicex/a", Self.environment) == "/Users/alicex/a")
        #expect(PathDisplay.short("/Users/sandvault-alice/.zshrc", Self.environment) == "~sandvault-alice/.zshrc")
        #expect(ActivityReport.anchor(of: "/a/node_modules/x/y.js") == "/a/node_modules")
        #expect(ActivityReport.anchor(of: "/a/node_modules") == "/a")
        #expect(ActivityReport.anchor(of: "/a/b/c.txt") == "/a/b")
    }

    @Test func everythingInPlainWords() {
        let lines = [
            Self.event(.open, "/Users/alice/a.txt", forWriting: true),
            Self.event(.open, "/Users/alice/a.txt"),
            Self.event(.close, "/Users/alice/a.txt", modified: true),
            Self.event(.close, "/Users/alice/a.txt"),
            Self.event(.create, "/tmp/x"),
            Self.event(.write, "/tmp/x"),
            Self.event(.rename, "/tmp/x", destination: "/tmp/y"),
            Self.event(.rename, "/tmp/x", destination: "/var/y"),
            Self.event(.delete, "/tmp/y"),
            Self.event(.exec, "/usr/bin/git", arguments: ["git", "diff", "--stat"]),
        ].map { ActivityEventLine($0, environment: Self.environment) }
        #expect(lines.map(\.text) == [
            "Opened for writing", "Opened for reading", "Closed, changed", "Closed", "Created", "Wrote to", "Renamed", "Moved", "Deleted", "Started",
        ])
        #expect(lines[0].path == "~/a.txt" && lines[0].sensitive)
        #expect(lines[6].path == "/tmp/x → /tmp/y")
        #expect(lines[9].path == "git diff --stat")
        #expect(lines[3].action == nil && lines[2].action == .change)
    }
}

@MainActor
@Suite struct FileActivityModelTests {
    @Test func startRecordsSavesTheSettingAndStopKeepsTheEvents() async throws {
        let world = TestWorld()
        defer { world.cleanUp() }
        let old = FileActivitySummaryTests.event(.open, "/Users/Shared/sv-alice/a.txt")
        world.activity.storedEvents.set([old])
        let model = world.model()
        let files = model.files

        await files.launch()
        #expect(files.state == .off)
        #expect(files.events == [old])
        #expect(world.activity.continuations.get().isEmpty)

        await files.start()
        #expect(try world.store.load().activity.enabled)
        #expect(files.state == .recording(since: world.clock.current.get()))
        #expect(files.bannerTitle.hasPrefix("Recording since "))
        let feed = try #require(world.activity.latest)
        let new = FileActivitySummaryTests.event(.create, "/Users/Shared/sv-alice/b.txt")
        feed.yield(new)
        #expect(await eventually { files.events.count == 2 })
        #expect(files.report.tiles.created == 1)

        await files.stop()
        #expect(files.state == .off)
        #expect(try !world.store.load().activity.enabled)
        #expect(files.events.count == 2)
        #expect(await eventually { world.activity.terminated.get() == 1 })
    }

    @Test func launchRecordsWhenSwitchedOnEarlierAndFailuresWaitForTheUser() async throws {
        let world = TestWorld()
        defer { world.cleanUp() }
        try world.store.save(AppConfig(activity: ActivityRecordingSettings(enabled: true, hideSystemFiles: false)))
        let files = world.model().files
        await files.launch()
        #expect(files.isRecording)
        #expect(world.activity.settingsSeen.get().map(\.hideSystemFiles) == [false])

        try #require(world.activity.latest).finish(throwing: ActivityRecorderFailure.needsFullDiskAccess)
        #expect(await eventually { files.state == .needsFullDiskAccess })
        // No restart on its own.
        try? await Task.sleep(nanoseconds: 20_000_000)
        #expect(world.activity.continuations.get().count == 1)
        #expect(try world.store.load().activity.enabled)

        await files.start()
        #expect(files.isRecording && world.activity.continuations.get().count == 2)
        try #require(world.activity.latest).finish(throwing: ActivityRecorderFailure.needsHelper)
        #expect(await eventually { files.state == .needsHelper })
    }

    @Test func failureStates() {
        #expect(FileActivityModel.state(after: nil) == .failed("The recorder stopped."))
        #expect(FileActivityModel.state(after: ActivityRecorderFailure.unavailable("eslogger missing")) == .failed("Recording is unavailable: eslogger missing"))
        #expect(FileActivityModel.state(after: SandvaultError.commandFailed("svctl-helper", 1, "boom")) != .off)
    }

    @Test func changingASettingRestartsARunningRecorder() async throws {
        let world = TestWorld()
        defer { world.cleanUp() }
        let model = world.model()
        await model.files.start()
        await model.recording.setOpenAndClose(true)
        #expect(try world.store.load().activity.openAndClose)
        #expect(world.activity.settingsSeen.get().map(\.openAndClose) == [false, true])
        #expect(model.files.isRecording)
        #expect(await eventually { world.activity.terminated.get() == 1 })

        await model.files.stop()
        await model.recording.setHideSystemFiles(false)
        #expect(world.activity.settingsSeen.get().count == 2)
        #expect(try !world.store.load().activity.hideSystemFiles)
    }

    @Test func installingTheHelperFromTheBannerStartsRecording() async throws {
        let world = TestWorld()
        defer { world.cleanUp() }
        let model = world.model()
        await model.installHelperForRecording()
        #expect(world.helperSetup.calls.get().count == 1)
        #expect(model.files.isRecording)
    }
}
