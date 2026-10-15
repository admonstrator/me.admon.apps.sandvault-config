import Foundation
import Testing
@testable import SandvaultCore

@Suite struct LabTests {
    static func file(_ size: Int64, _ mtime: Int64) -> LabEntry { LabEntry(kind: .file, size: size, mtime: mtime) }
    static func key(_ path: String) -> String { LabPath(root: .home, path: path).key }

    @Test func diffIgnoresDirectoryTimesButNotModes() {
        let old: LabManifest = [Self.key("d"): LabEntry(kind: .directory, mode: 0o755), Self.key("a"): Self.file(1, 1)]
        var new = old
        new[Self.key("d")] = LabEntry(kind: .directory, mode: 0o755, mtime: 99)
        #expect(LabDiff.changes(from: old, to: new).isEmpty)
        new[Self.key("d")] = LabEntry(kind: .directory, mode: 0o777)
        new[Self.key("a")] = nil
        new[Self.key("b")] = Self.file(5, 2)
        let changes = LabDiff.changes(from: old, to: new)
        #expect(changes.map(\.kind) == [.deleted, .created, .changed])
        #expect(changes.map(\.path.path) == ["a", "b", "d"])
        #expect(changes[2].attributesOnly)
        #expect(LabDiff.apply(changes, to: old) == new)
    }

    @Test func composeKeepsTheOuterStates() {
        let a = LabPath(root: .home, path: "a")
        let b = LabPath(root: .workspace, path: "b")
        let first = [
            LabChange(path: a, kind: .created, old: nil, new: Self.file(1, 1), secret: "contains a key"),
            LabChange(path: b, kind: .changed, old: Self.file(1, 1), new: Self.file(2, 2)),
        ]
        let second = [
            LabChange(path: a, kind: .deleted, old: Self.file(1, 1), new: nil),
            LabChange(path: b, kind: .changed, old: Self.file(2, 2), new: Self.file(1, 1)),
        ]
        #expect(LabDiff.compose(first, second).isEmpty)
        let third = [LabChange(path: a, kind: .changed, old: Self.file(1, 1), new: Self.file(3, 3))]
        let composed = LabDiff.compose(first, third)
        #expect(composed.map(\.kind) == [.created, .changed])
        #expect(composed[0].new == Self.file(3, 3) && composed[0].secret == "contains a key")
        #expect(LabDiff.bytes(of: composed) == (added: 5, removed: 1))
    }

    @Test func findingsNameKeysLoginItemsAndShellFiles() {
        func created(_ root: LabRoot, _ path: String, secret: String? = nil) -> LabChange {
            LabChange(path: LabPath(root: root, path: path), kind: .created, old: nil, new: Self.file(10, 1), secret: secret)
        }
        let findings = LabFindings.findings(in: [
            created(.home, ".ssh/id_rsa"), created(.home, ".ssh/id_rsa.pub"), created(.home, ".zshrc"),
            created(.home, "Library/LaunchAgents/com.example.agent.plist"), created(.home, "Library/Keychains/login.keychain-db"),
            created(.home, ".aws/credentials"), created(.workspace, "repos/x/config.json", secret: "contains what looks like a GitHub token (line 3)"),
            created(.home, "notes.txt"), created(.workspace, "repos/x/.env"),
            LabChange(path: LabPath(root: .home, path: ".bashrc"), kind: .deleted, old: Self.file(1, 1), new: nil),
        ])
        let byPath = Dictionary(uniqueKeysWithValues: findings.map { ($0.path.display, $0.kind) })
        #expect(byPath == [
            "~/.ssh/id_rsa": .key, "~/.zshrc": .shellStartup, "~/Library/LaunchAgents/com.example.agent.plist": .loginItem,
            "~/Library/Keychains/login.keychain-db": .keychain, "~/.aws/credentials": .credential,
            "Workspace/repos/x/config.json": .credential, "Workspace/repos/x/.env": .credential,
        ])
    }

    @Test func pruningPrefersOldAutomaticCheckpoints() {
        var session = LabSession(startedAt: Date(), settings: LabSettings(maxCheckpoints: 3), roots: [.home])
        let reasons: [LabCheckpoint.Reason] = [.start, .manual, .interval, .program, .interval]
        session.checkpoints = reasons.enumerated().map { index, reason in
            LabCheckpoint(id: index, parent: index == 0 ? nil : index - 1, takenAt: Date(), reason: reason, label: "")
        }
        session.head = 4
        #expect(session.overLimits)
        #expect(session.pruningCandidates() == [2, 3, 1])
        #expect(session.chain(to: 3).map(\.id) == [0, 1, 2, 3])
    }

    @Test func estimateCountsReplacedContentAndAbandonedBranches() {
        var session = LabSession(startedAt: Date(), settings: LabSettings(), roots: [.home])
        session.checkpoints = [
            LabCheckpoint(id: 0, parent: nil, takenAt: Date(), reason: .start, label: "Start"),
            LabCheckpoint(id: 1, parent: 0, takenAt: Date(), reason: .interval, label: "", addedBytes: 100, removedBytes: 10),
            LabCheckpoint(id: 2, parent: 1, takenAt: Date(), reason: .interval, label: "", addedBytes: 50, removedBytes: 20),
        ]
        session.head = 2
        #expect(session.estimatedBytes == 30)
        session.head = 0 // rewound to the start: 1 and 2 are a branch left behind
        #expect(session.estimatedBytes == 180)
    }

    @Test func settingsDecodeWithDefaultsAndValidate() throws {
        let settings = try JSONCoding.decoder.decode(LabSettings.self, from: Data("{\"intervalSeconds\":30}".utf8))
        #expect(settings.intervalSeconds == 30 && settings.excludes == LabSettings.defaultExcludes)
        #expect(throws: SandvaultError.self) { try LabSettings(intervalSeconds: 1).validated() }
        #expect(throws: SandvaultError.self) { try LabSettings(excludes: [LabPath(root: .home, path: "a/../b")]).validated() }
        #expect(try JSONCoding.decoder.decode(AppConfig.self, from: Data("{}".utf8)).lab == LabSettings())
    }

    @Test func requestsRoundTrip() throws {
        let requests: [LabRequest] = [
            .status, .start(LabSettings()), .checkpoint(reason: .program, label: "Started npm", onlyIfChanged: false),
            .compare(from: 0, to: nil), .file(LabPath(root: .workspace, path: "a/b"), at: 3), .rewind(to: 2), .finish(keep: true),
        ]
        for request in requests {
            #expect(try JSONCoding.decoder.decode(LabRequest.self, from: JSONCoding.lineEncoder.encode(request)) == request)
        }
    }

    @Test func programWatchReportsNewProgramsOnce() {
        var watch = LabProgramWatch()
        func process(_ pid: Int32, _ command: String) -> SandboxProcess { SandboxProcess(pid: pid, ppid: 1, user: "sandvault-alice", command: command) }
        #expect(watch.newPrograms(in: [process(1, "-zsh"), process(2, "/usr/local/bin/node server.js")]).isEmpty)
        #expect(watch.newPrograms(in: [process(1, "-zsh"), process(3, "npm install"), process(4, "/bin/ls")]) == ["npm"])
        #expect(watch.newPrograms(in: [process(5, "npm run build"), process(6, "/opt/homebrew/bin/node x.js")]).isEmpty)
        #expect(watch.newPrograms(in: [process(7, "curl https://example.com")]) == ["curl"])
    }

    @Test func autopilotSpacesProgramCheckpointsAndSkipsUnchangedIntervals() {
        let start = Date(timeIntervalSince1970: 1_000)
        var autopilot = LabAutopilot(settings: LabSettings(intervalSeconds: 60), now: start)
        func process(_ pid: Int32, _ command: String) -> SandboxProcess { SandboxProcess(pid: pid, ppid: 1, user: "u", command: command) }
        #expect(autopilot.tick(now: start, processes: [process(1, "zsh")]).isEmpty)
        #expect(autopilot.tick(now: start.addingTimeInterval(5), processes: [process(2, "npm i")])
            == [.checkpoint(reason: .program, label: "Started npm", onlyIfChanged: false)])
        #expect(autopilot.tick(now: start.addingTimeInterval(10), processes: [process(3, "python3 x.py")]).isEmpty)
        #expect(autopilot.tick(now: start.addingTimeInterval(20), processes: [process(4, "curl x")])
            == [.checkpoint(reason: .program, label: "Started python3, curl", onlyIfChanged: false)])
        #expect(autopilot.tick(now: start.addingTimeInterval(81), processes: nil)
            == [.checkpoint(reason: .interval, label: nil, onlyIfChanged: true)])
    }

    @Test func serversAreSummarizedPerHostWithinTheWindow() {
        let base = Date(timeIntervalSince1970: 2_000)
        let records = [
            ConnectionRecord(timestamp: base.addingTimeInterval(-10), kind: .explicitProxy, host: "before.example", decision: .allowed),
            ConnectionRecord(timestamp: base.addingTimeInterval(1), kind: .explicitProxy, host: "api.example", decision: .allowed, process: "node", bytesIn: 5),
            ConnectionRecord(timestamp: base.addingTimeInterval(2), kind: .explicitProxy, host: "api.example", decision: .denied, process: "curl", bytesIn: 7),
            ConnectionRecord(timestamp: base.addingTimeInterval(3), kind: .explicitProxy, host: "cdn.example", decision: .allowed),
        ]
        let servers = LabServer.summarize(records, from: base, to: base.addingTimeInterval(3))
        #expect(servers.map(\.host) == ["api.example"])
        #expect(servers[0].connections == 2 && servers[0].blocked == 1 && servers[0].bytesIn == 12 && servers[0].programs == ["node", "curl"])
        #expect(LabServer.summarize(records, from: base).map(\.host) == ["api.example", "cdn.example"])
    }

    @Test func pathsDisplayAndParse() throws {
        #expect(LabPath(root: .home, path: ".zshrc").display == "~/.zshrc")
        #expect(LabPath(key: "workspace/repos/a") == LabPath(root: .workspace, path: "repos/a"))
        #expect(LabPath(key: "elsewhere/a") == nil)
        for bad in ["", "/etc", "a//b", "a/./b", "../x", "a/.."] {
            #expect(throws: SandvaultError.self) { try LabPath.validate(bad) }
        }
    }
}
