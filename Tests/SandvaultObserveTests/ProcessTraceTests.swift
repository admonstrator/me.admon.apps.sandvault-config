import Foundation
import SandvaultCore
import Testing
@testable import SandvaultObserve

/// Process details (D51): processes from file events, connection records and the process list, linked by pid,
/// parent and start time.
@Suite struct ProcessTraceTests {
    static let t0 = Date(timeIntervalSince1970: 1_800_000_000)
    static let claudeStart = t0
    static let nodeStart = t0.addingTimeInterval(60)
    static let shStart = t0.addingTimeInterval(90)

    static func event(
        _ kind: FileActivityEvent.Kind, _ path: String, pid: Int32, ppid: Int32?, start: Date?, process: String, at offset: Double,
        arguments: [String] = [], cwd: String? = nil, signature: AskProgram.Signature? = nil
    ) -> FileActivityEvent {
        FileActivityEvent(
            timestamp: t0.addingTimeInterval(offset), kind: kind, path: path, pid: pid, process: process, executable: "/bin/\(process)",
            arguments: arguments, ppid: ppid, processStart: start, signature: signature, cwd: cwd
        )
    }

    /// claude (4121) starts node (4180, fork then exec), node starts sh (4195), sh reads ~/.npmrc.
    static var events: [FileActivityEvent] {
        [
            event(.exec, "/Users/sandvault-alice/.local/bin/claude", pid: 4121, ppid: 3902, start: claudeStart, process: "zsh", at: 0,
                  arguments: ["claude"], cwd: "/Users/Shared/sv-alice/shop", signature: .developer(team: nil)),
            event(.open, "/Users/Shared/sv-alice/shop/package.json", pid: 4121, ppid: 3902, start: claudeStart, process: "claude", at: 5),
            event(.exec, "/opt/homebrew/bin/node", pid: 4180, ppid: 4121, start: nodeStart, process: "claude", at: 60,
                  arguments: ["node", "/opt/homebrew/bin/npm", "install"]),
            event(.create, "/Users/Shared/sv-alice/shop/node_modules/a.js", pid: 4180, ppid: 4121, start: nodeStart, process: "node", at: 70),
            event(.exec, "/bin/sh", pid: 4195, ppid: 4180, start: shStart, process: "node", at: 90,
                  arguments: ["sh", "-c", "node postinstall.js"], signature: .apple),
            event(.open, "/Users/sandvault-alice/.npmrc", pid: 4195, ppid: 4180, start: shStart, process: "sh", at: 91),
        ]
    }

    static func connection(_ host: String, pid: Int32?, at offset: Double, decision: ConnectionDecision = .allowed,
                           kind: ConnectionKind = .transparentTLS) -> ConnectionRecord {
        ConnectionRecord(timestamp: t0.addingTimeInterval(offset), kind: kind, host: host, port: 443, decision: decision, pid: pid, process: "x")
    }

    @Test func buildsTheChainAndTheChildrenFromParentPids() throws {
        let tracer = ProcessTracer(snapshot: nil, events: Self.events, connections: [])
        let trace = try #require(tracer.trace(ProcessReference(pid: 4195)))
        #expect(trace.process.name == "sh")
        #expect(trace.process.command == "sh -c node postinstall.js")
        #expect(trace.process.signature == .apple)
        #expect(trace.ancestors.map(\.name) == ["claude", "node"])
        // claude's parent zsh (3902) is not known: the chain starts at claude, with the pid kept.
        #expect(trace.ancestors.first?.ppid == 3902 && trace.ancestors.first?.parentID == nil)

        let claude = try #require(tracer.trace(ProcessReference(pid: 4121)))
        #expect(claude.process.cwd == "/Users/Shared/sv-alice/shop")
        #expect(claude.process.signature == .developer(team: nil))
        #expect(claude.children.map(\.name) == ["node"])
        #expect(claude.descendants.map(\.name) == ["node", "sh"])
        #expect(claude.items.count == 6)
        // Items of the started programs keep the process that did them.
        #expect(claude.items.last.map { $0.processID == claude.descendants[1].id } == true)
    }

    @Test func leavesTheChildrenOutWhenAsked() throws {
        let tracer = ProcessTracer(snapshot: nil, events: Self.events, connections: [])
        let trace = try #require(tracer.trace(ProcessReference(pid: 4121), includeChildren: false))
        #expect(trace.items.count == 2)
        #expect(trace.children.map(\.name) == ["node"])
    }

    @Test func connectionsGoToTheProcessWithTheirPid() throws {
        let records = [
            Self.connection("api.anthropic.com", pid: 4121, at: 3),
            Self.connection("registry.npmjs.org", pid: 4180, at: 65),
            Self.connection("api.segment.io", pid: 4195, at: 92, decision: .denied),
            Self.connection("no-owner.example", pid: nil, at: 92),
        ]
        let ask = AskRequest(host: "example-updates.net", port: 80, kind: .transparentHTTP, pid: 4195, process: "curl",
                             createdAt: Self.t0.addingTimeInterval(93), expiresAt: Self.t0.addingTimeInterval(153))
        let tracer = ProcessTracer(snapshot: nil, events: Self.events, connections: records, asks: [ask])
        let sh = try #require(tracer.trace(ProcessReference(pid: 4195)))
        let hosts = sh.items.compactMap { item -> String? in
            switch item.content {
            case .connection(let record): record.host
            case .ask(let ask): ask.host
            default: nil
            }
        }
        #expect(hosts == ["api.segment.io", "example-updates.net"])
        let claude = try #require(tracer.trace(ProcessReference(pid: 4121)))
        #expect(claude.items.count == 6 + 4)
    }

    @Test func aReusedPidIsTwoProcesses() throws {
        let first = Self.event(.open, "/tmp/a", pid: 500, ppid: 4121, start: Self.t0, process: "git", at: 1)
        let second = Self.event(.open, "/tmp/b", pid: 500, ppid: 4121, start: Self.t0.addingTimeInterval(100), process: "python3", at: 101)
        let records = [Self.connection("a.example", pid: 500, at: 2), Self.connection("b.example", pid: 500, at: 102)]
        let tracer = ProcessTracer(snapshot: nil, events: [first, second], connections: records)

        let early = try #require(tracer.trace(ProcessReference(pid: 500, at: Self.t0.addingTimeInterval(50))))
        #expect(early.process.name == "git")
        #expect(early.items.count == 2)
        let late = try #require(tracer.trace(ProcessReference(pid: 500)))
        #expect(late.process.name == "python3")
        #expect(late.items.compactMap { if case .connection(let r) = $0.content { r.host } else { nil } } == ["b.example"])
    }

    @Test func theProcessListAddsRunningProcessesAndMatchesRecordedOnes() throws {
        let takenAt = Self.t0.addingTimeInterval(600)
        let snapshot = ProcessSnapshot(
            processes: [
                // claude: started 600 s before the snapshot, i.e. at t0: the recorded one.
                SandboxProcess(pid: 4121, ppid: 3902, user: "sandvault-alice", elapsedSeconds: 600, command: "claude", sessionID: "S1"),
                SandboxProcess(pid: 3902, ppid: 1, user: "sandvault-alice", elapsedSeconds: 700, command: "-zsh", sessionID: "S1"),
                // Not in any recording.
                SandboxProcess(pid: 4300, ppid: 4121, user: "sandvault-alice", elapsedSeconds: 10, command: "/usr/bin/git status"),
            ],
            sessions: [], helpers: [], environmentReadable: true, takenAt: takenAt
        )
        let tracer = ProcessTracer(snapshot: snapshot, events: Self.events, connections: [])
        let claude = try #require(tracer.trace(ProcessReference(pid: 4121)))
        #expect(claude.process.running && claude.process.sessionID == "S1")
        #expect(claude.process.start == Self.claudeStart)
        #expect(claude.ancestors.map(\.name) == ["zsh"])
        #expect(claude.children.map(\.name) == ["node", "git"])
        let git = try #require(claude.children.last)
        #expect(git.running && git.command == "/usr/bin/git status")
        #expect(git.start == takenAt.addingTimeInterval(-10))
        // node and sh are not in the list: they ended.
        #expect(claude.children.first?.running == false)
    }

    @Test func eventsStoredBeforeD51StillFindTheirProcess() throws {
        var old = Self.event(.open, "/tmp/x", pid: 777, ppid: nil, start: nil, process: "python3", at: 5)
        old.ppid = nil
        let tracer = ProcessTracer(snapshot: nil, events: [old], connections: [Self.connection("pypi.org", pid: 777, at: 6)])
        let trace = try #require(tracer.trace(ProcessReference(pid: 777)))
        #expect(trace.process.name == "python3" && trace.process.start == nil)
        #expect(trace.items.count == 2)
        #expect(trace.ancestors.isEmpty)
        #expect(tracer.trace(ProcessReference(pid: 778)) == nil)
    }

    @Test func parentLoopsAndSelfParentsEndTheChain() throws {
        // Two processes naming each other as parent (pid reuse gone wrong) must not hang or repeat.
        let a = Self.event(.open, "/tmp/a", pid: 10, ppid: 11, start: Self.t0, process: "a", at: 1)
        let b = Self.event(.open, "/tmp/b", pid: 11, ppid: 10, start: Self.t0, process: "b", at: 1)
        let c = Self.event(.open, "/tmp/c", pid: 12, ppid: 12, start: Self.t0, process: "c", at: 1)
        let tracer = ProcessTracer(snapshot: nil, events: [a, b, c], connections: [])
        let trace = try #require(tracer.trace(ProcessReference(pid: 10)))
        #expect(trace.ancestors.count <= 1)
        #expect(trace.descendants.count <= 1)
        #expect(tracer.trace(ProcessReference(pid: 12))?.ancestors.isEmpty == true)
    }

    @Test func traceIsJSON() throws {
        let tracer = ProcessTracer(snapshot: nil, events: Self.events, connections: [Self.connection("x.example", pid: 4121, at: 1)])
        let trace = try #require(tracer.trace(ProcessReference(pid: 4121)))
        let data = try JSONCoding.encoder.encode(trace)
        #expect(try JSONCoding.decoder.decode(ProcessTrace.self, from: data) == trace)
    }
}
