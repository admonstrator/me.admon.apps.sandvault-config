import Foundation
import SandvaultCore
import SandvaultObserve
import Testing
@testable import SandvaultAppModel

/// Process details (D51): the timeline, tiles and warnings of one process.
@Suite struct ProcessDetailTests {
    static let environment = SandvaultEnvironment(hostUser: "alice", hostHome: "/Users/alice")
    static let t0 = Date(timeIntervalSince1970: 1_800_000_000)
    static let shop = "/Users/Shared/sv-alice/shop"
    static let home = "/Users/sandvault-alice"

    static func event(
        _ kind: FileActivityEvent.Kind, _ path: String, pid: Int32 = 4121, ppid: Int32 = 3902, start: Double = 0, process: String = "claude",
        at offset: Double, forWriting: Bool = false, modified: Bool = false, arguments: [String] = [], cwd: String? = nil
    ) -> FileActivityEvent {
        FileActivityEvent(
            timestamp: t0.addingTimeInterval(offset), kind: kind, path: path, pid: pid, process: process, forWriting: forWriting,
            modified: modified, arguments: arguments, ppid: ppid, processStart: t0.addingTimeInterval(start), cwd: cwd
        )
    }

    static func web(_ host: String, pid: Int32 = 4121, at offset: Double, http: [HTTPSummary] = [], decision: ConnectionDecision = .allowed,
                    inspected: Bool = false) -> ConnectionRecord {
        ConnectionRecord(
            timestamp: t0.addingTimeInterval(offset), kind: .transparentTLS, host: host, port: 443, decision: decision, pid: pid,
            process: "claude", bytesIn: 2000, bytesOut: 500, inspected: inspected, http: http
        )
    }

    static var events: [FileActivityEvent] {
        var events: [FileActivityEvent] = [
            event(.exec, "\(home)/.local/bin/claude", process: "zsh", at: 0, arguments: ["claude"], cwd: shop),
            event(.open, "\(home)/.ssh/config", at: 7),
            event(.create, "\(shop)/src/cart.test.ts", at: 9),
            event(.write, "\(shop)/src/cart.test.ts", at: 9.5),
            event(.create, "\(home)/Library/LaunchAgents/com.example.updater.plist", at: 11),
        ]
        for index in 0..<20 {
            let offset: Double = 5 + Double(index) / 100
            events.append(event(.open, "\(shop)/src/f\(index).ts", at: offset))
        }
        events.append(event(.open, "\(shop)/src/f3.ts", at: 6))
        for index in 0..<3 {
            let pid: Int32 = 4200 + Int32(index)
            let offset: Double = 20 + Double(index)
            let command = index == 1 ? "diff" : "status"
            events.append(event(.exec, "/usr/bin/git", pid: pid, ppid: 4121, start: offset, process: "claude", at: offset, arguments: ["git", command]))
        }
        events.append(event(.exec, "/usr/bin/security", pid: 4210, ppid: 4121, start: 30, process: "claude", at: 30,
                            arguments: ["security", "find-generic-password", "-s", "x"]))
        events.append(event(.open, "\(shop)/.git/HEAD", pid: 4200, ppid: 4121, start: 20, process: "git", at: 20.5))
        return events
    }

    static var records: [ConnectionRecord] {
        let messages = (0..<3).map { index in
            HTTPSummary(method: "POST", url: "https://api.anthropic.com/v1/messages?beta=true", status: 200,
                        startedAt: t0.addingTimeInterval(3 + Double(index)), durationMs: 900, responseBytes: 18_400)
        }
        return [
            web("api.anthropic.com", at: 2, http: messages, inspected: true),
            web("sentry.io", at: 40),
            web("sentry.io", at: 41),
            web("evil.example", at: 42, decision: .askedDenied),
            ConnectionRecord(timestamp: t0.addingTimeInterval(1), kind: .dns, host: "api.anthropic.com", decision: .allowed, pid: 4121,
                             dnsAnswers: ["160.79.104.10"]),
        ]
    }

    static func detail(includeChildren: Bool = true, grouped: Bool = true) throws -> ProcessDetail {
        let tracer = ProcessTracer(snapshot: nil, events: events, connections: records)
        let trace = try #require(tracer.trace(ProcessReference(pid: 4121), includeChildren: includeChildren))
        return ProcessDetail.make(trace, environment: environment, grouped: grouped)
    }

    @Test func groupsAlikeEventsIntoOneRow() throws {
        let detail = try Self.detail()
        let titles = detail.rows.map(\.title)
        #expect(titles.first == "Started claude in ~/Shared/sv-alice/shop" || titles.first == "Started claude in /Users/Shared/sv-alice/shop")
        #expect(titles.contains("Read 20 files in src"))
        #expect(titles.contains("Read your SSH keys and settings"))
        // Created, then written: only Created.
        #expect(titles.contains("Created cart.test.ts") && !titles.contains("Changed cart.test.ts"))
        #expect(titles.contains("Started git 3 times"))
        #expect(titles.contains("Started security"))
        #expect(titles.contains("Looked up api.anthropic.com"))
        #expect(titles.contains("Blocked evil.example:443"))
        #expect(titles.contains("2 connections to sentry.io"))

        let messages = try #require(detail.rows.first { $0.title == "POST api.anthropic.com/v1/messages" })
        #expect(messages.count == 3 && messages.status == "200")
        #expect(messages.detail.hasPrefix("3 requests"))

        let git = try #require(detail.rows.first { $0.kind == .launched && $0.title.hasPrefix("Started git") })
        #expect(git.detail == "git status, git diff")
        #expect(git.opens?.pid == 4202)
        // git's own read shows under claude, with git as the process that did it.
        let head = try #require(detail.rows.first { $0.title == "Read HEAD" })
        #expect(head.processName == "git" && head.pid == 4200)
    }

    @Test func everyEventWithoutGrouping() throws {
        let detail = try Self.detail(grouped: false)
        #expect(detail.rows.filter { $0.kind == .web && $0.host == "api.anthropic.com" }.count == 3)
        #expect(detail.rows.filter { $0.kind == .launched }.count == 4)
        // A file read twice in a row is two rows, never a merged one.
        #expect(detail.rows.filter { $0.title == "Read f3.ts" }.count == 2)
    }

    @Test func tilesAndFilters() throws {
        let detail = try Self.detail()
        let counts = Dictionary(uniqueKeysWithValues: detail.tiles.map { ($0.filter, $0.count) })
        #expect(counts[.web] == 5)  // 3 inspected requests, 2 encrypted connections
        #expect(counts[.network] == 3)  // api.anthropic.com, sentry.io, evil.example
        #expect(counts[.files] == 24)
        #expect(counts[.programs] == 4)
        #expect(detail.encryptedConnections == 2)

        #expect(detail.rows(.files).allSatisfy { $0.kind == .file })
        #expect(detail.rows(.programs).allSatisfy { $0.kind == .started || $0.kind == .launched })
        #expect(detail.rows(.network).contains { $0.kind == .dns })
        #expect(detail.rows(.web).allSatisfy { $0.kind == .web })
        // Newest first; the search matches title, detail and process.
        let all = detail.rows(.all)
        #expect(all.first.map { $0.time >= all.last!.time } == true)
        #expect(detail.rows(.all, matching: "SENTRY").count == 1)
        #expect(detail.rows(.all, matching: "git").contains { $0.processName == "git" })
    }

    @Test func warningsForKeysLoginItemsAndTheKeychain() throws {
        let detail = try Self.detail()
        let kinds = Set(detail.warnings.compactMap { $0.sensitive?.kind })
        #expect(kinds == [.ssh, .loginItem, .keychain])
        #expect(detail.warningTitle == "3 things need a look")
        let login = try #require(detail.warnings.first { $0.sensitive?.kind == .loginItem })
        #expect(login.title == "Created a login item")
    }

    @Test func withoutChildrenTheirEventsStayOutButTheirStartsStay() throws {
        let detail = try Self.detail(includeChildren: false)
        #expect(!detail.rows.contains { $0.processName == "git" && $0.kind == .file })
        #expect(detail.rows.contains { $0.title == "Started git 3 times" })
    }

    @Test func headerTexts() throws {
        let detail = try Self.detail()
        #expect(detail.chain.map(\.name) == ["claude"])
        #expect(detail.startedBy == "Started by pid 3902")
        #expect(detail.signatureText == "Signature unknown")
        #expect(detail.state(now: Self.t0.addingTimeInterval(100)) == "Ended · last seen \(Format.time(Self.t0.addingTimeInterval(42)))")
        #expect(detail.children.map(\.name) == ["git", "git", "git", "security"])

        let tracer = ProcessTracer(snapshot: nil, events: Self.events, connections: [])
        let git = try #require(tracer.trace(ProcessReference(pid: 4201)))
        #expect(ProcessDetail.make(git, environment: Self.environment).startedBy == "Started by claude")
    }

    @Test func webRowsCarryTheProgramsPid() {
        let rows = WebRequestRow.rows(Self.records)
        #expect(rows.allSatisfy { $0.pid == 4121 })
        let first = rows.last
        #expect(first?.processReference == ProcessReference(pid: 4121, at: first?.time))
    }

    @MainActor @Test func modelPutsTogetherWhatTheOtherModelsHold() async throws {
        let world = TestWorld()
        defer { world.cleanUp() }
        world.activity.storedEvents.set(Self.events)
        world.netd.queue.set([.client(FakeNetdClient(recent: Self.records))])
        let model = world.model()
        await model.files.launch()
        model.netd.start()
        #expect(await eventually { model.netd.isConnected && model.netd.records.count == Self.records.count })

        let detail = try #require(model.processDetail.detail(for: ProcessReference(pid: 4121)))
        #expect(detail.rows.contains { $0.title == "Read your SSH keys and settings" })
        #expect(detail.rows.contains { $0.title == "POST api.anthropic.com/v1/messages" })
        #expect(model.processDetail.reference(forProgram: "git")?.pid == 4200)
        #expect(model.processDetail.detail(for: ProcessReference(pid: 9)) == nil)

        let hints = model.processDetail.hints(for: detail)
        #expect(hints.contains { $0.contains("Files & programs is not recording") })
        #expect(hints.contains { $0.contains("Look inside HTTPS") })

        model.processDetail.show(ProcessReference(pid: 4121))
        #expect(model.processDetail.presented?.pid == 4121)
        model.netd.stop()
    }
}
