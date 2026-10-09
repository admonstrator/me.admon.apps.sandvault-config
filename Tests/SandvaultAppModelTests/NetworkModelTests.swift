import Foundation
import SandvaultCore
import SandvaultNet
import Testing
@testable import SandvaultAppModel

@MainActor
@Suite struct NetworkModelTests {
    @Test func groupsRecordsByHostNewestFirst() {
        let now = Date(timeIntervalSince1970: 1_800_000_000)
        let records = [
            record("api.github.com", .allowed, at: now.addingTimeInterval(-30), process: "git"),
            record("evil.example", .denied, port: 80, at: now.addingTimeInterval(-20)),
            record("api.github.com", .askedDenied, at: now.addingTimeInterval(-10), process: "node"),
            record("evil.example", .timedOut, at: now.addingTimeInterval(-5)),
        ]
        let groups = HostGroup.group(records)
        #expect(groups.map(\.host) == ["evil.example", "api.github.com"])
        #expect(groups[0].denied == 2)
        #expect(groups[0].allowed == 0)
        #expect(groups[0].ports == [80, 443])
        #expect(groups[0].lastDecision == .timedOut)
        #expect(groups[1].allowed == 1)
        #expect(groups[1].denied == 1)
        #expect(groups[1].processes == ["git", "node"])
        #expect(groups[1].bytesIn == 200)

        #expect(HostGroup.group(records, filter: ConnectionFilter(deniedOnly: false, host: "GITHUB")).map(\.host) == ["api.github.com"])
        #expect(HostGroup.group([records[0]], filter: ConnectionFilter(deniedOnly: true)).isEmpty)
    }

    @Test func quickActionsEditTheConfigAndReloadNetd() async throws {
        let world = TestWorld()
        defer { world.cleanUp() }
        let model = world.model()

        await model.network.allowHost("API.GitHub.com")
        await model.network.allowDomain("objects.githubusercontent.com")
        await model.network.deny("tracker.example")

        let rules = try world.store.load().network.domainRules
        #expect(rules.map(\.pattern) == ["api.github.com", "*.githubusercontent.com", "tracker.example"])
        #expect(rules.map(\.action) == [.allow, .allow, .deny])
        #expect(world.netd.reloads.get() == 3)
        #expect(model.network.message?.title == "Denied tracker.example")
        #expect(model.network.message?.detail == "netd reloaded")

        #expect(model.network.rule(for: "api.github.com")?.pattern == "api.github.com")
        #expect(model.network.rule(for: "raw.githubusercontent.com")?.pattern == "*.githubusercontent.com")
        #expect(model.network.rule(for: "example.org") == nil)
    }

    @Test func anInvalidHostBecomesAWarning() async throws {
        let world = TestWorld()
        defer { world.cleanUp() }
        let model = world.model()
        await model.network.allowHost("bad host!")
        #expect(model.network.message?.kind == .warning)
        #expect(try world.store.load().network.domainRules.isEmpty)
        #expect(world.netd.reloads.get() == 0)
    }

    @Test func hostGroupsFollowTheLiveRecordsAndFilters() async {
        let world = TestWorld()
        defer { world.cleanUp() }
        let model = world.model()
        let now = world.clock.current.get()
        model.netd.handle(.connection(record("a.example", .allowed, at: now)))
        model.netd.handle(.connection(record("b.example", .denied, at: now.addingTimeInterval(1))))
        #expect(model.network.hostGroups.map(\.host) == ["b.example", "a.example"])
        model.network.deniedOnly = true
        #expect(model.network.hostGroups.map(\.host) == ["b.example"])
    }

    @Test func socketsAreReadAndListenersComeFirst() async {
        let world = TestWorld()
        defer { world.cleanUp() }
        world.connections.sockets.set([
            SandboxConnection(pid: 7, process: "node", proto: .tcp, family: .ipv4, localAddress: "10.0.0.2", localPort: 50000, remoteAddress: "140.82.112.3", remotePort: 443, state: "ESTABLISHED"),
            SandboxConnection(pid: 8, process: "python3", proto: .tcp, family: .ipv6, localAddress: "::1", localPort: 8000, state: "LISTEN"),
        ])
        let model = world.model()
        await model.network.refreshSockets()
        #expect(model.network.socketRows.map(\.local) == ["[::1]:8000", "10.0.0.2:50000"])
        #expect(model.network.socketRows[1].remote == "140.82.112.3:443")
    }
}
