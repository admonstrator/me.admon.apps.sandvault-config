import Foundation
import SandvaultCore
import SandvaultObserve
import Testing
@testable import SandvaultAppModel

@MainActor
@Suite struct ActivityModelTests {
    @Test func listsPingsHostsAndDirectConnections() async throws {
        let world = TestWorld()
        defer { world.cleanUp() }
        try world.store.save(AppConfig(network: NetworkPolicy(mode: .watch)))
        let now = world.clock.current.get()
        world.netd.queue.set([.client(FakeNetdClient(recent: [
            record("api.github.com", .allowed, at: now.addingTimeInterval(-20), process: "git"),
            record("tracker.example", .denied, at: now.addingTimeInterval(-10)),
        ]))])
        world.processes.snapshotResult.set(.success(ProcessSnapshot(processes: [
            process(10, command: "/bin/zsh -i"),
            SandboxProcess(pid: 11, ppid: 10, user: "root", elapsedSeconds: 75, command: "ping -c 100 example.com"),
        ], sessions: [], helpers: [], environmentReadable: true)))
        world.connections.sockets.set([
            SandboxConnection(pid: 12, process: "ssh", proto: .tcp, family: .ipv4, localAddress: "192.168.1.5", localPort: 50_000,
                              remoteAddress: "140.82.112.3", remotePort: 22, state: "ESTABLISHED"),
            // pf hands 443 to netd in watch mode; the socket still names the address, netd's record names the host.
            SandboxConnection(pid: 13, process: "node", proto: .tcp, family: .ipv4, localAddress: "192.168.1.5", localPort: 50_001,
                              remoteAddress: "140.82.112.4", remotePort: 443, state: "ESTABLISHED"),
            SandboxConnection(pid: 13, process: "node", proto: .tcp, family: .ipv4, localAddress: "127.0.0.1", localPort: 50_002,
                              remoteAddress: "127.0.0.1", remotePort: 18080, state: "ESTABLISHED"),
            SandboxConnection(pid: 14, process: "python3", proto: .tcp, family: .ipv4, localAddress: "*", localPort: 8000, state: "LISTEN"),
        ])
        let model = world.model()
        model.netd.start()
        defer { model.netd.stop() }
        #expect(await eventually { model.netd.records.count == 2 })
        await model.processes.refresh()
        await model.activity.refresh()

        let items = model.activity.items
        #expect(items.map(\.title) == ["ping example.com", "tracker.example", "api.github.com", "140.82.112.3:22"])
        #expect(items.map(\.kind) == [.icmp, .host, .host, .direct])
        #expect(items[0].detail == "ICMP, running 1m 15s · the firewall cannot filter it")
        #expect(items[1].blocked && items[1].status == "Blocked")
        #expect(items[2].detail == "git · 1 request · 100 B in, 10 B out")
        #expect(items[3].host == nil)
        #expect(model.activity.summary == "2 hosts · 1 blocked · 1 direct connection · 1 ping or traceroute")
        #expect(model.activity.hint == nil)

        model.activity.filter = "GITHUB"
        #expect(model.activity.items.map(\.title) == ["api.github.com"])
    }

    @Test func hostsWhoseNewestConnectionFailedShowWhy() async throws {
        let world = TestWorld()
        defer { world.cleanUp() }
        try world.store.save(AppConfig(network: NetworkPolicy(mode: .watch)))
        let now = world.clock.current.get()
        var failed = record("admon.me", .askedAllowed, at: now, process: "curl")
        failed.error = "the server closed the connection before answering"
        world.netd.queue.set([.client(FakeNetdClient(recent: [record("admon.me", .allowed, at: now.addingTimeInterval(-60)), failed]))])
        let model = world.model()
        model.netd.start()
        defer { model.netd.stop() }
        #expect(await eventually { model.netd.records.count == 2 })

        let item = try #require(model.activity.items.first)
        #expect(item.status == "Failed" && item.tint == .orange && !item.blocked)
        #expect(item.detail.hasSuffix("the server closed the connection before answering"))
        #expect(model.activity.summary == "1 host · 1 failed")
    }

    @Test func withoutNetdInTheLoopOnlyAddressesShow() async throws {
        let world = TestWorld()
        defer { world.cleanUp() }
        world.connections.sockets.set([
            SandboxConnection(pid: 13, process: "node", proto: .tcp, family: .ipv4, localAddress: "192.168.1.5", localPort: 50_001,
                              remoteAddress: "140.82.112.4", remotePort: 443, state: "ESTABLISHED"),
        ])
        let model = world.model()
        await model.activity.refresh()
        #expect(model.activity.items.map(\.title) == ["140.82.112.4:443"])
        #expect(model.activity.hint?.contains("Choose Watch") == true)
    }

    @Test func allowAndBlockWriteDomainRules() async throws {
        let world = TestWorld()
        defer { world.cleanUp() }
        let model = world.model()
        await model.activity.allow("objects.githubusercontent.com")
        await model.activity.block("tracker.example")
        let rules = try world.store.load().network.domainRules
        #expect(rules.map(\.pattern) == ["*.githubusercontent.com", "tracker.example"])
        #expect(rules.map(\.action) == [.allow, .deny])
        #expect(model.activity.message?.title == "Denied tracker.example")
        #expect(model.network.message == nil)
    }

    @Test func protectionLevelsMapToModes() {
        #expect(ProtectionLevel.current(NetworkPolicy(mode: .off)) == .off)
        #expect(ProtectionLevel.current(NetworkPolicy(mode: .watch)) == .watch)
        #expect(ProtectionLevel.current(NetworkPolicy(mode: .proxyOnly, defaultAction: .ask)) == .ask)
        #expect(ProtectionLevel.current(NetworkPolicy(mode: .proxyOnly, defaultAction: .deny)) == nil)
        #expect(ProtectionLevel.current(NetworkPolicy(mode: .open)) == nil)
        #expect(ProtectionLevel.current(NetworkPolicy(mode: .blocked)) == .blockAll)

        var policy = NetworkPolicy(mode: .off, defaultAction: .allow)
        ProtectionLevel.ask.apply(to: &policy)
        #expect(policy.mode == .proxyOnly && policy.defaultAction == .ask)
        ProtectionLevel.watch.apply(to: &policy)
        #expect(policy.mode == .watch && policy.defaultAction == .ask)
    }

    @Test func simpleWindowShowsFourPagesAndExpertModeAll() async {
        let world = TestWorld()
        defer { world.cleanUp() }
        let model = world.model()
        #expect(model.screens == [.overview, .activity, .handoff, .settings])
        model.select(.firewall)
        #expect(model.selection == .overview)

        model.setExpertMode(true)
        #expect(world.preferences.stored.get().expertMode)
        #expect(model.screens == Screen.allCases)
        model.select(.firewall)
        #expect(model.selection == .firewall)

        model.setExpertMode(false)
        #expect(model.selection == .overview)
    }

    @Test func olderPreferencesKeepTheirInterval() throws {
        let decoded = try JSONDecoder().decode(AppPreferences.self, from: Data(#"{"refreshInterval":5}"#.utf8))
        #expect(decoded == AppPreferences(refreshInterval: 5, expertMode: false))
    }
}
