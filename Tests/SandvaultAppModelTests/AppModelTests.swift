import Foundation
import SandvaultCore
import SandvaultObserve
import Testing
@testable import SandvaultAppModel

@MainActor
@Suite struct AppModelTests {
    @Test func pollingRunsOnlyWhileASurfaceIsVisible() async {
        let world = TestWorld()
        defer { world.cleanUp() }
        let model = world.model()
        #expect(!model.isPolling)

        model.setVisible(.menu, true)
        #expect(model.isPolling)
        #expect(await eventually { world.processes.snapshotCalls.get() >= 2 })
        // The menu alone does not read sockets.
        #expect(world.connections.calls.get() == 0)

        model.setVisible(.window, true)
        model.select(.network)
        #expect(await eventually { world.connections.calls.get() >= 2 })

        model.setVisible(.menu, false)
        #expect(model.isPolling)
        model.setVisible(.window, false)
        #expect(!model.isPolling)
        try? await Task.sleep(nanoseconds: 20_000_000)
        let calls = world.processes.snapshotCalls.get()
        try? await Task.sleep(nanoseconds: 20_000_000)
        #expect(world.processes.snapshotCalls.get() == calls)
    }

    @Test func menuBarSummary() {
        let now = Date(timeIntervalSince1970: 1_800_000_000)
        let snapshot = ProcessSnapshot(
            processes: [process(1, command: "claude", session: "S"), process(2, ppid: 1, command: "node", session: "S")],
            sessions: [SandboxSession(id: "S", rootPID: 1, processCount: 2, command: "claude", elapsedSeconds: 10)],
            helpers: [], environmentReadable: true
        )
        let records = [
            record("old.example", .denied, at: now.addingTimeInterval(-4000)),
            record("a.example", .denied, at: now.addingTimeInterval(-100)),
            record("b.example", .timedOut, at: now.addingTimeInterval(-50)),
            record("a.example", .askedDenied, at: now.addingTimeInterval(-10)),
            record("ok.example", .allowed, at: now.addingTimeInterval(-5)),
        ]
        let summary = MenuBarSummary(mode: .proxyOnly, panicActive: false, netdRunning: true, snapshot: snapshot, records: records, pendingAsks: 0, now: now)
        #expect(summary.symbolName == "checkmark.shield.fill")
        #expect(summary.sessions == 1)
        #expect(summary.processes == 2)
        #expect(summary.deniedLastHour == 3)
        #expect(summary.recentDenied.map(\.host) == ["a.example", "b.example"])
        #expect(summary.recentDenied[0].count == 2)

        func symbol(_ mode: FirewallMode, panic: Bool = false, netd: Bool = true, asks: Int = 0) -> String {
            MenuBarSummary(mode: mode, panicActive: panic, netdRunning: netd, snapshot: nil, records: [], pendingAsks: asks, now: now).symbolName
        }
        #expect(symbol(.off) == "shield.slash")
        #expect(symbol(.open) == "shield.lefthalf.filled")
        #expect(symbol(.proxyOnly, netd: false) == "exclamationmark.triangle")
        #expect(symbol(.open, asks: 2) == "exclamationmark.shield.fill")
        #expect(symbol(.open, panic: true, asks: 2) == "xmark.shield.fill")
        #expect(symbol(.blocked) == "xmark.shield.fill")
    }

    @Test func menuBarSymbolFollowsModeNetdAndAsks() async throws {
        let world = TestWorld()
        defer { world.cleanUp() }
        try world.store.save(AppConfig(network: NetworkPolicy(mode: .proxyOnly)))
        let now = world.clock.current.get()
        let ask = AskRequest(host: "a.example", port: 443, kind: .transparentTLS, createdAt: now, expiresAt: now.addingTimeInterval(30))
        world.netd.queue.set([.client(FakeNetdClient(pending: [ask]))])
        let model = world.model()
        #expect(model.menuBarSymbol == "exclamationmark.triangle")
        model.netd.start()
        defer { model.netd.stop() }
        #expect(await eventually { model.menuBarSymbol == "exclamationmark.shield.fill" })
        await model.asks.answer(ask, .denyOnce)
        #expect(model.menuBarSymbol == "checkmark.shield.fill")
        #expect(model.menuBar.stateTitle == "Firewall: proxy only")
    }

    @Test func droppedFoldersGoToTheHandOffPage() async throws {
        let world = TestWorld()
        defer { world.cleanUp() }
        let model = world.model()
        let file = world.directory.appendingPathComponent("notes.txt").path
        try "x".write(toFile: file, atomically: true, encoding: .utf8)

        #expect(!model.handOff(paths: [file]))
        #expect(model.selection == .overview)
        #expect(model.handOff(paths: [file, world.directory.path]))
        #expect(model.selection == .handoff)
        #expect(await eventually { model.handoff.source == world.directory.path })
    }

    @Test func startConnectsToNetdAndReadsTheSlowState() async {
        let world = TestWorld(checks: OverviewModelTests.healthy)
        defer { world.cleanUp() }
        let model = world.model()
        model.start()
        defer { model.stop() }
        #expect(await eventually { model.netd.isConnected && model.overview.refreshedAt != nil })
        #expect(world.policy.calls.get().contains("status"))
        #expect(model.overview.nextStep == .installHelper)

        await model.settings.installHelper()
        #expect(await eventually { model.overview.nextStep == .enableFirewall })
    }

    @Test func screensHaveTitlesInSidebarOrder() {
        #expect(Screen.allCases.map(\.title) == [
            "Overview", "Processes", "Network", "Firewall & Proxy", "Sandbox Rules & Learn", "Tools", "Repos & Hand-off",
            "Migration", "Settings",
        ])
    }
}
