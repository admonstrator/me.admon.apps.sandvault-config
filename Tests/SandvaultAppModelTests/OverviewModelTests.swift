import Foundation
import SandvaultCore
import Testing
@testable import SandvaultAppModel

@MainActor
@Suite struct OverviewModelTests {
    static let healthy: [Check] = [
        Check(id: "sv.installed", title: "sv", state: .ok, detail: "sv 1.32.0"),
        Check(id: "account.user", title: "Sandbox user", state: .ok, detail: "uid 601"),
        Check(id: "enforce.panic", title: "Panic switch", state: .ok, detail: "not active"),
        Check(id: "enforce.firewall", title: "Firewall anchor", state: .ok, detail: "off"),
    ]

    @Test func nextStepFollowsTheDependencyOrder() {
        func state(sv: Bool? = true, account: Bool? = true, helper: Bool = true, panic: Bool = false, netd: Bool = true, mode: FirewallMode = .proxyOnly, outOfSync: Bool = false) -> SetupStep {
            SetupState(svInstalled: sv, accountReady: account, helperInstalled: helper, netdRunning: netd, firewallMode: mode, panicActive: panic, firewallOutOfSync: outOfSync).nextStep
        }
        #expect(state(sv: nil) == .checking)
        #expect(state(sv: false, helper: false, netd: false) == .installSandvault(fix: nil))
        #expect(state(account: false, helper: false) == .createSandbox(fix: nil))
        #expect(state(helper: false, panic: true, netd: false) == .installHelper)
        #expect(state(panic: true, netd: false) == .endPanic)
        #expect(state(netd: false, mode: .off) == .startNetd)
        #expect(state(mode: .off) == .enableFirewall)
        #expect(state(outOfSync: true) == .applyFirewall)
        #expect(state() == .ready)
        #expect(SetupStep.installHelper.screen == .settings)
        #expect(SetupStep.enableFirewall.suggestedCommand == "svctl firewall mode proxy-only && svctl firewall apply")
    }

    @Test func setupStateReadsTheDoctorChecks() {
        let checks = [
            Check(id: "sv.installed", title: "sv", state: .failure, detail: "not found", fix: "brew install sandvault"),
            Check(id: "enforce.panic", title: "Panic switch", state: .warning, detail: "active"),
            Check(id: "enforce.firewall", title: "Firewall anchor", state: .warning, detail: "config says open, loaded is off"),
        ]
        let state = SetupState(checks: checks, helperInstalled: true, netdRunning: false, firewallMode: .open)
        #expect(state.svInstalled == false)
        #expect(state.accountReady == nil)
        #expect(state.panicActive)
        #expect(state.firewallOutOfSync)
        #expect(state.nextStep == .installSandvault(fix: "brew install sandvault"))
        #expect(state.nextStep.suggestedCommand == "brew install sandvault")
    }

    @Test func refreshAggregatesChecksSummaryAndNextStep() async throws {
        var checks = Self.healthy
        checks.append(Check(id: "net.ca", title: "Inspection CA", state: .warning, detail: "stale", fix: "svctl ca publish"))
        checks.append(Check(id: "umask", title: "umask", state: .failure, detail: "077"))
        let world = TestWorld(checks: checks)
        defer { world.cleanUp() }
        try world.store.save(AppConfig(network: NetworkPolicy(mode: .proxyOnly)))
        let model = world.model()

        await model.overview.refresh()

        #expect(model.overview.sections.count == 1)
        #expect(model.overview.summary?.firewallMode == .proxyOnly)
        #expect(model.overview.summary?.worstCheck == .failure)
        #expect(model.overview.problems.map(\.id) == ["umask", "net.ca"])
        #expect(model.overview.refreshedAt == world.clock.current.get())
        // Helper missing comes before netd.
        #expect(model.overview.nextStep == .installHelper)

        world.helperSetup.installed.set(true)
        #expect(model.overview.nextStep == .startNetd)
    }

    @Test func refreshIfStaleWaitsThirtySeconds() async {
        let world = TestWorld(checks: Self.healthy)
        defer { world.cleanUp() }
        let model = world.model()
        await model.overview.refresh()
        let first = model.overview.refreshedAt

        world.clock.advance(10)
        await model.overview.refreshIfStale()
        #expect(model.overview.refreshedAt == first)

        world.clock.advance(25)
        await model.overview.refreshIfStale()
        #expect(model.overview.refreshedAt == world.clock.current.get())
    }
}
