import Foundation
import SandvaultCore
import SandvaultEnforce
import Testing
@testable import SandvaultAppModel

@MainActor
@Suite struct FirewallModelTests {
    @Test func applyShowsTheAnchorFirstThenAppliesReleasingPanicAndReloads() async throws {
        let world = TestWorld()
        defer { world.cleanUp() }
        let model = world.model()
        let firewall = model.firewall

        await firewall.setMode(.proxyOnly)
        #expect(try world.store.load().network.mode == .proxyOnly)
        #expect(firewall.needsApply)
        let reloadsBefore = world.netd.reloads.get()

        await firewall.prepareApply()
        let plan = try #require(firewall.pendingApply)
        #expect(plan.mode == .proxyOnly)
        #expect(plan.uid == 601)
        #expect(plan.state.dynamicLocalPorts == [3000])
        #expect(plan.previewText.contains("user 601"))
        #expect(plan.previewText.contains("rdr"))
        // Nothing reached the helper before the confirmation.
        #expect(world.policy.calls.get().isEmpty)

        await firewall.confirmApply()
        #expect(world.policy.calls.get() == ["applyFirewall releasingPanic=true", "status"])
        #expect(world.policy.states.get().first?.network.mode == .proxyOnly)
        #expect(world.netd.reloads.get() == reloadsBefore + 1)
        #expect(firewall.pendingApply == nil)
        #expect(!firewall.changedSinceApply)
        #expect(firewall.message?.kind == .success)
    }

    @Test func protectionLevelsSaveAndApplyAtOnce() async throws {
        let world = TestWorld()
        defer { world.cleanUp() }
        let firewall = world.model().firewall
        #expect(firewall.protection == .off)

        await firewall.setProtection(.watch)
        #expect(try world.store.load().network.mode == .watch)
        #expect(world.policy.calls.get() == ["applyFirewall releasingPanic=true", "status"])
        #expect(world.policy.states.get().first?.network.mode == .watch)
        #expect(firewall.protection == .watch)
        #expect(!firewall.changedSinceApply)

        try world.store.save(AppConfig(network: NetworkPolicy(mode: .watch, defaultAction: .allow)))
        await firewall.setProtection(.ask)
        let policy = try world.store.load().network
        #expect(policy.mode == .proxyOnly && policy.defaultAction == .ask)

        await firewall.setProtection(.off)
        #expect(try world.store.load().network.mode == .off)
        #expect(world.policy.calls.get().suffix(2) == ["disableFirewall", "status"])
    }

    @Test func cancelLeavesEverythingAsItWas() async {
        let world = TestWorld()
        defer { world.cleanUp() }
        let firewall = world.model().firewall
        await firewall.setMode(.open)
        await firewall.prepareApply()
        #expect(firewall.pendingApply != nil)
        firewall.cancelApply()
        await firewall.confirmApply()
        #expect(world.policy.calls.get().isEmpty)
        #expect(firewall.needsApply)
    }

    @Test func modeOffPreviewsAFlush() async throws {
        let world = TestWorld()
        defer { world.cleanUp() }
        let firewall = world.model().firewall
        await firewall.prepareApply()
        let plan = try #require(firewall.pendingApply)
        #expect(plan.rules == nil)
        #expect(plan.uid == nil)
        #expect(plan.previewText.contains("flushed"))
        #expect(plan.state.dynamicLocalPorts.isEmpty)
    }

    @Test func panicSavesBlockedBeforeCallingTheHelper() async throws {
        let world = TestWorld()
        defer { world.cleanUp() }
        try world.store.save(AppConfig(network: NetworkPolicy(mode: .proxyOnly)))
        world.policy.helperStatus.mutate { $0.panicActive = true }
        let model = world.model()

        await model.firewall.panic()
        #expect(try world.store.load().network.mode == .blocked)
        #expect(world.policy.calls.get() == ["panic", "status"])
        #expect(world.policy.states.get().first?.network.mode == .blocked)
        #expect(world.netd.reloads.get() == 1)
        #expect(model.firewall.panicActive)
        #expect(model.menuBar.symbolName == "xmark.shield.fill")
        #expect(model.firewall.message?.kind == .warning)
    }

    @Test func turnOffSavesOffAndFlushes() async throws {
        let world = TestWorld()
        defer { world.cleanUp() }
        try world.store.save(AppConfig(network: NetworkPolicy(mode: .blocked)))
        let firewall = world.model().firewall
        await firewall.turnOff()
        #expect(try world.store.load().network.mode == .off)
        #expect(world.policy.calls.get() == ["disableFirewall", "status"])
        #expect(firewall.message?.title == "Firewall off")
    }

    @Test func proxySettingsAndRules() async throws {
        let world = TestWorld()
        defer { world.cleanUp() }
        let firewall = world.model().firewall

        #expect(await firewall.upsertDomainRule(pattern: "*.npmjs.org", action: .allow, inspect: true))
        await firewall.setDefaultAction(.deny)
        await firewall.setAskTimeout(1000)
        #expect(await firewall.upsertDnsOverride(pattern: "db.internal", address: "10.0.0.5"))
        #expect(!(await firewall.upsertDnsOverride(pattern: "db.internal", address: "not-an-ip")))
        #expect(firewall.message?.kind == .warning)

        var network = try world.store.load().network
        #expect(network.domainRules.map(\.pattern) == ["*.npmjs.org"])
        #expect(network.domainRules[0].inspect)
        #expect(network.defaultAction == .deny)
        #expect(network.askTimeoutSeconds == 300)
        #expect(network.dnsOverrides.map(\.address) == ["10.0.0.5"])
        #expect(!firewall.changedSinceApply)

        await firewall.removeDomainRule(network.domainRules[0].id)
        await firewall.removeDnsOverride(network.dnsOverrides[0].id)
        network = try world.store.load().network
        #expect(network.domainRules.isEmpty)
        #expect(network.dnsOverrides.isEmpty)
    }

    @Test func editingAPortRuleKeepsItsPort() async throws {
        let world = TestWorld()
        defer { world.cleanUp() }
        let firewall = world.model().firewall

        #expect(await firewall.upsertDomainRule(pattern: "example.com", action: .ask))
        #expect(await firewall.upsertDomainRule(pattern: "example.com", action: .allow, port: 22))
        var rule = try #require(try world.store.load().network.domainRules.first { $0.port == 22 })
        await firewall.setInspect(rule, true)
        #expect(await firewall.upsertDomainRule(pattern: rule.pattern, action: .deny, port: rule.port))

        let rules = try world.store.load().network.domainRules
        #expect(rules.count == 2)
        rule = try #require(rules.first { $0.port == 22 })
        #expect(rule.action == .deny && rule.inspect)
        #expect(rules.first { $0.port == nil }?.action == .ask)
    }

    @Test func exceptionsValidateThePort() async throws {
        let world = TestWorld()
        defer { world.cleanUp() }
        let firewall = world.model().firewall

        #expect(!(await firewall.addException(proto: .tcp, destination: "140.82.112.0/20", port: "ssh", note: "")))
        #expect(firewall.message?.kind == .warning)
        #expect(await firewall.addException(proto: .tcp, destination: "140.82.112.0/20", port: "22", note: " GitHub SSH "))
        #expect(await firewall.addException(proto: .udp, destination: "any", port: "", note: ""))

        let exceptions = try world.store.load().network.portExceptions
        #expect(exceptions.map(\.port) == [22, nil])
        #expect(exceptions[0].note == "GitHub SSH")
        #expect(firewall.changedSinceApply)

        await firewall.removeException(exceptions[0].id)
        #expect(try world.store.load().network.portExceptions.count == 1)
    }

    @Test func inspectionOnPublishesTheCAAndSyncsTheSandboxEnvironment() async throws {
        let world = TestWorld()
        defer { world.cleanUp() }
        let firewall = world.model().firewall
        await firewall.setInspection(true)
        #expect(try world.store.load().network.inspection.enabled)
        #expect(firewall.ca.exists)
        #expect(world.ca.synced.get() == [true])

        await firewall.setInspection(false)
        #expect(try !world.store.load().network.inspection.enabled)
        #expect(world.ca.synced.get() == [true, false])
    }

    @Test func loadedModeDecidesWhetherAnApplyIsNeeded() async throws {
        let world = TestWorld()
        defer { world.cleanUp() }
        try world.store.save(AppConfig(network: NetworkPolicy(mode: .open)))
        world.policy.helperStatus.mutate { $0.firewallMode = .open }
        let firewall = world.model().firewall
        await firewall.refreshStatus()
        #expect(!firewall.needsApply)
        world.policy.helperStatus.mutate { $0.firewallMode = nil }
        await firewall.refreshStatus()
        #expect(firewall.needsApply)
    }
}
