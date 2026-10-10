import Foundation
import Testing
@testable import SandvaultCore
@testable import SandvaultEnforce

@Suite struct PolicyApplierTests {
    static let sudo = ["/usr/bin/sudo", "-n", AppPaths.helperPath]

    func fake(ok: Bool = true) throws -> FakeCommandRunner {
        let fake = FakeCommandRunner()
        let result = HelperResult(ok: ok, message: ok ? "done" : "refused", details: ["mode": "open"])
        fake.on(Self.sudo, stdout: String(decoding: try JSONCoding.lineEncoder.encode(result), as: UTF8.self), exitCode: ok ? 0 : 1)
        return fake
    }

    func state(ports: [UInt16], mode: FirewallMode = .open) -> AppliedState {
        var config = AppConfig()
        config.network.mode = mode
        return AppliedState(config: config, dynamicLocalPorts: ports)
    }

    @Test func repeatedFirewallAppliesAreFreeWhenNothingChanged() async throws {
        let fake = try fake()
        let applier = HelperPolicyApplier(runner: fake, isMacOS: true)
        #expect(try await applier.applyFirewall(state(ports: [3000, 9222])).ok)
        // Same ports in another order, a new timestamp and different domain rules: nothing pf cares about.
        var same = state(ports: [9222, 3000, 3000])
        same.network.domainRules = [DomainRule(pattern: "example.com", action: .allow)]
        #expect(try await applier.applyFirewall(same).message == "firewall unchanged")
        #expect(fake.invocations.count == 1)

        #expect(try await applier.applyFirewall(state(ports: [3000])).ok)
        #expect(fake.invocations.count == 2)
        #expect(fake.invocations.last?.argv == Self.sudo + ["pf-apply", "--json"])
        let sent = try JSONCoding.decoder.decode(AppliedState.self, from: try #require(fake.invocations.last?.stdin))
        #expect(sent.dynamicLocalPorts == [3000])
    }

    @Test func userAppliesReleasePanicAndBypassTheCache() async throws {
        let fake = try fake()
        let applier = HelperPolicyApplier(runner: fake, isMacOS: true)
        _ = try await applier.applyFirewall(state(ports: []))
        _ = try await applier.applyFirewall(state(ports: []), releasingPanic: true)
        #expect(fake.invocations.map(\.argv).last == Self.sudo + ["pf-apply", "--json", "--release-panic"])
        #expect(fake.invocations.count == 2)
    }

    @Test func failedAppliesAreNotCached() async throws {
        let fake = try fake(ok: false)
        let applier = HelperPolicyApplier(runner: fake, isMacOS: true)
        #expect(try await !applier.applyFirewall(state(ports: [])).ok)
        #expect(try await !applier.applyFirewall(state(ports: [])).ok)
        #expect(fake.invocations.count == 2)
    }

    @Test func everyArgvTheClientsSendIsCoveredByTheSudoersRule() async throws {
        let fake = try fake()
        let applier = HelperPolicyApplier(runner: fake, isMacOS: true)
        _ = try await applier.applyFirewall(state(ports: []))
        _ = try await applier.applyFirewall(state(ports: []), releasingPanic: true)
        _ = try await applier.applyProfile(state(ports: []))
        _ = try await applier.resetProfile()
        _ = try await applier.disableFirewall()
        _ = try await applier.panic()
        _ = try await applier.status()
        for subcommand in [HelperSubcommand.profileApply, .profileReset, .pfApply, .pfDisable, .panic, .status] {
            _ = try await HelperClient(runner: fake).run(subcommand)
        }
        let allowed = Set(PrivilegedHelper.unattendedArguments.map { Self.sudo + $0 })
        for invocation in fake.invocations {
            #expect(allowed.contains(invocation.argv), "\(invocation.argv) is not in the sudoers rule")
        }
        // The activity recorder (SandvaultObserve) sends the streaming argv; its own test checks it against this list.
        let streaming = Self.sudo + [HelperSubcommand.activityRecord.rawValue, "--json"]
        #expect(Set(fake.invocations.map(\.argv)) == allowed.subtracting([streaming]))
        #expect(allowed.contains(streaming))
    }

    @Test func refusesOffMacOS() async throws {
        let applier = HelperPolicyApplier(runner: try fake(), isMacOS: false)
        await #expect(throws: SandvaultError.unsupportedPlatform("the root helper (sandbox-exec, pf) exists on macOS only")) {
            try await applier.applyProfile(state(ports: []))
        }
    }

    @Test func explainsAMissingSudoersRule() async throws {
        let fake = FakeCommandRunner()
        fake.on(["/usr/bin/sudo"], stdout: "", exitCode: 1, stderr: "sudo: a password is required\n")
        await #expect(throws: SandvaultError.permissionDenied("helper sudoers rule missing; run `svctl helper install`")) {
            try await HelperPolicyApplier(runner: fake, isMacOS: true).status()
        }
    }

    @Test func factoryReturnsTheHelperApplier() {
        #expect(Enforce.makePolicyApplier(runner: FakeCommandRunner()) is HelperPolicyApplier)
    }

    @Test func autoReapplyOnlyWhenTheBlockIsMissing() async throws {
        let root = try TempRoot()
        defer { root.cleanup() }
        let fake = try fake()
        let applier = HelperPolicyApplier(runner: fake, isMacOS: true)
        let inspector = ProfileInspector(profilePath: root.path + root.alice.sandboxProfilePath, recordPath: root.path + "/none.json")
        var config = AppConfig()
        config.sandbox = SBPLGeneratorTests.rules
        #expect(try await Enforce.reapplyIfMissing(config: config, inspector: inspector, applier: applier) == nil)
        config.sandbox.autoReapply = true
        #expect(try await Enforce.reapplyIfMissing(config: config, inspector: inspector, applier: applier)?.ok == true)
        #expect(fake.invocations.map(\.argv) == [Self.sudo + ["profile-apply", "--json"]])

        let body = try #require(try SBPLGenerator.block(for: config.sandbox))
        try root.write(ProfileMerge.candidate(profile: try Fixture.text("sandbox-sandvault-alice.sb"), body: body + "\n;; old"), to: root.alice.sandboxProfilePath)
        #expect(try await Enforce.reapplyIfMissing(config: config, inspector: inspector, applier: applier) == nil)
        #expect(fake.invocations.count == 1)
    }
}
