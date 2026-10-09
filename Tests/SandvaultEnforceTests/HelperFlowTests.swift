import Foundation
import Testing
@testable import SandvaultCore
@testable import SandvaultEnforce

/// The root helper's real logic against a temporary root, with every macOS command faked.
@Suite struct HelperFlowTests {
    static let pfctl = "/sbin/pfctl"
    static let anchor = AppPaths.pfAnchor
    static let dscl = ["/usr/bin/dscl", ".", "-read", "/Users/sandvault-alice", "UniqueID"]
    static let token = "10520867366174617903"

    let root: TempRoot
    let fake = FakeCommandRunner()
    let original: String
    let stateDir = AppPaths.rootStateDir

    init() throws {
        root = try TempRoot()
        original = try Fixture.text("sandbox-sandvault-alice.sb")
        fake.on(Self.dscl, stdout: "UniqueID: 601\n")
        fake.on(["/usr/bin/sandbox-exec"], stdout: "")
        fake.on([Self.pfctl, "-s", "info"], stdout: try Fixture.text("pfctl-s-info-disabled.txt"))
        fake.on([Self.pfctl, "-E"], stdout: "", stderr: try Fixture.text("pfctl-E.stderr.txt"))
        fake.on([Self.pfctl, "-a", Self.anchor], stdout: "")
        fake.on([Self.pfctl, "-a", Self.anchor, "-sn"], stdout: "")
        fake.on([Self.pfctl, "-a", Self.anchor, "-sr"], stdout: try Fixture.text("pfctl-sr.txt"))
        fake.on([Self.pfctl, "-X"], stdout: "")
        fake.on(["/bin/launchctl"], stdout: "")
        fake.on(["/usr/bin/pkill"], stdout: "", exitCode: 1)
        fake.on(["/usr/sbin/visudo"], stdout: "parsed OK\n")
    }

    func helper(_ environment: [String: String] = ["SUDO_USER": "alice", "SUDO_UID": "501"]) -> PrivilegedHelper {
        PrivilegedHelper(context: HelperContext(
            root: root.path, runner: fake, processEnvironment: environment, setsRootOwnership: false,
            now: { Date(timeIntervalSince1970: 1_700_000_000) }
        ))
    }

    func input(_ config: AppConfig, ports: [UInt16] = []) throws -> Data {
        try JSONCoding.lineEncoder.encode(AppliedState(config: config, dynamicLocalPorts: ports))
    }

    func config(_ mode: FirewallMode, rules: Bool = false) -> AppConfig {
        var config = AppConfig()
        config.network.mode = mode
        if rules { config.sandbox = SBPLGeneratorTests.rules }
        return config
    }

    var record: HelperRecord { RootState.readRecord(at: root.path + RootState.recordPath(in: stateDir)) ?? HelperRecord() }
    var argvs: [[String]] { fake.invocations.map(\.argv) }

    func argvs(after count: Int) -> [[String]] { Array(argvs.dropFirst(count)) }

    // MARK: - Profile

    @Test func profileApplyValidatesTheStagedFileThenRenamesIt() async throws {
        defer { root.cleanup() }
        let config = config(.off, rules: true)
        let result = await helper().run(.profileApply, input: try input(config))
        #expect(result.ok, "\(result.message)")

        let body = try #require(try SBPLGenerator.block(for: config.sandbox))
        #expect(root.read(root.alice.sandboxProfilePath) == ProfileMerge.candidate(profile: original, body: body))
        #expect(root.mode(root.alice.sandboxProfilePath) == 0o444)
        let check = try #require(fake.invocations.first)
        #expect(argvs.count == 1)
        #expect(check.executable == "/usr/bin/sandbox-exec")
        #expect(check.arguments.count == 3 && check.arguments[0] == "-f" && check.arguments[2] == "/usr/bin/true")
        #expect(check.arguments[1].hasPrefix(root.path + "/var/sandvault/.sandbox-sandvault-alice.sb."))
        #expect(root.stagedLeftovers(in: "/var/sandvault").isEmpty)

        let svHash = ProfileMerge.svPartSHA256(of: original)
        let backup = RootState.backupPath(in: stateDir, svPartSHA256: svHash)
        #expect(root.read(backup) == original)
        #expect(root.mode(backup) == 0o600)
        #expect(record.svPartSHA256 == svHash)
        #expect(record.profileBlockSHA256 == Fingerprint.sha256(body))
        #expect(root.mode(RootState.recordPath(in: stateDir)) == 0o644)
        #expect(root.mode(RootState.statePath(in: stateDir)) == 0o600)

        let again = await helper().run(.profileApply, input: try input(config))
        #expect(again.ok && again.message == "profile unchanged")
        #expect(argvs.count == 1)
    }

    @Test func profileApplyKeepsTheProfileWhenSandboxExecRejectsIt() async throws {
        defer { root.cleanup() }
        fake.on(["/usr/bin/sandbox-exec"], stdout: "", exitCode: 65, stderr: "sandbox-exec: unbound variable: foo")
        let result = await helper().run(.profileApply, input: try input(config(.off, rules: true)))
        #expect(!result.ok)
        #expect(result.message.contains("sandbox-exec rejected the candidate profile: sandbox-exec: unbound variable: foo"))
        #expect(root.read(root.alice.sandboxProfilePath) == original)
        #expect(root.stagedLeftovers(in: "/var/sandvault").isEmpty)
    }

    @Test func profileApplyRejectsBadInputBeforeRunningAnything() async throws {
        defer { root.cleanup() }
        var bad = AppConfig()
        bad.sandbox.fileRules = [FileRule(path: "etc/passwd", access: .read, effect: .allow)]
        var newer = AppliedState(config: AppConfig())
        newer.version = 2
        for data in [try input(bad), Data(), Data("{\"not\":\"state\"}".utf8), try JSONCoding.lineEncoder.encode(newer),
                     Data(repeating: 0x20, count: PrivilegedHelper.maxInputBytes + 1)] {
            let result = await helper().run(.profileApply, input: data)
            #expect(!result.ok)
        }
        let missing = await helper().run(.profileApply, input: nil)
        #expect(missing.message == "invalid input: expected AppliedState JSON on stdin")
        #expect(argvs.isEmpty)
        #expect(root.read(root.alice.sandboxProfilePath) == original)
    }

    @Test func profileResetRestoresSvsBytes() async throws {
        defer { root.cleanup() }
        #expect(await helper().run(.profileApply, input: try input(config(.off, rules: true))).ok)
        let result = await helper().run(.profileReset)
        #expect(result.ok && result.message == "managed block removed")
        #expect(root.read(root.alice.sandboxProfilePath) == original)
        #expect(record.profileBlockSHA256 == nil)
        #expect(await helper().run(.profileReset).message == "no managed block")
    }

    @Test func identityComesFromSudoOnly() async throws {
        defer { root.cleanup() }
        let state = try input(config(.open))
        #expect(await helper([:]).run(.status).message == "permission denied: SUDO_USER is not set; run the helper through sudo")
        #expect(await helper(["SUDO_USER": "sandvault-alice"]).run(.status).message == "permission denied: sandvault-alice cannot own a sandvault")
        #expect(await helper(["SUDO_USER": "root"]).run(.status).message == "permission denied: root cannot own a sandvault")
        #expect(!(await helper(["SUDO_USER": "../alice"]).run(.status).ok))
        #expect(await helper().run(.pfApply, options: HelperOptions(user: "bob"), input: state).message == "invalid input: --user is accepted by install and uninstall only")
        #expect(await helper().run(.uninstall, options: HelperOptions(source: "/tmp/x")).message == "invalid input: --source is accepted by install only")
        #expect(await helper().run(.status, options: HelperOptions(releasePanic: true)).message == "invalid input: --release-panic is accepted by pf-apply only")
        // The sandbox uid must not be the caller's own.
        let own = await helper(["SUDO_USER": "alice", "SUDO_UID": "601"]).run(.pfApply, input: state)
        #expect(own.message == "invalid input: uid 601 of sandvault-alice is the caller's own uid")
        #expect(!argvs.contains { $0.first == Self.pfctl && $0.contains("-f") })
    }

    // MARK: - Firewall

    @Test func pfApplyValidatesLoadsEnablesAndRecords() async throws {
        defer { root.cleanup() }
        let config = config(.proxyOnly)
        let result = await helper().run(.pfApply, input: try input(config, ports: [9222]))
        #expect(result.ok, "\(result.message)")
        let rules = try #require(try PFAnchorGenerator.rules(for: AppliedState(config: config, dynamicLocalPorts: [9222]), uid: 601))
        #expect(argvs == [
            Self.dscl,
            [Self.pfctl, "-s", "info"],
            [Self.pfctl, "-a", Self.anchor, "-n", "-f", "-"],
            [Self.pfctl, "-a", Self.anchor, "-f", "-"],
            [Self.pfctl, "-E"],
            [Self.pfctl, "-a", Self.anchor, "-sn"],
            [Self.pfctl, "-a", Self.anchor, "-sr"],
        ])
        #expect(fake.invocations[2].stdin == Data(rules.utf8))
        #expect(fake.invocations[3].stdin == Data(rules.utf8))
        #expect(record.pfToken == Self.token)
        #expect(record.firewallMode == .proxyOnly)
        #expect(record.sandboxUID == 601)
        #expect(record.hostUser == "alice")
        #expect(record.anchorSHA256 == Fingerprint.sha256(try Fixture.text("pfctl-sr.txt")))
        #expect(result.details["changed"] == "true")
    }

    @Test func pfApplySkipsAnUnchangedAnchorAndKeepsItsToken() async throws {
        defer { root.cleanup() }
        #expect(await helper().run(.pfApply, input: try input(config(.open), ports: [3000])).ok)
        fake.on([Self.pfctl, "-s", "info"], stdout: try Fixture.text("pfctl-s-info-enabled.txt"))

        var count = argvs.count
        let same = await helper().run(.pfApply, input: try input(config(.open), ports: [3000]))
        #expect(same.ok && same.details["changed"] == "false")
        #expect(argvs(after: count) == [Self.dscl, [Self.pfctl, "-s", "info"], [Self.pfctl, "-a", Self.anchor, "-sn"], [Self.pfctl, "-a", Self.anchor, "-sr"]])

        count = argvs.count
        let changed = await helper().run(.pfApply, input: try input(config(.open), ports: [3000, 5173]))
        #expect(changed.ok && changed.details["changed"] == "true")
        #expect(argvs(after: count).contains([Self.pfctl, "-a", Self.anchor, "-f", "-"]))
        #expect(!argvs(after: count).contains([Self.pfctl, "-E"]))

        // Someone flushed the anchor: same text, different loaded rules, so it is reloaded.
        fake.on([Self.pfctl, "-a", Self.anchor, "-sr"], stdout: "")
        count = argvs.count
        #expect(await helper().run(.pfApply, input: try input(config(.open), ports: [3000, 5173])).details["changed"] == "true")
        #expect(argvs(after: count).contains([Self.pfctl, "-a", Self.anchor, "-f", "-"]))
    }

    @Test func pfDisableFlushesAndReleasesTheToken() async throws {
        defer { root.cleanup() }
        #expect(await helper().run(.pfApply, input: try input(config(.open))).ok)
        let count = argvs.count
        let result = await helper().run(.pfDisable)
        #expect(result.ok)
        #expect(argvs(after: count) == [[Self.pfctl, "-a", Self.anchor, "-F", "all"], [Self.pfctl, "-X", Self.token]])
        #expect(record.pfToken == nil && record.firewallMode == .off)
        let persisted = try JSONCoding.decoder.decode(AppliedState.self, from: Data(try #require(root.read(RootState.statePath(in: stateDir))).utf8))
        #expect(persisted.network.mode == .off)
        // pf-apply with mode off is the same rollback.
        #expect(await helper().run(.pfApply, input: try input(config(.off))).message == "firewall off (anchor flushed)")
    }

    @Test func panicBlocksFirstThenKillsAndLatches() async throws {
        defer { root.cleanup() }
        #expect(await helper().run(.pfApply, input: try input(config(.open))).ok)
        let count = argvs.count
        let result = await helper().run(.panic)
        #expect(result.ok, "\(result.message)")
        let calls = argvs(after: count)
        let load = try #require(calls.firstIndex(of: [Self.pfctl, "-a", Self.anchor, "-f", "-"]))
        let bootout = try #require(calls.firstIndex(of: ["/bin/launchctl", "bootout", "user/601"]))
        let pkill = try #require(calls.firstIndex(of: ["/usr/bin/pkill", "-9", "-u", "sandvault-alice"]))
        #expect(load < bootout && bootout < pkill)
        let loaded = String(decoding: fake.invocations[count + load].stdin ?? Data(), as: UTF8.self)
        #expect(loaded.contains("block return log quick proto { tcp udp } from any to any user 601"))
        #expect(record.panicActive == true && record.firewallMode == .blocked)

        // netd's routine apply must not undo the panic; a user's apply may.
        let routine = await helper().run(.pfApply, input: try input(config(.proxyOnly)))
        #expect(!routine.ok && routine.message.hasPrefix("panic is active"))
        let released = await helper().run(.pfApply, options: HelperOptions(releasePanic: true), input: try input(config(.proxyOnly)))
        #expect(released.ok)
        #expect(record.panicActive == nil && record.firewallMode == .proxyOnly)
    }

    @Test func panicStillKillsWhenTheFirewallFails() async throws {
        defer { root.cleanup() }
        fake.on(Self.dscl, stdout: "", exitCode: 56)
        fake.on(["/usr/bin/id"], stdout: "", exitCode: 1)
        let result = await helper().run(.panic)
        #expect(!result.ok && result.message.hasPrefix("panic incomplete: firewall:"))
        #expect(argvs.contains(["/usr/bin/pkill", "-9", "-u", "sandvault-alice"]))
    }

    @Test func oneHostUserOwnsTheAnchor() async throws {
        defer { root.cleanup() }
        #expect(await helper().run(.pfApply, input: try input(config(.open))).ok)
        let bob = await helper(["SUDO_USER": "bob"]).run(.pfApply, input: try input(config(.blocked)))
        #expect(bob.message == "permission denied: the pf anchor is in use for alice; one host user per Mac can use the firewall")
        #expect(!(await helper(["SUDO_USER": "bob"]).run(.pfDisable).ok))
    }

    @Test func restoreReloadsWithTheStoredUIDAndAFreshToken() async throws {
        defer { root.cleanup() }
        #expect(await helper().run(.restore).message == "nothing to restore")
        #expect(await helper().run(.pfApply, input: try input(config(.proxyOnly))).ok)
        let count = argvs.count
        let result = await helper([:]).run(.restore)
        #expect(result.ok, "\(result.message)")
        #expect(argvs(after: count) == [
            [Self.pfctl, "-s", "info"], [Self.pfctl, "-a", Self.anchor, "-n", "-f", "-"], [Self.pfctl, "-a", Self.anchor, "-f", "-"],
            [Self.pfctl, "-E"], [Self.pfctl, "-a", Self.anchor, "-sn"], [Self.pfctl, "-a", Self.anchor, "-sr"],
        ])
        #expect(record.firewallMode == .proxyOnly)

        // After a panic the boot restores the block.
        #expect(await helper().run(.panic).ok)
        #expect(await helper([:]).run(.restore).ok)
        #expect(record.firewallMode == .blocked && record.panicActive == true)
    }

    // MARK: - Install, status, uninstall

    func installSource() throws -> String {
        let source = root.path + "/build/svctl-helper"
        try FileManager.default.createDirectory(atPath: root.path + "/build", withIntermediateDirectories: true)
        try Data("helper binary v1".utf8).write(to: URL(fileURLWithPath: source))
        return source
    }

    @Test func installWritesHelperSudoersAndLaunchDaemon() async throws {
        defer { root.cleanup() }
        let source = try installSource()
        let result = await helper().run(.install, options: HelperOptions(source: source))
        #expect(result.ok, "\(result.message)")

        #expect(root.read(AppPaths.helperPath) == "helper binary v1")
        #expect(root.mode(AppPaths.helperPath) == 0o755)
        let sudoers = AppPaths(environment: root.alice).helperSudoersFile
        #expect(root.read(sudoers) == PrivilegedHelper.sudoersRule(user: "alice"))
        #expect(root.mode(sudoers) == 0o440)
        let visudo = try #require(fake.invocations.first { $0.executable == "/usr/sbin/visudo" })
        #expect(visudo.arguments.count == 3 && Array(visudo.arguments.prefix(2)) == ["-c", "-f"])
        #expect(visudo.arguments[2].hasPrefix(root.path + "/etc/sudoers.d/.60-sandvault-config-alice."))
        #expect(root.stagedLeftovers(in: "/etc/sudoers.d").isEmpty)
        #expect(root.read(AppPaths.launchDaemonPlist) == PrivilegedHelper.launchDaemonPlist())
        #expect(root.mode(AppPaths.launchDaemonPlist) == 0o644)
        #expect(record.helperSHA256 == Fingerprint.sha256("helper binary v1"))
        #expect(record.svSudoersSHA256 != nil)
    }

    @Test func sudoersRuleListsOnlyUnattendedArgv() throws {
        let rule = PrivilegedHelper.sudoersRule(user: "alice")
        try Fixture.expectGolden(rule, "sudoers-alice")
        #expect(!rule.contains("install") && !rule.contains("restore") && !rule.contains("--user") && !rule.contains("--source"))
        try Fixture.expectGolden(PrivilegedHelper.launchDaemonPlist(), "launchdaemon.plist")
    }

    @Test func installFailsCleanlyWhenVisudoRejects() async throws {
        defer { root.cleanup() }
        fake.on(["/usr/sbin/visudo"], stdout: "", exitCode: 1, stderr: "syntax error near line 2")
        let result = await helper().run(.install, options: HelperOptions(source: try installSource()))
        #expect(!result.ok)
        #expect(!root.exists(AppPaths(environment: root.alice).helperSudoersFile))
        #expect(root.stagedLeftovers(in: "/etc/sudoers.d").isEmpty)
    }

    @Test func installForAUserWithoutSudo() async throws {
        defer { root.cleanup() }
        let result = await helper([:]).run(.install, options: HelperOptions(user: "bob", source: try installSource()))
        #expect(result.ok, "\(result.message)")
        #expect(root.read("/etc/sudoers.d/60-sandvault-config-bob")?.hasPrefix("# Sandvault Config: bob may run") == true)
    }

    @Test func statusReportsTamperingSinceTheLastApply() async throws {
        defer { root.cleanup() }
        #expect(await helper().run(.install, options: HelperOptions(source: try installSource())).ok)
        #expect(await helper().run(.profileApply, input: try input(config(.open, rules: true))).ok)
        #expect(await helper().run(.pfApply, input: try input(config(.open))).ok)
        fake.on([Self.pfctl, "-s", "info"], stdout: try Fixture.text("pfctl-s-info-enabled.txt"))

        var status = HelperStatus(details: await helper().run(.status).details)
        #expect(!status.tampered && !status.svPartChanged && !status.profileBlockMissing)
        #expect(status.pfEnabled == true && status.pfTokenHeld && status.firewallMode == .open)

        try root.write("helper binary v2", to: AppPaths.helperPath, mode: 0o755)
        let profile = try #require(root.read(root.alice.sandboxProfilePath))
        try root.write(profile.replacingOccurrences(of: "(deny process-exec (literal \"/usr/bin/osascript\"))", with: ""), to: root.alice.sandboxProfilePath)
        fake.on([Self.pfctl, "-a", Self.anchor, "-sr"], stdout: "pass out all\n")
        try root.write("changed by sv\n", to: root.alice.sudoersFile)
        let result = await helper().run(.status)
        status = HelperStatus(details: result.details)
        #expect(status.helperChanged && status.profileBlockChanged && status.anchorChanged && status.svSudoersChanged)
        #expect(!status.sudoersChanged && !status.svPartChanged)
        #expect(status.tampered && result.details["tampered"] == "true")
        #expect(result.message == "integrity: helper binary changed, managed profile block edited, pf anchor differs from the last apply")

        // sv --rebuild: our block is gone and sv's text changed. That is drift, not tampering.
        try root.write(original + ";; newer sv\n", to: root.alice.sandboxProfilePath)
        status = HelperStatus(details: await helper().run(.status).details)
        #expect(status.profileBlockMissing && status.svPartChanged && !status.profileBlockChanged)
    }

    @Test func uninstallReversesEverything() async throws {
        defer { root.cleanup() }
        #expect(await helper().run(.install, options: HelperOptions(source: try installSource())).ok)
        #expect(await helper().run(.profileApply, input: try input(config(.open, rules: true))).ok)
        #expect(await helper().run(.pfApply, input: try input(config(.open))).ok)
        let count = argvs.count
        let result = await helper().run(.uninstall)
        #expect(result.ok, "\(result.message)")
        let calls = argvs(after: count)
        #expect(calls.contains([Self.pfctl, "-a", Self.anchor, "-F", "all"]))
        #expect(calls.contains([Self.pfctl, "-X", Self.token]))
        #expect(calls.contains(["/bin/launchctl", "bootout", "system/\(PrivilegedHelper.launchDaemonLabel)"]))
        #expect(root.read(root.alice.sandboxProfilePath) == original)
        for path in [AppPaths.helperPath, AppPaths(environment: root.alice).helperSudoersFile, AppPaths.launchDaemonPlist, stateDir] {
            #expect(!root.exists(path), "\(path)")
        }
        #expect(root.read(root.alice.sudoersFile) != nil)
    }
}
