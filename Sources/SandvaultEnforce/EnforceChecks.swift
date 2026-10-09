import Foundation
import SandvaultCore

/// Enforce's part of `svctl doctor`: helper, profile block, firewall anchor, integrity, panic.
struct EnforceCheckProvider: CheckProvider {
    let environment: SandvaultEnvironment
    let runner: CommandRunner
    let config: AppConfig
    var helperPath = AppPaths.helperPath
    var inspector: ProfileInspector
    var isMacOS = EnforcePlatform.isMacOS

    init(environment: SandvaultEnvironment, runner: CommandRunner, config: AppConfig) {
        self.environment = environment
        self.runner = runner
        self.config = config
        inspector = ProfileInspector(environment: environment)
    }

    func checks() async -> [Check] {
        var checks: [Check] = []
        let helper = await helperCheck()
        checks.append(helper.check)
        checks += profileChecks()
        guard helper.usable else {
            let reason = isMacOS ? "helper not usable" : "macOS only"
            let firewallState: CheckState = !isMacOS || config.network.mode == .off ? .skipped : .unknown
            checks.append(Check(id: "enforce.firewall", title: "Firewall anchor", state: firewallState, detail: reason, fix: isMacOS ? "svctl helper install" : nil))
            checks.append(Check(id: "enforce.integrity", title: "Integrity", state: .skipped, detail: reason))
            return checks
        }
        do {
            let status = try await HelperPolicyApplier(runner: runner, isMacOS: true).status()
            checks.append(firewallCheck(status))
            checks.append(integrityCheck(status))
            checks.append(panicCheck(status))
        } catch {
            for (id, title) in [("enforce.firewall", "Firewall anchor"), ("enforce.integrity", "Integrity")] {
                checks.append(Check(id: id, title: title, state: .unknown, detail: "svctl-helper status failed: \(error)"))
            }
        }
        return checks
    }

    var needsHelper: Bool {
        config.network.mode != .off || config.sandbox.preset == .hardened || !config.sandbox.rules.isEmpty
    }

    func helperCheck() async -> (check: Check, usable: Bool) {
        let title = "Privileged helper"
        guard isMacOS else { return (Check(id: "enforce.helper", title: title, state: .skipped, detail: "macOS only"), false) }
        guard FileManager.default.isExecutableFile(atPath: helperPath) else {
            let detail = "not installed at \(helperPath)" + (needsHelper ? "" : " (needed to apply rules or the firewall)")
            return (Check(id: "enforce.helper", title: title, state: needsHelper ? .warning : .skipped, detail: detail, fix: "svctl helper install"), false)
        }
        // The rule lists exact argv, so probe with one of them.
        let probe = try? await runner.run(CommandInvocation("/usr/bin/sudo", ["-n", "-l", helperPath, "status", "--json"], timeout: 10))
        guard probe?.succeeded == true else {
            return (Check(id: "enforce.helper", title: title, state: .failure, detail: "installed, but sudo -n refuses it (sudoers rule missing)", fix: "svctl helper install"), false)
        }
        return (Check(id: "enforce.helper", title: title, state: .ok, detail: "installed, sudoers rule works"), true)
    }

    func profileChecks() -> [Check] {
        let title = "Sandbox rules (profile block)"
        let plan: ProfilePlan
        do {
            plan = try inspector.plan(for: config.sandbox)
        } catch SandvaultError.invalidInput(let why) {
            return [Check(id: "enforce.profile", title: title, state: .failure, detail: "config holds an invalid rule: \(why)", fix: "svctl rules list, then svctl rules remove <id>")]
        } catch {
            return [Check(id: "enforce.profile", title: title, state: .unknown, detail: "\(error)")]
        }
        let block: Check
        switch plan.drift {
        case .inSync:
            block = Check(id: "enforce.profile", title: title, state: .ok, detail: plan.body == nil ? "no rules configured, no block" : "block matches the config")
        case .missing:
            block = Check(id: "enforce.profile", title: title, state: .warning, detail: "block missing (sv --rebuild rewrites the profile)", fix: "svctl rules apply")
        case .outdated:
            block = Check(id: "enforce.profile", title: title, state: .warning, detail: "block differs from the config", fix: "svctl rules diff, then svctl rules apply")
        case .unexpected:
            block = Check(id: "enforce.profile", title: title, state: .warning, detail: "block present but the config has no rules", fix: "svctl rules apply")
        case .profileMissing:
            block = Check(id: "enforce.profile", title: title, state: .skipped, detail: "sv's profile \(plan.profilePath) not found")
        }
        guard plan.svPartChanged else { return [block] }
        return [block, Check(
            id: "enforce.profile.sv-part", title: "sv's profile since last apply", state: .warning,
            detail: "sv rewrote its part of the profile since the last apply", fix: "svctl rules diff, then svctl rules apply"
        )]
    }

    func firewallCheck(_ status: HelperStatus) -> Check {
        let title = "Firewall anchor"
        let wanted = config.network.mode
        let loaded = status.firewallMode ?? .off
        if wanted != loaded {
            return Check(id: "enforce.firewall", title: title, state: .warning, detail: "config says \(wanted.cliName), loaded is \(loaded.cliName)", fix: "svctl firewall apply")
        }
        if wanted == .off { return Check(id: "enforce.firewall", title: title, state: .ok, detail: "off") }
        if status.pfEnabled == false {
            return Check(id: "enforce.firewall", title: title, state: .failure, detail: "\(loaded.cliName) loaded but pf is disabled", fix: "svctl firewall apply")
        }
        return Check(id: "enforce.firewall", title: title, state: .ok, detail: "\(loaded.cliName) loaded, pf enabled")
    }

    func integrityCheck(_ status: HelperStatus) -> Check {
        let note = status.svSudoersChanged ? " (sv's sudoers file changed since install)" : ""
        guard status.tampered else {
            return Check(id: "enforce.integrity", title: "Integrity", state: .ok, detail: "helper, sudoers rule, profile block and anchor as last applied" + note)
        }
        return Check(
            id: "enforce.integrity", title: "Integrity", state: .failure, detail: status.tamperFindings.joined(separator: ", ") + note,
            fix: "check who changed it, then svctl helper install / svctl rules apply / svctl firewall apply"
        )
    }

    func panicCheck(_ status: HelperStatus) -> Check {
        status.panicActive
            ? Check(id: "enforce.panic", title: "Panic switch", state: .warning, detail: "active: the sandbox user has no network", fix: "svctl firewall mode <mode>, then svctl firewall apply")
            : Check(id: "enforce.panic", title: "Panic switch", state: .ok, detail: "not active")
    }
}
