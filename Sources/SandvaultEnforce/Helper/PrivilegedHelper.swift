import Foundation
import SandvaultCore

/// Flags of `svctl-helper` besides `--json`. Typed state still arrives only as JSON on stdin.
public struct HelperOptions: Sendable, Equatable {
    /// `install`/`uninstall` only: the host user when not run through sudo (e.g. an admin prompt from the app).
    public var user: String?
    /// `install` only: the helper binary to copy.
    public var source: String?
    /// `pf-apply` only: a user action that may leave the `blocked` state a panic left behind.
    public var releasePanic: Bool

    public init(user: String? = nil, source: String? = nil, releasePanic: Bool = false) {
        self.user = user
        self.source = source
        self.releasePanic = releasePanic
    }
}

/// The root helper's logic for every `HelperSubcommand`. The executable only parses flags, reads stdin and
/// prints the result; everything else happens here against `HelperContext`, so tests run it unprivileged.
public struct PrivilegedHelper: Sendable {
    public static let sandboxExecPath = "/usr/bin/sandbox-exec"
    public static let visudoPath = "/usr/sbin/visudo"
    public static let launchctlPath = "/bin/launchctl"
    public static let pkillPath = "/usr/bin/pkill"
    public static let maxInputBytes = 1 << 20
    public static var launchDaemonLabel: String { "\(BundleIdentity.bundleID).pf" }

    public var context: HelperContext

    public init(context: HelperContext) {
        self.context = context
    }

    var files: RootFiles { RootFiles(setsRootOwnership: context.setsRootOwnership) }
    var pf: PFControl { PFControl(runner: context.runner) }

    /// Never throws: failures become `HelperResult(ok: false, ...)`.
    public func run(_ subcommand: HelperSubcommand, options: HelperOptions = HelperOptions(), input: Data? = nil) async -> HelperResult {
        do {
            try check(options, for: subcommand)
            switch subcommand {
            case .profileApply: return try await applyProfile(try sudoEnvironment(), try decodeState(input))
            case .profileReset: return try await resetProfile(try sudoEnvironment())
            case .pfApply: return try await applyFirewall(try sudoEnvironment(), try decodeState(input), releasePanic: options.releasePanic)
            case .pfDisable: return try await disableFirewall(try sudoEnvironment())
            case .panic: return await panic(try sudoEnvironment(), input.flatMap { try? decodeState($0) })
            case .status: return try await status(try sudoEnvironment())
            case .restore: return try await restore()
            case .install: return try await install(try installEnvironment(options), source: options.source)
            case .uninstall: return await uninstall(try installEnvironment(options))
            case .activityRecord: throw SandvaultError.notImplemented("activity-record")
            }
        } catch {
            return HelperResult(ok: false, message: "\(error)")
        }
    }

    // MARK: - Input

    func check(_ options: HelperOptions, for subcommand: HelperSubcommand) throws {
        if options.user != nil, subcommand != .install, subcommand != .uninstall {
            throw SandvaultError.invalidInput("--user is accepted by install and uninstall only")
        }
        if options.source != nil, subcommand != .install {
            throw SandvaultError.invalidInput("--source is accepted by install only")
        }
        if options.releasePanic, subcommand != .pfApply {
            throw SandvaultError.invalidInput("--release-panic is accepted by pf-apply only")
        }
    }

    /// The host user is whoever ran sudo; never a name from the input.
    func sudoEnvironment() throws -> SandvaultEnvironment {
        guard let user = context.processEnvironment["SUDO_USER"], !user.isEmpty else {
            throw SandvaultError.permissionDenied("SUDO_USER is not set; run the helper through sudo")
        }
        return try Self.environment(for: user)
    }

    func installEnvironment(_ options: HelperOptions) throws -> SandvaultEnvironment {
        guard let user = options.user ?? context.processEnvironment["SUDO_USER"], !user.isEmpty else {
            throw SandvaultError.invalidInput("pass --user <name> or run through sudo")
        }
        return try Self.environment(for: user)
    }

    static func environment(for user: String) throws -> SandvaultEnvironment {
        try validateUserName(user)
        return SandvaultEnvironment(hostUser: user, hostHome: "/Users/\(user)")
    }

    /// Short POSIX-ish account names only; the name ends up in file paths and the sudoers rule.
    static func validateUserName(_ name: String) throws {
        let valid = (1...64).contains(name.utf8.count)
            && name.utf8.allSatisfy { ($0 >= 0x30 && $0 <= 0x39) || ($0 >= 0x41 && $0 <= 0x5A) || ($0 >= 0x61 && $0 <= 0x7A) || $0 == 0x5F || $0 == 0x2E || $0 == 0x2D }
            && !name.hasPrefix("-") && !name.hasPrefix(".")
        guard valid else { throw SandvaultError.invalidInput("invalid user name \(SBPLGenerator.printable(name))") }
        guard name != "root", !name.hasPrefix(SandvaultEnvironment.sandvaultPrefix) else {
            throw SandvaultError.permissionDenied("\(name) cannot own a sandvault")
        }
    }

    func decodeState(_ input: Data?) throws -> AppliedState {
        guard let input, !input.isEmpty else { throw SandvaultError.invalidInput("expected AppliedState JSON on stdin") }
        guard input.count <= Self.maxInputBytes else { throw SandvaultError.invalidInput("stdin exceeds \(Self.maxInputBytes) bytes") }
        let state: AppliedState
        do {
            state = try JSONCoding.decoder.decode(AppliedState.self, from: input)
        } catch {
            throw SandvaultError.invalidInput("stdin is not an AppliedState: \(error)")
        }
        guard state.version == 1 else { throw SandvaultError.invalidInput("AppliedState version \(state.version) is not supported") }
        return state
    }

    // MARK: - Profile

    func applyProfile(_ environment: SandvaultEnvironment, _ state: AppliedState) async throws -> HelperResult {
        let path = context.profile(environment)
        guard let current = try files.readText(path) else {
            throw SandvaultError.notInstalled("sv's sandbox profile \(environment.sandboxProfilePath) (run sv once)")
        }
        let body = try SBPLGenerator.block(for: state.sandbox)
        let candidate = ProfileMerge.candidate(profile: current, body: body)
        let svPart = ProfileMerge.svPartSHA256(of: current)
        try ensureStateDir()
        try backupOnce(current, svPartSHA256: svPart)
        let changed = candidate != current
        if changed { try await writeProfile(candidate, to: path) }

        var record = loadRecord()
        record.svPartSHA256 = svPart
        record.profileSHA256 = Fingerprint.sha256(candidate)
        record.profileBlockSHA256 = body.map(Fingerprint.sha256)
        record.profileAppliedAt = context.now()
        try save(record)
        var persisted = loadPersistedState()
        persisted.sandbox = state.sandbox
        try save(persisted)

        let rules = state.sandbox.fileRules.count + state.sandbox.machRules.count + state.sandbox.execRules.count
        return HelperResult(
            ok: true,
            message: changed ? "profile updated (\(rules) rules, preset \(state.sandbox.preset.rawValue))" : "profile unchanged",
            details: [
                "profile": environment.sandboxProfilePath, "changed": String(changed), "svPartSHA256": svPart,
                "profileBlockSHA256": record.profileBlockSHA256 ?? "none",
            ]
        )
    }

    func resetProfile(_ environment: SandvaultEnvironment) async throws -> HelperResult {
        let path = context.profile(environment)
        guard let current = try files.readText(path) else {
            throw SandvaultError.notInstalled("sv's sandbox profile \(environment.sandboxProfilePath)")
        }
        let candidate = ProfileMerge.candidate(profile: current, body: nil)
        let changed = candidate != current
        if changed { try await writeProfile(candidate, to: path) }
        try ensureStateDir()
        var record = loadRecord()
        record.svPartSHA256 = ProfileMerge.svPartSHA256(of: current)
        record.profileSHA256 = Fingerprint.sha256(candidate)
        record.profileBlockSHA256 = nil
        record.profileAppliedAt = context.now()
        try save(record)
        var persisted = loadPersistedState()
        persisted.sandbox = SandboxSettings()
        try save(persisted)
        return HelperResult(ok: true, message: changed ? "managed block removed" : "no managed block", details: ["changed": String(changed)])
    }

    /// Stages the text beside the profile, lets sandbox-exec compile exactly that file, then renames it into place.
    func writeProfile(_ text: String, to path: String) async throws {
        let staged = try files.stage(Data(text.utf8), beside: path, mode: 0o444)
        do {
            let result = try await context.runner.run(CommandInvocation(Self.sandboxExecPath, ["-f", staged, "/usr/bin/true"]))
            guard result.succeeded else {
                throw SandvaultError.invalidInput("sandbox-exec rejected the candidate profile: \(result.stderrString.trimmingCharacters(in: .whitespacesAndNewlines))")
            }
            try files.commit(staged, to: path)
        } catch {
            files.discard(staged)
            throw error
        }
    }

    /// Keeps sv's profile as found, once per distinct sv part.
    func backupOnce(_ profile: String, svPartSHA256: String) throws {
        let path = RootState.backupPath(in: context.stateDir, svPartSHA256: svPartSHA256)
        guard try files.read(path) == nil else { return }
        try files.write(Data(profile.utf8), to: path, mode: 0o600)
    }

    // MARK: - Firewall

    func applyFirewall(
        _ environment: SandvaultEnvironment, _ state: AppliedState, releasePanic: Bool, knownUID: UInt32? = nil
    ) async throws -> HelperResult {
        var record = loadRecord()
        try checkAnchorOwner(record, environment)
        if record.panicActive == true, !releasePanic, state.network.mode != .blocked {
            return HelperResult(
                ok: false, message: "panic is active: the firewall stays blocked until a user applies a mode (svctl firewall mode <mode>, then svctl firewall apply)",
                details: ["panicActive": "true"]
            )
        }
        guard state.network.mode != .off else { return try await disableFirewall(environment, persisting: state) }

        let uid: UInt32
        if let knownUID { uid = knownUID } else { uid = try await resolveUID(environment) }
        guard let rules = try PFAnchorGenerator.rules(for: state, uid: uid) else { throw SandvaultError.io("no rules for \(state.network.mode)") }
        let textSHA = Fingerprint.sha256(rules)
        let enabled = try await pf.isEnabled()

        var unchanged = false
        if textSHA == record.anchorTextSHA256, record.pfToken != nil, enabled, let stored = record.anchorSHA256 {
            unchanged = Fingerprint.sha256(try await pf.loadedRules()) == stored
        }
        if !unchanged { try await load(rules, pfEnabled: enabled, into: &record) }
        record.hostUser = environment.hostUser
        record.sandboxUID = uid
        record.firewallMode = state.network.mode
        if releasePanic { record.panicActive = nil }
        try ensureStateDir()
        try save(record)
        var persisted = loadPersistedState()
        persisted.network = state.network
        persisted.dynamicLocalPorts = state.dynamicLocalPorts
        try save(persisted)

        return HelperResult(
            ok: true,
            message: unchanged ? "firewall unchanged (\(state.network.mode.cliName))" : "firewall \(state.network.mode.cliName) loaded",
            details: [
                "mode": state.network.mode.rawValue, "uid": String(uid), "changed": String(!unchanged),
                "anchorTextSHA256": textSHA, "pfToken": record.pfToken ?? "",
            ]
        )
    }

    func disableFirewall(_ environment: SandvaultEnvironment, persisting newState: AppliedState? = nil) async throws -> HelperResult {
        var record = loadRecord()
        try checkAnchorOwner(record, environment)
        try await pf.flush()
        var details: [String: String] = ["mode": FirewallMode.off.rawValue]
        if let token = record.pfToken {
            // A stale token (pf restarted, reboot) must not stop the rollback.
            details["tokenReleased"] = String((try? await pf.release(token: token)) ?? false)
        }
        record.pfToken = nil
        record.anchorSHA256 = nil
        record.anchorTextSHA256 = nil
        record.firewallMode = .off
        record.panicActive = nil
        record.hostUser = environment.hostUser
        record.firewallAppliedAt = context.now()
        try ensureStateDir()
        try save(record)
        var persisted = newState ?? loadPersistedState()
        persisted.network.mode = .off
        try save(persisted)
        return HelperResult(ok: true, message: "firewall off (anchor flushed)", details: details)
    }

    /// Validates and loads the anchor, takes a pf reference when pf is off or we hold none, records the hashes.
    func load(_ rules: String, pfEnabled: Bool, into record: inout HelperRecord) async throws {
        try await pf.validate(rules)
        try await pf.load(rules)
        if record.pfToken == nil || !pfEnabled { record.pfToken = try await pf.enable() }
        record.anchorSHA256 = Fingerprint.sha256(try await pf.loadedRules())
        record.anchorTextSHA256 = Fingerprint.sha256(rules)
        record.firewallAppliedAt = context.now()
    }

    /// One anchor exists per Mac; a second host user must not overwrite or flush the first one's rules.
    func checkAnchorOwner(_ record: HelperRecord, _ environment: SandvaultEnvironment) throws {
        if let owner = record.hostUser, owner != environment.hostUser, (record.firewallMode ?? .off) != .off {
            throw SandvaultError.permissionDenied("the pf anchor is in use for \(owner); one host user per Mac can use the firewall")
        }
    }

    func resolveUID(_ environment: SandvaultEnvironment) async throws -> UInt32 {
        let uid = try await SandboxAccount.resolveUID(environment: environment, runner: context.runner)
        if let caller = context.processEnvironment["SUDO_UID"].flatMap(UInt32.init), caller == uid {
            throw SandvaultError.invalidInput("uid \(uid) of \(environment.sandvaultUser) is the caller's own uid")
        }
        return uid
    }

    // MARK: - Panic

    /// Blocks the network first, then terminates every sandbox process; each step runs even if the other failed.
    func panic(_ environment: SandvaultEnvironment, _ provided: AppliedState?) async -> HelperResult {
        var problems: [String] = []
        var details: [String: String] = [:]
        var uid: UInt32?
        do {
            var record = loadRecord()
            try checkAnchorOwner(record, environment)
            let resolved = try await resolveUID(environment)
            uid = resolved
            var state = provided ?? loadPersistedState()
            state.network.mode = .blocked
            guard let rules = try PFAnchorGenerator.rules(for: state, uid: resolved) else { throw SandvaultError.io("no blocked rules") }
            try await load(rules, pfEnabled: try await pf.isEnabled(), into: &record)
            record.firewallMode = .blocked
            record.panicActive = true
            record.hostUser = environment.hostUser
            record.sandboxUID = resolved
            try ensureStateDir()
            try save(record)
            var persisted = loadPersistedState()
            persisted.network.mode = .blocked
            try save(persisted)
            details["mode"] = FirewallMode.blocked.rawValue
        } catch {
            problems.append("firewall: \(error)")
        }

        if let uid {
            let bootout = try? await context.runner.run(CommandInvocation(Self.launchctlPath, ["bootout", "user/\(uid)"]))
            details["bootoutExit"] = bootout.map { String($0.exitCode) } ?? "not run"
        }
        do {
            // pkill exits 0 when it signalled processes and 1 when none matched.
            let result = try await context.runner.run(CommandInvocation(Self.pkillPath, ["-9", "-u", environment.sandvaultUser]))
            details["pkillExit"] = String(result.exitCode)
            if result.exitCode > 1 { problems.append("pkill exited \(result.exitCode): \(result.stderrString)") }
        } catch {
            problems.append("pkill: \(error)")
        }
        return HelperResult(
            ok: problems.isEmpty,
            message: problems.isEmpty ? "panic: firewall blocked, sandbox processes terminated" : "panic incomplete: " + problems.joined(separator: "; "),
            details: details
        )
    }

    // MARK: - Status and restore

    func status(_ environment: SandvaultEnvironment) async throws -> HelperResult {
        let record = loadRecord()
        func hash(_ path: String) -> String? { (try? files.read(path, maxBytes: 256 << 20)).map(Fingerprint.sha256) }
        func changed(_ current: String?, _ stored: String?) -> Bool { stored != nil && current != stored }

        var status = HelperStatus()
        status.hostUser = record.hostUser
        status.firewallMode = record.firewallMode
        status.panicActive = record.panicActive == true
        status.pfTokenHeld = record.pfToken != nil
        status.pfEnabled = try? await pf.isEnabled()
        status.helperSHA256 = hash(context.helperBinary)
        status.sudoersSHA256 = hash(context.helperSudoers(environment))
        status.svSudoersSHA256 = hash(context.svSudoers(environment))

        let profile = try? files.readText(context.profile(environment))
        let block = profile.flatMap { ManagedBlock.sandboxProfile.extract(from: $0) }
        status.profileSHA256 = profile.map(Fingerprint.sha256)
        status.profileBlockSHA256 = block.map(Fingerprint.sha256)
        status.svPartSHA256 = profile.map(ProfileMerge.svPartSHA256(of:))
        status.anchorSHA256 = (try? await pf.loadedRules()).map(Fingerprint.sha256)

        status.helperChanged = changed(status.helperSHA256, record.helperSHA256)
        status.sudoersChanged = changed(status.sudoersSHA256, record.sudoersSHA256)
        status.svSudoersChanged = changed(status.svSudoersSHA256, record.svSudoersSHA256)
        status.svPartChanged = changed(status.svPartSHA256, record.svPartSHA256)
        status.profileBlockMissing = record.profileBlockSHA256 != nil && block == nil
        status.profileBlockChanged = block != nil && record.profileSHA256 != nil && status.profileBlockSHA256 != record.profileBlockSHA256
        // A flushed anchor prints nothing; after `off` an empty anchor is the expected state.
        let expectedAnchor = record.anchorSHA256 ?? (record.firewallMode == .off ? Fingerprint.sha256("") : nil)
        status.anchorChanged = status.anchorSHA256 != nil && changed(status.anchorSHA256, expectedAnchor)
        return HelperResult(ok: true, message: status.summary, details: status.details)
    }

    /// Boot: re-load the persisted anchor. pf tokens do not survive a reboot, so the stored one is dropped first.
    func restore() async throws -> HelperResult {
        var record = loadRecord()
        guard let user = record.hostUser, FileManager.default.fileExists(atPath: context.statePath) else {
            return HelperResult(ok: true, message: "nothing to restore")
        }
        let environment = try Self.environment(for: user)
        let state = loadPersistedState()
        record.pfToken = nil
        try save(record)
        guard state.network.mode != .off else { return HelperResult(ok: true, message: "firewall off; nothing to restore") }
        return try await applyFirewall(environment, state, releasePanic: false, knownUID: record.sandboxUID)
    }

    // MARK: - Install

    func install(_ environment: SandvaultEnvironment, source: String?) async throws -> HelperResult {
        guard let source = source ?? context.executablePath, source.hasPrefix("/") else {
            throw SandvaultError.invalidInput("--source must be the absolute path of svctl-helper")
        }
        guard let binary = try files.read(source, maxBytes: 256 << 20) else { throw SandvaultError.notInstalled("helper binary \(source)") }
        let helperPath = context.helperBinary
        try files.makeDirectory(URL(fileURLWithPath: helperPath).deletingLastPathComponent().path, mode: 0o755)
        if source != helperPath { try files.write(binary, to: helperPath, mode: 0o755) }
        try ensureStateDir()

        let sudoersPath = context.helperSudoers(environment)
        let rule = Self.sudoersRule(user: environment.hostUser)
        let staged = try files.stage(Data(rule.utf8), beside: sudoersPath, mode: 0o440)
        do {
            let check = try await context.runner.run(CommandInvocation(Self.visudoPath, ["-c", "-f", staged]))
            guard check.succeeded else {
                throw SandvaultError.commandFailed("visudo -c -f <staged sudoers>", check.exitCode, check.stdoutString + check.stderrString)
            }
            try files.commit(staged, to: sudoersPath)
        } catch {
            files.discard(staged)
            throw error
        }
        try files.write(Data(Self.launchDaemonPlist().utf8), to: context.launchDaemonPlist, mode: 0o644)

        var record = loadRecord()
        record.helperSHA256 = Fingerprint.sha256(binary)
        record.sudoersSHA256 = Fingerprint.sha256(rule)
        record.svSudoersSHA256 = (try? files.read(context.svSudoers(environment))).map(Fingerprint.sha256)
        try save(record)
        return HelperResult(
            ok: true, message: "helper installed for \(environment.hostUser)",
            details: [
                "helperPath": AppPaths.helperPath, "sudoersFile": AppPaths(environment: environment).helperSudoersFile,
                "launchDaemon": AppPaths.launchDaemonPlist, "helperSHA256": record.helperSHA256 ?? "",
            ]
        )
    }

    /// Best effort: every step runs, failures are collected.
    func uninstall(_ environment: SandvaultEnvironment) async -> HelperResult {
        var problems: [String] = []
        let record = loadRecord()
        let firewallActive = (record.firewallMode ?? .off) != .off || record.pfToken != nil
        if firewallActive, record.hostUser == nil || record.hostUser == environment.hostUser {
            do { _ = try await disableFirewall(environment) } catch { problems.append("firewall: \(error)") }
        }
        if let profile = try? files.readText(context.profile(environment)), ManagedBlock.sandboxProfile.contains(in: profile) {
            do { _ = try await resetProfile(environment) } catch { problems.append("profile: \(error)") }
        }
        _ = try? await context.runner.run(CommandInvocation(Self.launchctlPath, ["bootout", "system/\(Self.launchDaemonLabel)"]))
        for path in [context.launchDaemonPlist, context.helperSudoers(environment), context.helperBinary] {
            do { try files.remove(path) } catch { problems.append("\(error)") }
        }
        do { try files.removeTree(context.stateDir) } catch { problems.append("\(error)") }
        return HelperResult(
            ok: problems.isEmpty,
            message: problems.isEmpty ? "helper uninstalled" : "uninstall incomplete: " + problems.joined(separator: "; ")
        )
    }

    /// argv the host user may run through `sudo -n` without a password: exactly what `HelperClient` and
    /// `HelperPolicyApplier` send. `install`, `uninstall` (which take `--user`/`--source`) and `restore` are
    /// deliberately absent: a bare `NOPASSWD: <helper>` would let anyone running as the host user install a
    /// different binary as root without a password.
    public static let unattendedArguments: [[String]] = [
        [HelperSubcommand.profileApply.rawValue, "--json"],
        [HelperSubcommand.profileReset.rawValue, "--json"],
        [HelperSubcommand.pfApply.rawValue, "--json"],
        [HelperSubcommand.pfApply.rawValue, "--json", "--release-panic"],
        [HelperSubcommand.pfDisable.rawValue, "--json"],
        [HelperSubcommand.panic.rawValue, "--json"],
        [HelperSubcommand.status.rawValue, "--json"],
    ]

    static func sudoersRule(user: String) -> String {
        let commands = unattendedArguments.map { ([AppPaths.helperPath] + $0).joined(separator: " ") }
        return """
        # Sandvault Config: \(user) may run these helper subcommands as root without a password.
        \(user) ALL=(root) NOPASSWD: \(commands.joined(separator: ", \\\n    "))

        """
    }

    /// Runs `<helper> restore --json` once at boot; output goes to the root state directory.
    static func launchDaemonPlist() -> String {
        let log = "\(AppPaths.rootStateDir)/restore.log"
        return """
        <?xml version="1.0" encoding="UTF-8"?>
        <!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
        <plist version="1.0">
        <dict>
        \t<key>Label</key>
        \t<string>\(launchDaemonLabel)</string>
        \t<key>ProgramArguments</key>
        \t<array>
        \t\t<string>\(AppPaths.helperPath)</string>
        \t\t<string>restore</string>
        \t\t<string>--json</string>
        \t</array>
        \t<key>RunAtLoad</key>
        \t<true/>
        \t<key>StandardOutPath</key>
        \t<string>\(log)</string>
        \t<key>StandardErrorPath</key>
        \t<string>\(log)</string>
        </dict>
        </plist>

        """
    }

    // MARK: - Root state

    func ensureStateDir() throws {
        try files.makeDirectory(context.stateDir, mode: 0o755)
    }

    func loadRecord() -> HelperRecord {
        RootState.readRecord(at: context.recordPath) ?? HelperRecord()
    }

    func save(_ record: HelperRecord) throws {
        try files.write(try JSONCoding.encoder.encode(record), to: context.recordPath, mode: 0o644)
    }

    /// The persisted state for `restore`, or the default state (firewall off, no rules).
    func loadPersistedState() -> AppliedState {
        guard let data = try? files.read(context.statePath),
              let state = try? JSONCoding.decoder.decode(AppliedState.self, from: data)
        else { return AppliedState(config: AppConfig()) }
        return state
    }

    /// Root-only (0600): it holds the user's network policy.
    func save(_ state: AppliedState) throws {
        try files.write(try JSONCoding.encoder.encode(state), to: context.statePath, mode: 0o600)
    }
}
