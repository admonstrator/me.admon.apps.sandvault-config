import Foundation

// Contract between unprivileged callers (svctl, app, netd) and the root helper
// (`AppPaths.helperPath`, run through `sudo -n` per `/etc/sudoers.d/60-sandvault-config-<user>`).
//
// Rules for the helper (agent B):
// - The only input is typed JSON on stdin (`AppliedState`); it never accepts SBPL or pf text, file paths to write,
//   or user names. The host user comes from `SUDO_USER`, every path from `SandvaultEnvironment`/`AppPaths`.
// - Output is one `HelperResult` as JSON on stdout; exit code 0 iff `ok`.

public enum HelperSubcommand: String, Codable, Sendable, CaseIterable {
    /// Validate and write the managed block into sv's sandbox profile (stdin: AppliedState).
    case profileApply = "profile-apply"
    /// Remove the managed block (restores sv's original profile text).
    case profileReset = "profile-reset"
    /// Load the pf anchor for `AppliedState.network` (stdin: AppliedState).
    case pfApply = "pf-apply"
    /// Flush the anchor and release the pf enable token.
    case pfDisable = "pf-disable"
    /// Panic: anchor in `blocked` mode and terminate every sandbox process.
    case panic
    /// Report profile block, anchor, helper and sudoers hashes.
    case status
    /// Re-apply the last persisted state (LaunchDaemon at boot).
    case restore
    /// Copy the helper, write its sudoers rule and the boot LaunchDaemon (plain sudo with an admin password;
    /// the only subcommands that accept `--user` and `--source`).
    case install
    /// Reverse `install`: firewall off, profile block removed, files deleted.
    case uninstall
}

/// The desired state the helper enforces; also persisted root-owned in `AppPaths.rootStateDir` for `restore`.
public struct AppliedState: Codable, Sendable, Equatable {
    public var version: Int
    public var sandbox: SandboxSettings
    public var network: NetworkPolicy
    /// Loopback ports the sandbox may reach under `LocalhostPolicy.sandboxAndHelpers`
    /// (its own listeners and sv's host helpers), refreshed by netd.
    public var dynamicLocalPorts: [UInt16]
    public var generatedAt: Date

    public init(
        version: Int = 1, sandbox: SandboxSettings, network: NetworkPolicy, dynamicLocalPorts: [UInt16] = [],
        generatedAt: Date = Date()
    ) {
        self.version = version
        self.sandbox = sandbox
        self.network = network
        self.dynamicLocalPorts = dynamicLocalPorts
        self.generatedAt = generatedAt
    }

    public init(config: AppConfig, dynamicLocalPorts: [UInt16] = []) {
        self.init(sandbox: config.sandbox, network: config.network, dynamicLocalPorts: dynamicLocalPorts)
    }
}

public struct HelperResult: Codable, Sendable, Equatable {
    public var ok: Bool
    public var message: String
    /// Machine-readable facts, e.g. `profileBlockSHA256`, `pfToken`, `anchorRules`.
    public var details: [String: String]

    public init(ok: Bool, message: String, details: [String: String] = [:]) {
        self.ok = ok
        self.message = message
        self.details = details
    }
}

/// Unprivileged side of the helper contract.
public struct HelperClient: Sendable {
    public var runner: CommandRunner

    public init(runner: CommandRunner) {
        self.runner = runner
    }

    public var isInstalled: Bool { FileManager.default.isExecutableFile(atPath: AppPaths.helperPath) }

    public func run(_ subcommand: HelperSubcommand, state: AppliedState? = nil) async throws -> HelperResult {
        let stdin = try state.map { try JSONCoding.lineEncoder.encode($0) }
        let result = try await runner.run(.viaHelper(subcommand.rawValue, ["--json"], stdin: stdin))
        if let decoded = try? JSONCoding.decoder.decode(HelperResult.self, from: result.stdout) {
            return decoded
        }
        if result.stderrString.contains("a password is required") || result.stderrString.contains("not allowed") {
            throw SandvaultError.permissionDenied("helper sudoers rule missing; run `svctl helper install`")
        }
        throw SandvaultError.commandFailed("svctl-helper \(subcommand.rawValue)", result.exitCode, result.stderrString)
    }
}
