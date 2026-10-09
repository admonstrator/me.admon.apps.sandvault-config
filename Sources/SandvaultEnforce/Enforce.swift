import SandvaultCore

/// Entry points other modules use.
public enum Enforce {
    /// Applies state through the privileged helper (consumed by svctl, sandvault-netd, the app).
    /// The concrete type is `HelperPolicyApplier`, which also offers reset, firewall off, panic and status.
    public static func makePolicyApplier(runner: CommandRunner) -> PolicyApplier {
        HelperPolicyApplier(runner: runner)
    }

    /// Helper installed, profile block drift, pf anchor state, integrity (consumed by `svctl doctor`, the app).
    public static func makeCheckProvider(environment: SandvaultEnvironment, runner: CommandRunner, config: AppConfig) -> CheckProvider {
        EnforceCheckProvider(environment: environment, runner: runner, config: config)
    }

    /// What `rules apply` would write: current profile, candidate, diff and drift.
    public static func profilePlan(environment: SandvaultEnvironment, settings: SandboxSettings) throws -> ProfilePlan {
        try ProfileInspector(environment: environment).plan(for: settings)
    }

    /// The anchor text `firewall apply` would load for the sandbox user's uid, or `nil` for `off`.
    public static func firewallPreview(state: AppliedState, uid: UInt32) throws -> String? {
        try PFAnchorGenerator.rules(for: state, uid: uid)
    }

    /// `SandboxSettings.autoReapply`: writes the block again when it is missing (typically after `sv --rebuild`).
    /// Returns `nil` when auto-reapply is off or the block is not missing; an outdated block is left for the user.
    /// Pass `ProfileInspector(environment:)`.
    public static func reapplyIfMissing(config: AppConfig, inspector: ProfileInspector, applier: PolicyApplier) async throws -> HelperResult? {
        guard config.sandbox.autoReapply, try inspector.plan(for: config.sandbox).drift == .missing else { return nil }
        return try await applier.applyProfile(AppliedState(config: config))
    }
}
