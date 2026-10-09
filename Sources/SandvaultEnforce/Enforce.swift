import SandvaultCore

/// Entry points other modules use. Agent B replaces the stub bodies; the signatures are the contract.
public enum Enforce {
    /// Applies state through the privileged helper (consumed by svctl, sandvault-netd, the app).
    public static func makePolicyApplier(runner: CommandRunner) -> PolicyApplier {
        UnimplementedPolicyApplier()
    }

    /// Helper installed, profile block drift, pf anchor state, integrity (consumed by `svctl doctor`, the app).
    public static func makeCheckProvider(environment: SandvaultEnvironment, runner: CommandRunner, config: AppConfig) -> CheckProvider {
        NoChecks()
    }
}

struct UnimplementedPolicyApplier: PolicyApplier {
    func applyFirewall(_ state: AppliedState) async throws -> HelperResult {
        throw SandvaultError.notImplemented("Enforce.applyFirewall")
    }

    func applyProfile(_ state: AppliedState) async throws -> HelperResult {
        throw SandvaultError.notImplemented("Enforce.applyProfile")
    }
}
