import SandvaultCore

/// Entry points other modules use. Agent B replaces the stub bodies; the signatures are the contract.
public enum Enforce {
    /// Applies state through the privileged helper (consumed by svctl, sandvault-netd, the app).
    public static func makePolicyApplier(runner: CommandRunner) -> PolicyApplier {
        UnimplementedPolicyApplier()
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
