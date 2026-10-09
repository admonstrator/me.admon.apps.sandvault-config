import SandvaultCore

/// Entry points other modules use. Agent A replaces the stub bodies; the signatures are the contract.
public enum Observe {
    /// Attributes proxied connections to sandbox processes (consumed by sandvault-netd).
    public static func makeProcessAttributor(environment: SandvaultEnvironment, runner: CommandRunner) -> ProcessAttributor {
        NoProcessAttributor()
    }

    /// Loopback ports the sandbox may reach (consumed by sandvault-netd for the pf anchor).
    public static func makeLocalPortSource(environment: SandvaultEnvironment, runner: CommandRunner) -> LocalPortSource {
        UnimplementedLocalPortSource()
    }

    /// Account, workspace, sudoers, profile presence, sv install checks (consumed by `svctl doctor`, the app).
    public static func makeCheckProvider(environment: SandvaultEnvironment, runner: CommandRunner) -> CheckProvider {
        NoChecks()
    }
}

struct UnimplementedLocalPortSource: LocalPortSource {
    func allowedLocalPorts() async throws -> [UInt16] {
        throw SandvaultError.notImplemented("Observe.makeLocalPortSource")
    }
}
