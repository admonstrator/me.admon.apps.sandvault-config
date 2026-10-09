import SandvaultCore

/// Namespace for the proxy, DNS forwarder, policy engine and control socket (agent C).
public enum Net {
    /// netd reachable, LaunchAgent loaded, CA present, zshenv block current (consumed by `svctl doctor`, the app).
    public static func makeCheckProvider(environment: SandvaultEnvironment, runner: CommandRunner, config: AppConfig) -> CheckProvider {
        NoChecks()
    }
}
