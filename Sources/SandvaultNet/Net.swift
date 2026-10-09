import Foundation
import SandvaultCore

/// Namespace for the proxy, DNS forwarder, policy engine and control socket (agent C).
public enum Net {
    /// netd reachable, LaunchAgent installed, CA present and published, zshenv block current, ports bound
    /// (consumed by `svctl doctor`, the app).
    public static func makeCheckProvider(environment: SandvaultEnvironment, runner: CommandRunner, config: AppConfig) -> CheckProvider {
        NetChecks(paths: AppPaths(environment: environment), runner: runner, config: config)
    }
}

/// Checks of the network side. Everything here is read-only.
public struct NetChecks: CheckProvider {
    public var paths: AppPaths
    public var runner: CommandRunner
    public var config: AppConfig
    public var socketPath: String
    public var shared: SharedFiles
    public var launchAgent: NetdLaunchAgent

    public init(paths: AppPaths, runner: CommandRunner, config: AppConfig, socketPath: String? = nil, shared: SharedFiles? = nil) {
        self.paths = paths
        self.runner = runner
        self.config = config
        self.socketPath = socketPath ?? paths.effectiveControlSocket
        self.shared = shared ?? SharedFiles(environment: paths.environment)
        launchAgent = NetdLaunchAgent(paths: paths, runner: runner)
    }

    public func checks() async -> [Check] {
        let policy = config.network
        let needed = policy.mode != .off
        var result: [Check] = []

        let status = try? await ControlClient.send(.status, socketPath: socketPath, timeout: 3)
        if case .status(let netd)? = status {
            result.append(Check(
                id: "net.netd", title: "sandvault-netd", state: .ok,
                detail: "running since \(ISO8601DateFormatter().string(from: netd.startedAt)), \(netd.activeConnections) active, "
                    + "\(netd.allowedCount) allowed, \(netd.deniedCount) denied, \(netd.pendingAsks) pending asks"
            ))
            let mismatched = zip(["proxy", "http", "tls", "dns"], zip(netd.ports.all, policy.ports.all)).filter { $0.1.0 != $0.1.1 }
            result.append(mismatched.isEmpty
                ? Check(id: "net.ports", title: "netd ports", state: .ok, detail: policy.ports.all.map(String.init).joined(separator: ", "))
                : Check(
                    id: "net.ports", title: "netd ports", state: .warning,
                    detail: mismatched.map { "\($0.0) bound \($0.1.0), configured \($0.1.1)" }.joined(separator: "; "),
                    fix: "svctl netd restart"
                ))
        } else {
            result.append(Check(
                id: "net.netd", title: "sandvault-netd", state: needed ? .failure : .skipped,
                detail: "not reachable at \(socketPath)", fix: "svctl netd install"
            ))
            result.append(Check(id: "net.ports", title: "netd ports", state: .unknown, detail: "netd is not running"))
        }

        if launchAgent.platformSupported {
            let installed = FileManager.default.fileExists(atPath: launchAgent.plistPath)
            result.append(Check(
                id: "net.launchagent", title: "netd LaunchAgent", state: installed ? .ok : (needed ? .warning : .skipped),
                detail: installed ? launchAgent.plistPath : "not installed", fix: installed ? nil : "svctl netd install"
            ))
        } else {
            result.append(Check(id: "net.launchagent", title: "netd LaunchAgent", state: .skipped, detail: "launchd is macOS only"))
        }

        result.append(caCheck())

        do {
            let state = try SandboxEnvironmentBlock.check(policy: policy, paths: paths, shared: shared)
            let detail: String
            switch state {
            case .current: detail = needed ? "proxy variables current in \(paths.sharedZshenv)" : "no block (firewall off)"
            case .missing: detail = "block missing in \(paths.sharedZshenv)"
            case .stale: detail = "block differs from the configuration"
            }
            result.append(Check(
                id: "net.zshenv", title: "Sandbox proxy variables", state: state == .current ? .ok : .warning, detail: detail,
                fix: state == .current ? nil : "svctl proxy env apply"
            ))
        } catch {
            result.append(Check(id: "net.zshenv", title: "Sandbox proxy variables", state: .warning, detail: "\(error)", fix: "svctl proxy env apply"))
        }
        return result
    }

    private func caCheck() -> Check {
        let wanted = config.network.inspection.enabled
        let store = CAStore(paths: paths)
        let ca: InspectionCA?
        do {
            ca = try store.load()
        } catch {
            return Check(id: "net.ca", title: "Inspection CA", state: .failure, detail: "\(error)", fix: "svctl ca remove && svctl ca create")
        }
        guard let ca else {
            return Check(
                id: "net.ca", title: "Inspection CA", state: wanted ? .failure : .skipped,
                detail: wanted ? "inspection is on but no CA exists" : "not created (inspection off)", fix: wanted ? "svctl ca create" : nil
            )
        }
        let published = (try? CAPublisher(paths: paths, runner: runner, shared: shared).state(of: ca)) ?? .missing
        let fingerprint = (try? ca.fingerprint) ?? "?"
        if published != .current {
            return Check(
                id: "net.ca", title: "Inspection CA", state: wanted ? .warning : .ok,
                detail: "present (\(fingerprint)), published copy \(published.rawValue)", fix: "svctl ca publish"
            )
        }
        return Check(id: "net.ca", title: "Inspection CA", state: .ok, detail: "present and published (\(fingerprint))")
    }
}
