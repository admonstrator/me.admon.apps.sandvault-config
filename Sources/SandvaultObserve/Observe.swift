import Foundation
import SandvaultCore

/// Entry points other modules use. The signatures are the contract.
public enum Observe {
    /// Attributes proxied connections to sandbox processes (consumed by sandvault-netd).
    /// One `lsof` per burst, cached for 2 s; a lookup answers within about 200 ms or returns `nil`.
    public static func makeProcessAttributor(environment: SandvaultEnvironment, runner: CommandRunner) -> ProcessAttributor {
        CachedProcessAttributor(monitor: ConnectionMonitor(environment: environment, runner: runner))
    }

    /// Loopback ports the sandbox may reach (consumed by sandvault-netd for the pf anchor): TCP ports sandbox
    /// processes listen on (loopback or wildcard) plus ports of live host helpers, sorted and unique.
    public static func makeLocalPortSource(environment: SandvaultEnvironment, runner: CommandRunner) -> LocalPortSource {
        SandboxLocalPortSource(environment: environment, runner: runner)
    }

    /// Account, workspace, sudoers, profile presence, sv install checks (consumed by `svctl doctor`, the app).
    public static func makeCheckProvider(environment: SandvaultEnvironment, runner: CommandRunner) -> CheckProvider {
        ObserveChecks(environment: environment, runner: runner)
    }
}

/// One-screen overview (`svctl status`, the app's menu bar).
public struct StatusSummary: Codable, Sendable, Equatable {
    /// The `sv.installed` check (state and version detail).
    public var installation: Check?
    public var sessions: [SandboxSession]
    public var processCount: Int
    /// TCP ports sandbox processes listen on, sorted and unique.
    public var listeningPorts: [UInt16]
    public var firewallMode: FirewallMode
    public var worstCheck: CheckState
    /// Checks in `warning` or `failure`.
    public var problems: [Check]
    /// Parts that could not be read, e.g. `lsof` without working sudo.
    public var errors: [String]
    public var generatedAt: Date

    public init(
        installation: Check?, sessions: [SandboxSession], processCount: Int, listeningPorts: [UInt16], firewallMode: FirewallMode,
        worstCheck: CheckState, problems: [Check], errors: [String], generatedAt: Date = Date()
    ) {
        self.installation = installation
        self.sessions = sessions
        self.processCount = processCount
        self.listeningPorts = listeningPorts
        self.firewallMode = firewallMode
        self.worstCheck = worstCheck
        self.problems = problems
        self.errors = errors
        self.generatedAt = generatedAt
    }

    /// Reads processes and listeners; `checks` are the concatenated doctor checks of all modules.
    public static func collect(
        environment: SandvaultEnvironment, runner: CommandRunner, firewallMode: FirewallMode, checks: [Check]
    ) async -> StatusSummary {
        async let snapshot = Result { try await ProcessMonitor(environment: environment, runner: runner).snapshot() }
        async let connections = Result { try await ConnectionMonitor(environment: environment, runner: runner).connections() }
        var errors: [String] = []
        let processes = await snapshot
        let sockets = await connections
        if case .failure(let error) = processes { errors.append("processes: \(error)") }
        if case .failure(let error) = sockets { errors.append("connections: \(error)") }
        let listening = ((try? sockets.get()) ?? []).filter { $0.proto == .tcp && $0.isListening }.map(\.localPort)
        return StatusSummary(
            installation: checks.first { $0.id == "sv.installed" },
            sessions: (try? processes.get().sessions) ?? [],
            processCount: (try? processes.get().processes.count) ?? 0,
            listeningPorts: Array(Set(listening)).sorted(),
            firewallMode: firewallMode,
            worstCheck: CheckReport(checks: checks).worst,
            problems: checks.filter { $0.state >= .warning },
            errors: errors
        )
    }
}

extension Result where Failure == Error {
    init(catching body: () async throws -> Success) async {
        do {
            self = .success(try await body())
        } catch {
            self = .failure(error)
        }
    }
}
