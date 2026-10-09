import Foundation
import SandvaultCore

/// Sockets and traffic of the sandbox user.
public struct ConnectionMonitor: Sendable {
    public var environment: SandvaultEnvironment
    public var runner: CommandRunner

    public init(environment: SandvaultEnvironment, runner: CommandRunner) {
        self.environment = environment
        self.runner = runner
    }

    /// Internet sockets of the sandbox user (`lsof` as that user: lsof sees other users' sockets only as root).
    public func connections() async throws -> [SandboxConnection] {
        let result = try await runner.run(Invocations.lsof(environment))
        if result.sudoRefused { throw SandvaultError.sudoMissing(environment) }
        // lsof exits 1 when nothing matched, and also after mere warnings while still listing sockets.
        guard result.succeeded || !result.stdout.isEmpty || Self.onlyWarnings(result.stderrString) else {
            throw SandvaultError.commandFailed(Invocations.lsof(environment).description, result.exitCode, result.stderrString)
        }
        return LsofParser.parse(result.stdoutString)
    }

    /// Empty, or only `lsof: WARNING: ...` lines with their indented continuation lines.
    static func onlyWarnings(_ stderr: String) -> Bool {
        stderr.split(separator: "\n").allSatisfy { $0.hasPrefix("lsof: WARNING") || $0.first?.isWhitespace == true }
    }

    /// Cumulative bytes per sandbox process from one `nettop` sample. `pids` defaults to the sandbox
    /// user's current processes.
    public func traffic(pids: Set<Int32>? = nil) async throws -> [ProcessTraffic] {
        let wanted: Set<Int32>
        if let pids {
            wanted = pids
        } else {
            wanted = Set(try await ProcessMonitor(environment: environment, runner: runner).sandboxProcesses().map(\.pid))
        }
        let output = try await runner.checked(Invocations.nettop).stdoutString
        return NettopParser.parse(output).filter { wanted.contains($0.pid) }
    }
}

extension SandboxConnection {
    /// Bound to loopback or to every interface, i.e. reachable from `127.0.0.1`.
    public var isLoopbackReachable: Bool {
        ["*", "0.0.0.0", "::", "::0"].contains(localAddress) || PrivateNetworks.loopback.contains { $0.contains(localAddress) }
    }
}

/// netd seam: loopback ports the sandbox may reach under `LocalhostPolicy.sandboxAndHelpers`.
/// TCP ports sandbox processes listen on (loopback or wildcard) plus ports of live host helpers.
/// UDP is left out: an unconnected UDP socket is not a listener, and allowing every ephemeral client port
/// would open loopback far wider than intended.
struct SandboxLocalPortSource: LocalPortSource {
    var environment: SandvaultEnvironment
    var runner: CommandRunner
    var files: HostFiles = .live

    func allowedLocalPorts() async throws -> [UInt16] {
        async let connections = ConnectionMonitor(environment: environment, runner: runner).connections()
        async let helpers = ProcessMonitor(environment: environment, runner: runner, files: files).helpers()
        let listening = try await connections.filter { $0.proto == .tcp && $0.isListening && $0.isLoopbackReachable }.map(\.localPort)
        let helperPorts = try await helpers.compactMap(\.port)
        return Array(Set(listening + helperPorts).subtracting([0])).sorted()
    }
}

/// netd seam: maps the source port of a proxied loopback connection to the sandbox process.
/// One `lsof` serves a whole burst of lookups; a lookup never waits longer than `deadline`.
final class CachedProcessAttributor: ProcessAttributor {
    let cache: ConnectionCache

    init(monitor: ConnectionMonitor, maxAge: Duration = .seconds(2), minInterval: Duration = .milliseconds(100), deadline: Duration = .milliseconds(200)) {
        cache = ConnectionCache(monitor: monitor, maxAge: maxAge, minInterval: minInterval, deadline: deadline)
    }

    func process(forLocalPort port: UInt16, proto: TransportProtocol) async -> (pid: Int32, name: String)? {
        guard let hit = await cache.lookup(port: port, proto: proto) else { return nil }
        return (hit.pid, hit.name)
    }
}

actor ConnectionCache {
    struct Key: Hashable {
        var port: UInt16
        var proto: TransportProtocol
    }

    struct Owner: Sendable {
        var pid: Int32
        var name: String
    }

    let monitor: ConnectionMonitor
    let maxAge: Duration
    let minInterval: Duration
    let deadline: Duration
    let clock = ContinuousClock()

    private var owners: [Key: Owner] = [:]
    private var refreshedAt: ContinuousClock.Instant?
    private var finishedAt: ContinuousClock.Instant?
    private var inFlight: Task<Void, Never>?
    /// Number of lsof runs; for tests.
    private(set) var refreshCount = 0

    init(monitor: ConnectionMonitor, maxAge: Duration, minInterval: Duration, deadline: Duration) {
        self.monitor = monitor
        self.maxAge = maxAge
        self.minInterval = minInterval
        self.deadline = deadline
    }

    func lookup(port: UInt16, proto: TransportProtocol) async -> Owner? {
        let key = Key(port: port, proto: proto)
        if let refreshedAt, clock.now - refreshedAt < maxAge, let owner = owners[key] { return owner }
        await waitBounded(for: refresh())
        return owners[key]
    }

    /// The running refresh, or a new one; a new one starts no sooner than `minInterval` after the last.
    private func refresh() -> Task<Void, Never> {
        if let inFlight { return inFlight }
        let delay = finishedAt.map { minInterval - (clock.now - $0) } ?? .zero
        let task = Task {
            if delay > .zero { try? await Task.sleep(for: delay) }
            let connections = try? await monitor.connections()
            self.store(connections)
        }
        inFlight = task
        return task
    }

    private func store(_ connections: [SandboxConnection]?) {
        finishedAt = clock.now
        refreshCount += 1
        inFlight = nil
        guard let connections else {
            // Stale owners would misattribute; without lsof nothing is attributed.
            owners = [:]
            refreshedAt = nil
            return
        }
        var owners: [Key: Owner] = [:]
        for connection in connections {
            owners[Key(port: connection.localPort, proto: connection.proto)] = Owner(pid: connection.pid, name: connection.process)
        }
        self.owners = owners
        refreshedAt = clock.now
    }

    private nonisolated func waitBounded(for task: Task<Void, Never>) async {
        let deadline = deadline
        await withCheckedContinuation { (continuation: CheckedContinuation<Void, Never>) in
            let once = Once()
            Task {
                await task.value
                if once.claim() { continuation.resume() }
            }
            Task {
                try? await Task.sleep(for: deadline)
                if once.claim() { continuation.resume() }
            }
        }
    }
}

/// True for the first caller only.
final class Once: @unchecked Sendable {
    private let lock = NSLock()
    private var claimed = false

    func claim() -> Bool {
        lock.withLock {
            defer { claimed = true }
            return !claimed
        }
    }
}
