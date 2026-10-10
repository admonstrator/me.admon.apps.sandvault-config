import Foundation
import NIOCore
import NIOPosix
import NIOSSL
import SandvaultCore

/// Settings of one netd instance. Production uses the defaults derived from `AppPaths`;
/// tests pass ephemeral ports, temporary paths and local upstreams.
public struct NetdOptions: Sendable {
    public var paths: AppPaths
    public var configPath: String
    public var socketPath: String
    public var bindHost: String
    /// `ip` or `ip:port` (`[v6]:port`); `nil` uses the first nameserver of /etc/resolv.conf.
    public var upstreamDNS: String?
    /// Listener ports; `nil` uses `NetworkPolicy.ports` (port 0 binds an ephemeral port).
    public var ports: ProxyPorts?
    /// Where the transparent listeners connect (80 and 443 outside tests).
    public var transparentHTTPUpstreamPort = 80
    public var transparentTLSUpstreamPort = 443
    /// Where the transparent TCP listener connects instead of the original destination; `nil` outside tests.
    public var transparentTCPUpstream: SocketAddress?
    public var upstreamTrustRoots: NIOSSLTrustRoots = .default
    public var connectionLogPath: String
    public var caDirectory: String
    /// Seconds between firewall refreshes and status events.
    public var refreshInterval: Double = 5
    /// Keep the `.zshenv` block in the shared workspace in line with the config (on start and reload).
    public var manageEnvironmentBlock = true
    public var sharedFiles: SharedFiles

    public init(paths: AppPaths, configPath: String? = nil, socketPath: String? = nil, bindHost: String = "127.0.0.1", upstreamDNS: String? = nil) {
        self.paths = paths
        self.configPath = configPath ?? paths.configFile
        self.socketPath = socketPath ?? paths.effectiveControlSocket
        self.bindHost = bindHost
        self.upstreamDNS = upstreamDNS
        connectionLogPath = paths.connectionLog
        caDirectory = paths.caDir
        sharedFiles = SharedFiles(environment: paths.environment)
    }
}

/// sandvault-netd: explicit proxy, transparent HTTP/TLS/TCP listeners, DNS forwarder, policy, connection log
/// and control socket, composed from the seams of the other modules.
public final class NetDaemon: Sendable, ControlService {
    public let options: NetdOptions
    let runtime: NetRuntime
    private let refresher: LocalPortRefresher?
    private let group: EventLoopGroup
    private let logger: @Sendable (String) -> Void
    private let state = LockedState()

    public init(
        options: NetdOptions,
        attributor: ProcessAttributor = NoProcessAttributor(),
        localPorts: LocalPortSource? = nil,
        applier: PolicyApplier? = nil,
        resolver: HostResolver = SystemHostResolver(),
        group: EventLoopGroup = MultiThreadedEventLoopGroup.singleton,
        logger: @escaping @Sendable (String) -> Void
    ) throws {
        self.options = options
        self.group = group
        self.logger = logger
        let policy = try PolicyStore(store: ConfigStore(path: options.configPath))
        let inspection = try InspectionService(store: CAStore(directory: options.caDirectory), upstreamTrustRoots: options.upstreamTrustRoots)
        runtime = NetRuntime(
            policy: policy, resolver: resolver, attributor: attributor, log: ConnectionLog(path: options.connectionLogPath),
            hub: ControlHub(), inspection: inspection, transparentHTTPPort: options.transparentHTTPUpstreamPort,
            transparentTLSPort: options.transparentTLSUpstreamPort, transparentTCPUpstream: options.transparentTCPUpstream, logger: logger
        )
        if let localPorts, let applier {
            refresher = LocalPortRefresher(source: localPorts, applier: applier, log: logger)
        } else {
            refresher = nil
        }
    }

    /// The ports actually bound (useful when `options.ports` asked for ephemeral ones).
    public var boundPorts: ProxyPorts { state.withLock { $0.bound } }

    /// Binds the control socket and every listener, then starts the refresh loop.
    @discardableResult
    public func start() async throws -> ProxyPorts {
        do {
            try runtime.inspection.reload()
        } catch {
            logger("inspection CA: \(error)")
        }
        let config = runtime.policy.snapshot.config
        let wanted = options.ports ?? config.network.ports
        let host = options.bindHost

        var channels: [Channel] = []
        do {
            channels.append(try await ControlServer.bind(path: options.socketPath, group: group, hub: runtime.hub, service: self))
            let explicit = try await ProxyListeners.bind(.explicitProxy, host: host, port: Int(wanted.explicitProxy), group: group, runtime: runtime)
            let http = try await ProxyListeners.bind(.transparentHTTP, host: host, port: Int(wanted.transparentHTTP), group: group, runtime: runtime)
            let tls = try await ProxyListeners.bind(.transparentTLS, host: host, port: Int(wanted.transparentTLS), group: group, runtime: runtime)
            let otherPorts = try await ProxyListeners.bind(.transparentTCP, host: host, port: Int(wanted.transparentTCP), group: group, runtime: runtime)
            channels += [explicit, http, tls, otherPorts]
            let dns = DNSService(runtime: runtime, upstream: try dnsUpstream())
            let (udp, tcp) = try await bindDNS(host: host, port: Int(wanted.dns), service: dns)
            channels += [udp, tcp]
            let dnsPort = udp.localAddress?.port ?? Int(wanted.dns)
            let bound = ProxyPorts(
                explicitProxy: Self.port(of: explicit), transparentHTTP: Self.port(of: http),
                transparentTLS: Self.port(of: tls), dns: UInt16(dnsPort), transparentTCP: Self.port(of: otherPorts)
            )
            state.withLock {
                $0.channels = channels
                $0.bound = bound
                $0.startedAt = Date()
            }
            logger(
                "listening on \(host): proxy \(bound.explicitProxy), http \(bound.transparentHTTP), tls \(bound.transparentTLS), tcp \(bound.transparentTCP), dns \(bound.dns); control \(options.socketPath)"
            )
        } catch {
            for channel in channels { try? await channel.close() }
            throw error
        }

        syncEnvironmentBlock(config)
        let loop = Task { [weak self] in
            while !Task.isCancelled {
                await self?.tick()
                try? await Task.sleep(nanoseconds: UInt64((self?.options.refreshInterval ?? 5) * 1_000_000_000))
            }
        }
        state.withLock { $0.loop = loop }
        return boundPorts
    }

    /// Closes every listener and resolves pending asks with `deny`.
    public func stop() async {
        let (channels, loop) = state.withLock { s -> ([Channel], Task<Void, Never>?) in
            defer {
                s.channels = []
                s.loop = nil
            }
            return (s.channels, s.loop)
        }
        loop?.cancel()
        await runtime.asks.cancelAll()
        for channel in channels { try? await channel.close() }
        runtime.log.close()
        if FileManager.default.fileExists(atPath: options.socketPath) { try? FileManager.default.removeItem(atPath: options.socketPath) }
        logger("stopped")
    }

    /// Re-reads the config, swaps the policy, reloads the CA and refreshes the `.zshenv` block.
    public func reload() throws {
        let config = try runtime.policy.reload()
        do {
            try runtime.inspection.reload()
        } catch {
            logger("inspection CA: \(error)")
        }
        syncEnvironmentBlock(config)
        logger("configuration reloaded (mode \(config.network.mode.rawValue), \(config.network.domainRules.count) rules)")
    }

    public func status() async -> NetdStatus {
        let config = runtime.policy.snapshot.config
        let counts = runtime.counters.snapshot
        let (bound, startedAt) = state.withLock { ($0.bound, $0.startedAt) }
        return NetdStatus(
            startedAt: startedAt, ports: bound, mode: config.network.mode, activeConnections: counts.active,
            allowedCount: counts.allowed, deniedCount: counts.denied, pendingAsks: await runtime.asks.pendingCount,
            inspectionEnabled: config.network.inspection.enabled, caFingerprint: runtime.inspection.fingerprint
        )
    }

    // MARK: ControlService

    func handle(_ request: ControlRequest, client: UUID) async -> ControlEvent {
        switch request {
        case .hello:
            return .hello(version: BundleIdentity.version)
        case .subscribe(let topics):
            runtime.hub.subscribe(client, topics: topics)
            return .ack
        case .status:
            return .status(await status())
        case .reloadConfig:
            do {
                try reload()
                return .ack
            } catch {
                return .error("\(error)")
            }
        case .answer(let answer):
            do {
                try await runtime.asks.answer(answer)
                return .ack
            } catch {
                return .error("\(error)")
            }
        case .recent(let limit):
            return .recent(runtime.log.recent(limit: limit))
        case .pendingAsks:
            return .pending(await runtime.asks.pendingRequests())
        }
    }

    // MARK: - Internals

    private func tick() async {
        let config = runtime.policy.snapshot.config
        await refresher?.tick(config: config)
        if runtime.hub.hasSubscribers(.status) {
            runtime.hub.publish(.status(await status()), topic: .status)
        }
    }

    /// Writes or removes the `.zshenv` block; a repeated failure is logged once.
    private func syncEnvironmentBlock(_ config: AppConfig) {
        guard options.manageEnvironmentBlock else { return }
        let message: String
        var isDirectory: ObjCBool = false
        if !FileManager.default.fileExists(atPath: options.sharedFiles.root, isDirectory: &isDirectory) || !isDirectory.boolValue {
            message = "sandbox .zshenv block skipped: shared workspace \(options.sharedFiles.root) does not exist"
        } else {
            do {
                let change = try SandboxEnvironmentBlock.apply(policy: config.network, paths: options.paths, shared: options.sharedFiles)
                if change != .unchanged { logger("sandbox .zshenv block \(change.rawValue)") }
                state.withLock { $0.environmentProblem = nil }
                return
            } catch {
                message = "sandbox .zshenv block: \(error)"
            }
        }
        let repeated = state.withLock { values -> Bool in
            defer { values.environmentProblem = message }
            return values.environmentProblem == message
        }
        if !repeated { logger(message) }
    }

    /// UDP and TCP on the same port. For an ephemeral port (0) the TCP side may collide; then try another.
    private func bindDNS(host: String, port: Int, service: DNSService) async throws -> (Channel, Channel) {
        var attempt = 0
        while true {
            let udp = try await DNSListeners.bindUDP(host: host, port: port, group: group, service: service)
            do {
                let tcp = try await DNSListeners.bindTCP(host: host, port: udp.localAddress?.port ?? port, group: group, service: service)
                return (udp, tcp)
            } catch {
                try? await udp.close()
                attempt += 1
                if port != 0 || attempt >= 10 { throw error }
            }
        }
    }

    private func dnsUpstream() throws -> DNSForwarding? {
        guard let text = options.upstreamDNS ?? DNSUpstream.systemResolver() else {
            logger("no upstream DNS server (none in /etc/resolv.conf); allowed queries answer SERVFAIL")
            return nil
        }
        guard let (host, port) = HostName.splitHostPort(text), AddressRange.parseAddress(host) != nil else {
            throw SandvaultError.invalidInput("upstream DNS '\(text)' is not an IP address")
        }
        return DNSUpstream(server: try SocketAddress(ipAddress: host, port: port ?? 53), group: group)
    }

    private static func port(of channel: Channel) -> UInt16 {
        UInt16(truncatingIfNeeded: channel.localAddress?.port ?? 0)
    }
}

private final class LockedState: @unchecked Sendable {
    struct Values {
        var channels: [Channel] = []
        var bound = ProxyPorts(explicitProxy: 0, transparentHTTP: 0, transparentTLS: 0, dns: 0, transparentTCP: 0)
        var startedAt = Date()
        var loop: Task<Void, Never>?
        var environmentProblem: String?
    }

    private let lock = NSLock()
    private var values = Values()

    func withLock<T>(_ body: (inout Values) -> T) -> T {
        lock.withLock { body(&values) }
    }
}
