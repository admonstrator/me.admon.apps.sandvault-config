import Foundation
import NIOCore
import NIOPosix
import NIOSSL
import SandvaultCore
@testable import SandvaultNet

/// A netd on ephemeral 127.0.0.1 ports with a temporary home, config, log and control socket.
struct TestNetd {
    let daemon: NetDaemon
    let layout: TempLayout
    let ports: ProxyPorts
    let socketPath: String
    let messages: Recorded<String>

    var store: ConfigStore { ConfigStore(paths: layout.paths) }

    static func start(
        _ config: AppConfig,
        resolver: HostResolver = StaticHostResolver([:]),
        attributor: ProcessAttributor = NoProcessAttributor(),
        upstreamDNS: String? = nil,
        transparentHTTPPort: Int = 80,
        transparentTLSPort: Int = 443,
        transparentTCPUpstream: SocketAddress? = nil,
        trustRoots: NIOSSLTrustRoots = .default,
        createCA: Bool = false
    ) async throws -> TestNetd {
        let layout = try TempLayout()
        try ConfigStore(paths: layout.paths).save(config)
        if createCA { _ = try CAStore(paths: layout.paths).loadOrCreate(hostUser: "alice") }
        // Short path: Unix socket paths are limited to 104 bytes on macOS.
        let socketPath = "/tmp/svn-\(UUID().uuidString.prefix(8)).sock"
        var options = NetdOptions(paths: layout.paths, socketPath: socketPath, upstreamDNS: upstreamDNS ?? "127.0.0.1:9")
        options.ports = ProxyPorts(explicitProxy: 0, transparentHTTP: 0, transparentTLS: 0, dns: 0, transparentTCP: 0)
        options.transparentHTTPUpstreamPort = transparentHTTPPort
        options.transparentTLSUpstreamPort = transparentTLSPort
        options.transparentTCPUpstream = transparentTCPUpstream
        options.upstreamTrustRoots = trustRoots
        options.manageEnvironmentBlock = false
        options.refreshInterval = 60
        let messages = Recorded<String>()
        let daemon = try NetDaemon(options: options, attributor: attributor, resolver: resolver, logger: { messages.append($0) })
        let ports = try await daemon.start()
        return TestNetd(daemon: daemon, layout: layout, ports: ports, socketPath: socketPath, messages: messages)
    }

    func stop() async {
        await daemon.stop()
        layout.cleanup()
    }

    /// Waits until a record matching `predicate` is in the ring buffer.
    func record(timeout: Double = 5, where predicate: (ConnectionRecord) -> Bool) async throws -> ConnectionRecord {
        let deadline = Date().addingTimeInterval(timeout)
        while Date() < deadline {
            if let match = daemon.runtime.log.recent(limit: 1000).last(where: predicate) { return match }
            try await Task.sleep(nanoseconds: 20_000_000)
        }
        throw SandvaultError.timedOut("no matching connection record; log: \(daemon.runtime.log.recent(limit: 20).map { "\($0.host) \($0.decision)" }) messages: \(messages.all)")
    }
}

/// Runs `body`, then `cleanup`, also when `body` throws (an async `defer`).
func withCleanup(_ cleanup: () async -> Void, _ body: () async throws -> Void) async throws {
    do {
        try await body()
    } catch {
        await cleanup()
        throw error
    }
    await cleanup()
}

/// A CA and TLS context for test origins (`upstream` side), separate from netd's inspection CA.
/// The CA lives in memory; its temporary directory is removed right away.
struct OriginTLS {
    let ca: InspectionCA
    let service: InspectionService

    init() throws {
        let directory = FileManager.default.temporaryDirectory.appendingPathComponent("origin-ca-\(UUID().uuidString)").path
        defer { try? FileManager.default.removeItem(atPath: directory) }
        let store = CAStore(directory: directory)
        ca = try store.loadOrCreate(hostUser: "origin-test").ca
        service = try InspectionService(store: store, upstreamTrustRoots: .default)
        try service.reload()
    }

    func serverContext(for host: String) throws -> NIOSSLContext {
        try service.serverContext(for: host)
    }

    var trustRoots: NIOSSLTrustRoots {
        get throws { .certificates([try NIOSSLCertificate(bytes: Array(ca.certificatePEM.utf8), format: .pem)]) }
    }

    func clientContext() throws -> NIOSSLContext {
        var configuration = TLSConfiguration.makeClientConfiguration()
        configuration.trustRoots = try trustRoots
        return try NIOSSLContext(configuration: configuration)
    }
}

extension AppConfig {
    /// A config with `rules`, the firewall in `proxyOnly` mode and private destinations allowed unless asked.
    static func testing(
        _ rules: [(String, DomainAction)] = [], inspect: Set<String> = [], overrides: [String: String] = [:],
        defaultAction: DomainAction = .ask, blockPrivate: Bool = false, askTimeout: Int = 30, inspection: Bool = false
    ) -> AppConfig {
        var config = AppConfig()
        config.network.mode = .proxyOnly
        config.network.defaultAction = defaultAction
        config.network.blockPrivateDestinations = blockPrivate
        config.network.askTimeoutSeconds = askTimeout
        config.network.inspection.enabled = inspection
        config.network.domainRules = rules.map { DomainRule(pattern: $0.0, action: $0.1, inspect: inspect.contains($0.0)) }
        config.network.dnsOverrides = overrides.sorted { $0.key < $1.key }.map { DnsOverride(pattern: $0.key, address: $0.value) }
        return config
    }
}

/// Attributes every port to one process and destination.
struct FixedAttributor: ProcessAttributor {
    var process: (pid: Int32, name: String)?
    var destination: (address: String, port: UInt16)?

    func process(forLocalPort port: UInt16, proto: TransportProtocol) async -> (pid: Int32, name: String)? { process }
    func destination(forLocalPort port: UInt16, proto: TransportProtocol) async -> (address: String, port: UInt16)? { destination }
}

/// Attributes every port to one process and to the destination set last (the next connection's original destination).
final class SwitchableAttributor: ProcessAttributor, @unchecked Sendable {
    private let lock = NSLock()
    private var current: (address: String, port: UInt16)?
    let process: (pid: Int32, name: String)?

    init(process: (pid: Int32, name: String)?, destination: (address: String, port: UInt16)?) {
        self.process = process
        current = destination
    }

    func set(_ destination: (address: String, port: UInt16)?) { lock.withLock { current = destination } }

    func process(forLocalPort port: UInt16, proto: TransportProtocol) async -> (pid: Int32, name: String)? { process }
    func destination(forLocalPort port: UInt16, proto: TransportProtocol) async -> (address: String, port: UInt16)? {
        lock.withLock { current }
    }
}
