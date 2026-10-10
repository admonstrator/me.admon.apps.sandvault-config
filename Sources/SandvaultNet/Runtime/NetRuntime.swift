import Foundation
import NIOCore
import SandvaultCore

/// What the gate decided for one connection or DNS-free proxy request.
struct GateResult: Sendable {
    enum Verdict: Sendable { case allow, deny, fail }

    var verdict: Verdict
    var host: String
    var port: UInt16
    /// Where to connect (filtered for private destinations), when allowed.
    var addresses: [SocketAddress] = []
    var inspect = false
    var decision: ConnectionDecision
    var ruleID: UUID?
    var reason: String
    var owner: ProcessOwner?
}

/// Shared state of the listeners: policy, asks, resolution, attribution, logging, kept contents and TLS material.
final class NetRuntime: Sendable {
    let policy: PolicyStore
    let asks: AskCoordinator
    let resolver: HostResolver
    let attributor: ProcessAttributor
    let log: ConnectionLog
    /// Request and response bodies kept with `WebRecordingSettings.contents` (D43).
    let contents: ContentStore
    let hub: ControlHub
    let counters = NetdCounters()
    let inspection: InspectionService
    /// Upstream ports of the transparent listeners (80 and 443 in production).
    let transparentHTTPPort: Int
    let transparentTLSPort: Int
    /// Where the transparent TCP listener connects instead of the original destination (tests only).
    let transparentTCPUpstream: SocketAddress?
    let logger: @Sendable (String) -> Void

    init(
        policy: PolicyStore, resolver: HostResolver, attributor: ProcessAttributor, log: ConnectionLog, contents: ContentStore, hub: ControlHub,
        inspection: InspectionService, transparentHTTPPort: Int, transparentTLSPort: Int, enricher: AskEnriching = NoAskEnrichment(),
        transparentTCPUpstream: SocketAddress? = nil, logger: @escaping @Sendable (String) -> Void
    ) {
        self.policy = policy
        self.resolver = resolver
        self.attributor = attributor
        self.log = log
        self.contents = contents
        self.hub = hub
        self.inspection = inspection
        self.transparentHTTPPort = transparentHTTPPort
        self.transparentTLSPort = transparentTLSPort
        self.transparentTCPUpstream = transparentTCPUpstream
        self.logger = logger
        asks = AskCoordinator(
            hub: hub,
            persist: { pattern, port, action in try policy.persistRule(pattern: pattern, port: port, action: action) },
            log: logger,
            enricher: enricher
        )
    }

    /// Policy, ask, resolution and private-destination check for a proxied connection to `host:port`.
    /// `hint` is what the listener saw (original address, server name, protocol); it goes to the ask's details.
    /// With `destination` (an IP literal) the connection goes there, the address the program chose, instead of to a
    /// resolution of `host`; the private-destination guard still applies.
    func authorize(
        host rawHost: String, port: UInt16, kind: ConnectionKind, clientPort: UInt16?, hint: ConnectionHint = ConnectionHint(),
        destination: String? = nil
    ) async -> GateResult {
        let host = HostName.normalize(rawHost)
        let snapshot = policy.snapshot
        let engine = snapshot.engine
        async let attributed = owner(ofPort: clientPort, proto: .tcp)
        let verdict = engine.evaluate(host: host, port: port)
        var result = GateResult(verdict: .deny, host: host, port: port, decision: .denied, ruleID: verdict.rule?.id, reason: verdict.reason)

        switch verdict.action {
        case .deny:
            result.owner = await attributed
            return result
        case .allow:
            result.decision = .allowed
        case .ask:
            let owner = await attributed
            result.owner = owner
            let resolution = await asks.decide(host: host, port: port, kind: kind, owner: owner, policy: snapshot.policy, hint: hint)
            result.decision = resolution.decision
            result.reason = resolution.reason
            guard resolution.allowed else { return result }
        }
        result.owner = await attributed
        result.inspect = verdict.inspect && inspection.isAvailable

        if let destination {
            if engine.refusesDestination(destination) {
                result.decision = .denied
                result.reason = "\(destination) is a private destination"
                return result
            }
            guard let address = try? SocketAddress(ipAddress: destination, port: Int(port)) else {
                result.verdict = .fail
                result.reason = "invalid address \(destination)"
                return result
            }
            result.addresses = [address]
        } else if let override = engine.override(for: host) {
            // An explicit override is the user's choice and exempt from the private-destination guard.
            guard let address = try? SocketAddress(ipAddress: override.address, port: Int(port)) else {
                result.verdict = .fail
                result.reason = "override \(override.pattern) has an invalid address"
                return result
            }
            result.addresses = [address]
        } else if HostName.isIPLiteral(host) {
            if engine.refusesDestination(host) {
                result.decision = .denied
                result.reason = "\(host) is a private destination"
                return result
            }
            guard let address = try? SocketAddress(ipAddress: host, port: Int(port)) else {
                result.verdict = .fail
                result.reason = "invalid address \(host)"
                return result
            }
            result.addresses = [address]
        } else {
            let resolved: [SocketAddress]
            do {
                resolved = try await resolver.resolve(host: host, port: Int(port))
            } catch {
                result.verdict = .fail
                result.reason = "\(error)"
                return result
            }
            let usable = resolved.filter { !engine.refusesDestination($0.ipAddress ?? "") }
            guard !usable.isEmpty else {
                result.decision = .denied
                let list = resolved.compactMap(\.ipAddress).joined(separator: ", ")
                result.reason = "\(host) resolves only to private addresses (\(list))"
                return result
            }
            result.addresses = usable
        }
        result.verdict = .allow
        return result
    }

    func owner(ofPort port: UInt16?, proto: TransportProtocol) async -> ProcessOwner? {
        guard let port else { return nil }
        return await attributor.process(forLocalPort: port, proto: proto).map { ProcessOwner(pid: $0.pid, name: $0.name) }
    }

    /// The address and port the sandbox socket on `port` connects to (the destination before pf's `rdr`).
    func originalDestination(ofPort port: UInt16?, proto: TransportProtocol) async -> (address: String, port: UInt16)? {
        guard let port else { return nil }
        return await attributor.destination(forLocalPort: port, proto: proto)
    }

    /// A tracker whose record goes to the log, the subscribers and the counters when finished.
    func track(_ result: GateResult, kind: ConnectionKind) -> ConnectionTracker {
        counters.opened()
        let record = ConnectionRecord(
            kind: kind, host: result.host, port: result.port, decision: result.decision, ruleID: result.ruleID,
            pid: result.owner?.pid, process: result.owner?.name
        )
        return ConnectionTracker(record: record) { [self] record in
            counters.closed()
            self.record(record)
        }
    }

    func record(_ record: ConnectionRecord) {
        if let error = record.error {
            logger("\(record.kind.rawValue) \(record.host)\(record.port.map { ":\($0)" } ?? ""): \(error)")
        }
        counters.count(record.decision)
        log.append(record)
        if let error = log.takeError() { logger("connection log: \(error)") }
        hub.publish(.connection(record), topic: .connections)
    }

    /// The one-line body of a 403: what was blocked, why, and how to allow it.
    static func denialMessage(_ result: GateResult) -> String {
        let target = result.port == 0 ? result.host : "\(result.host):\(result.port)"
        return "sandvault-config blocked \(target): \(result.reason). To allow it: svctl proxy allow \(result.host)\n"
    }
}
