import Foundation
import Observation
import SandvaultCore
import SandvaultNet

/// Network screen: the sandbox's sockets and traffic (lsof, nettop), and netd's live decisions grouped by host
/// with one-click rules.
@MainActor @Observable
public final class NetworkModel {
    public private(set) var sockets: [SandboxConnection] = []
    public private(set) var traffic: [ProcessTraffic] = []
    public private(set) var socketsError: UserMessage?
    public var hostFilter = ""
    public var deniedOnly = false
    public var message: UserMessage?

    @ObservationIgnored private let connections: ConnectionSource
    @ObservationIgnored private let netd: NetdLink
    @ObservationIgnored private let editor: ConfigEditor
    @ObservationIgnored private let clock: AppClock

    public init(connections: ConnectionSource, netd: NetdLink, editor: ConfigEditor, clock: AppClock) {
        self.connections = connections
        self.netd = netd
        self.editor = editor
        self.clock = clock
    }

    /// One lsof and one nettop sample; polled only while the network screen is visible.
    public func refreshSockets() async {
        do {
            sockets = try await connections.connections()
            socketsError = nil
        } catch {
            socketsError = UserMessage(error: error, action: "Read sockets")
        }
        traffic = (try? await connections.traffic(pids: nil)) ?? []
    }

    public var hostGroups: [HostGroup] {
        HostGroup.group(netd.records, filter: ConnectionFilter(deniedOnly: deniedOnly, host: hostFilter))
    }

    public var socketRows: [SocketRow] {
        sockets.enumerated()
            .map { SocketRow($0.element, index: $0.offset) }
            .sorted { ($0.isListening ? 0 : 1, $0.process, $0.localPort, $0.index) < ($1.isListening ? 0 : 1, $1.process, $1.localPort, $1.index) }
    }

    /// The rule that currently decides `host`, if one matches (exact > longer suffix > `*`).
    public func rule(for host: String) -> DomainRule? {
        let name = HostName.normalize(host)
        return editor.config.network.domainRules
            .compactMap { rule in (try? DomainPattern(rule.pattern)).map { (rule, $0) } }
            .filter { $0.1.matches(name) }
            .max { Self.specificity($0.1) < Self.specificity($1.1) }?.0
    }

    public func allowHost(_ host: String) async {
        await setRule(RegistrableDomain.rulePattern(for: host, scope: .host), .allow, verb: "Allowed")
    }

    /// `*.<registrable domain>`: subdomains and the apex.
    public func allowDomain(_ host: String) async {
        await setRule(RegistrableDomain.rulePattern(for: host, scope: .domain), .allow, verb: "Allowed")
    }

    public func deny(_ host: String) async {
        await setRule(RegistrableDomain.rulePattern(for: host, scope: .host), .deny, verb: "Denied")
    }

    private func setRule(_ pattern: String, _ action: DomainAction, verb: String) async {
        do {
            let now = clock.now()
            let edit = try await editor.edit { try $0.network.upsertDomainRule(pattern: pattern, action: action, now: now) }
            message = .success("\(verb) \(edit.value.pattern)", detail: netdReloadNote(edit.netdReloaded))
        } catch {
            message = UserMessage(error: error, action: "\(verb == "Allowed" ? "Allow" : "Deny") \(pattern)")
        }
    }

    private static func specificity(_ pattern: DomainPattern) -> Int {
        switch pattern {
        case .any: 0
        case .suffix(let base): 1 + base.split(separator: ".").count
        case .exact: 1_000
        }
    }
}

/// netd's decisions for one host.
public struct HostGroup: Identifiable, Sendable, Equatable {
    public var host: String
    public var ports: [UInt16]
    public var allowed: Int
    public var denied: Int
    public var lastSeen: Date
    public var lastDecision: ConnectionDecision
    public var processes: [String]
    public var bytesIn: Int64
    public var bytesOut: Int64
    public var inspected: Bool

    public var id: String { host }

    /// Newest activity first; `filter` as in `svctl netlog`.
    public static func group(_ records: [ConnectionRecord], filter: ConnectionFilter = ConnectionFilter()) -> [HostGroup] {
        var groups: [String: HostGroup] = [:]
        for record in records where filter.matches(record) {
            var group = groups[record.host] ?? HostGroup(
                host: record.host, ports: [], allowed: 0, denied: 0, lastSeen: record.timestamp, lastDecision: record.decision,
                processes: [], bytesIn: 0, bytesOut: 0, inspected: false
            )
            if let port = record.port, !group.ports.contains(port) { group.ports.append(port) }
            if record.decision.blocked { group.denied += 1 } else { group.allowed += 1 }
            if record.timestamp >= group.lastSeen {
                group.lastSeen = record.timestamp
                group.lastDecision = record.decision
            }
            if let process = record.process, !group.processes.contains(process) { group.processes.append(process) }
            group.bytesIn += record.bytesIn
            group.bytesOut += record.bytesOut
            group.inspected = group.inspected || record.inspected
            groups[record.host] = group
        }
        return groups.values
            .map { group in
                var sorted = group
                sorted.ports.sort()
                return sorted
            }
            .sorted { ($0.lastSeen, $1.host) > ($1.lastSeen, $0.host) }
    }
}

public struct SocketRow: Identifiable, Sendable, Equatable {
    public var pid: Int32
    public var process: String
    public var proto: TransportProtocol
    public var local: String
    public var localPort: UInt16
    public var remote: String
    public var state: String
    public var isListening: Bool
    /// Position in the lsof output; lsof can list identical sockets (unconnected UDP), so it keeps ids unique.
    public var index: Int

    public var id: Int { index }

    public init(_ connection: SandboxConnection, index: Int) {
        self.index = index
        pid = connection.pid
        process = connection.process
        proto = connection.proto
        local = Self.address(connection.localAddress, connection.localPort, connection.family)
        localPort = connection.localPort
        remote = connection.remoteAddress.map { Self.address($0, connection.remotePort ?? 0, connection.family) } ?? ""
        state = connection.state ?? ""
        isListening = connection.isListening
    }

    static func address(_ host: String, _ port: UInt16, _ family: AddressFamily) -> String {
        family == .ipv6 && host.contains(":") ? "[\(host)]:\(port)" : "\(host):\(port)"
    }
}
