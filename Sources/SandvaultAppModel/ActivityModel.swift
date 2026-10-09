import Foundation
import Observation
import SandvaultCore
import SandvaultObserve

/// Activity screen: what the sandbox talks to, in one list. Host names come from netd (web and DNS in Watch, Ask
/// and Proxy only); direct connections from lsof show addresses only; ICMP tools come from the process list,
/// because no socket of the sandbox user carries them.
@MainActor @Observable
public final class ActivityModel {
    public var filter = ""
    public var message: UserMessage?

    @ObservationIgnored private let network: NetworkModel
    @ObservationIgnored private let processes: ProcessesModel
    @ObservationIgnored private let netd: NetdLink
    @ObservationIgnored private let editor: ConfigEditor

    public init(network: NetworkModel, processes: ProcessesModel, netd: NetdLink, editor: ConfigEditor) {
        self.network = network
        self.processes = processes
        self.netd = netd
        self.editor = editor
    }

    /// One lsof and one nettop sample; polled while the screen is visible.
    public func refresh() async {
        await network.refreshSockets()
    }

    public var items: [ActivityItem] {
        let mode = editor.config.network.mode
        let all = ActivityItem.icmp(ICMPActivity.find(in: processes.snapshot?.processes ?? []))
            + HostGroup.group(netd.records).map(ActivityItem.init(host:))
            + ActivityItem.direct(network.sockets, skippingWeb: mode.needsNetd)
        let wanted = filter.trimmingCharacters(in: .whitespaces).lowercased()
        return wanted.isEmpty ? all : all.filter { $0.title.lowercased().contains(wanted) || $0.detail.lowercased().contains(wanted) }
    }

    /// `12 hosts · 2 blocked · 1 direct connection · 1 ping`.
    public var summary: String {
        let items = items
        let hosts = items.filter { $0.kind == .host }
        var parts = [Format.count(hosts.count, "host")]
        let blocked = hosts.filter(\.blocked).count
        if blocked > 0 { parts.append("\(blocked) blocked") }
        let direct = items.filter { $0.kind == .direct }.count
        if direct > 0 { parts.append(Format.count(direct, "direct connection")) }
        let icmp = items.filter { $0.kind == .icmp }.count
        if icmp > 0 { parts.append(Format.count(icmp, "ping or traceroute", plural: "pings or traceroutes")) }
        return parts.joined(separator: " · ")
    }

    /// Why host names may be missing, or `nil` when netd sees the sandbox's web and DNS traffic.
    public var hint: String? {
        let mode = editor.config.network.mode
        switch mode {
        case .off, .open:
            return "Only addresses are visible. Choose Watch on the Overview to see the host names the sandbox uses."
        case .blocked:
            return "The sandbox has no network."
        case .watch, .proxyOnly:
            return netd.isConnected ? nil : "sandvault-netd is not running: the sandbox's web and DNS fail and nothing is logged."
        }
    }

    /// Allows the host's registrable domain (`*.<domain>`).
    public func allow(_ host: String) async {
        await network.allowDomain(host)
        takeMessage()
    }

    /// Denies exactly this host name.
    public func block(_ host: String) async {
        await network.deny(host)
        takeMessage()
    }

    private func takeMessage() {
        message = network.message
        network.message = nil
    }
}

/// One line of the Activity screen.
public struct ActivityItem: Identifiable, Sendable, Equatable {
    public enum Kind: String, Sendable {
        /// A host name netd saw (web, DNS).
        case host
        /// A connection that did not go through netd: address and port only.
        case direct
        /// `ping` or `traceroute`: ICMP, no socket and no firewall rule for it.
        case icmp
    }

    public var kind: Kind
    public var title: String
    public var detail: String
    public var status: String
    public var tint: Tint
    /// Host name for Allow and Block; `nil` for direct connections and ICMP.
    public var host: String?
    public var blocked: Bool
    public var lastSeen: Date?

    public var id: String { "\(kind.rawValue) \(title)" }

    public init(kind: Kind, title: String, detail: String, status: String, tint: Tint, host: String? = nil, blocked: Bool = false, lastSeen: Date? = nil) {
        self.kind = kind
        self.title = title
        self.detail = detail
        self.status = status
        self.tint = tint
        self.host = host
        self.blocked = blocked
        self.lastSeen = lastSeen
    }

    init(host group: HostGroup) {
        var parts = group.processes.isEmpty ? [] : [group.processes.joined(separator: ", ")]
        let count = group.allowed + group.denied
        parts.append(Format.count(count, "request"))
        if group.bytesIn + group.bytesOut > 0 { parts.append("\(Format.bytes(group.bytesIn)) in, \(Format.bytes(group.bytesOut)) out") }
        let blocked = group.lastDecision.blocked
        self.init(
            kind: .host, title: group.host, detail: parts.joined(separator: " · "), status: blocked ? "Blocked" : "Allowed",
            tint: blocked ? .red : .green, host: group.host, blocked: blocked, lastSeen: group.lastSeen
        )
    }

    static func icmp(_ activity: [ICMPActivity]) -> [ActivityItem] {
        activity.map { tool in
            ActivityItem(
                kind: .icmp, title: "\(tool.tool) \(tool.target ?? "")".trimmingCharacters(in: .whitespaces),
                detail: "ICMP, running \(Format.duration(tool.elapsedSeconds)) · the firewall cannot filter it",
                status: "Running", tint: .orange
            )
        }
    }

    /// Outgoing sockets grouped by destination. Loopback is left out (netd, the sandbox's own servers); with
    /// `skippingWeb`, so are 80, 443 and 53, which pf hands to netd although the socket still names the address.
    static func direct(_ sockets: [SandboxConnection], skippingWeb: Bool) -> [ActivityItem] {
        var groups: [String: (proto: TransportProtocol, processes: [String])] = [:]
        var order: [String] = []
        for socket in sockets where !socket.isListening {
            guard let address = socket.remoteAddress, let port = socket.remotePort, !Self.isLoopback(address) else { continue }
            if skippingWeb && [53, 80, 443].contains(port) { continue }
            let key = SocketRow.address(address, port, socket.family)
            if groups[key] == nil { order.append(key) }
            var entry = groups[key] ?? (socket.proto, [])
            if !entry.processes.contains(socket.process) { entry.processes.append(socket.process) }
            groups[key] = entry
        }
        return order.map { key in
            let entry = groups[key]!
            return ActivityItem(
                kind: .direct, title: key,
                detail: "\(entry.processes.joined(separator: ", ")) · \(entry.proto.displayName), not through netd, so no host name",
                status: "Direct", tint: .gray
            )
        }
    }

    static func isLoopback(_ address: String) -> Bool {
        PrivateNetworks.loopback.contains { $0.contains(address) }
    }
}

/// The four protection levels the simple window offers; each sets the firewall mode (and for Ask netd's default).
public enum ProtectionLevel: String, CaseIterable, Identifiable, Sendable {
    case off, watch, ask, blockAll

    public var id: String { rawValue }

    public var title: String {
        switch self {
        case .off: "Off"
        case .watch: "Watch"
        case .ask: "Ask"
        case .blockAll: "Block All"
        }
    }

    public var explanation: String {
        switch self {
        case .off: "The sandbox reaches the network directly. Only addresses are visible."
        case .watch: "Everything is allowed. Every website and DNS name the sandbox uses appears under Activity."
        case .ask: "A website the sandbox has not used before waits for your answer. Other ports stay closed."
        case .blockAll: "The sandbox has no network. Running programs keep running."
        }
    }

    /// The level the policy matches, `nil` for a combination only expert mode sets (Open, Proxy only with a
    /// default other than Ask).
    public static func current(_ policy: NetworkPolicy) -> ProtectionLevel? {
        switch policy.mode {
        case .off: .off
        case .watch: .watch
        case .proxyOnly: policy.defaultAction == .ask ? .ask : nil
        case .blocked: .blockAll
        case .open: nil
        }
    }

    public func apply(to policy: inout NetworkPolicy) {
        switch self {
        case .off: policy.mode = .off
        case .watch: policy.mode = .watch
        case .ask:
            policy.mode = .proxyOnly
            policy.defaultAction = .ask
        case .blockAll: policy.mode = .blocked
        }
    }
}
