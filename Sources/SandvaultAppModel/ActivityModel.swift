import Foundation
import Observation
import SandvaultCore
import SandvaultNet
import SandvaultObserve

/// Activity screen. Hosts: what the sandbox talks to, in one list. Host names come from netd (web and DNS in Watch,
/// Ask and Proxy only); direct connections from lsof show addresses only; ICMP tools come from the process list,
/// because no socket of the sandbox user carries them. Web traffic: one row per request netd saw (D42).
/// Files & programs has its own model (`FileActivityModel`).
@MainActor @Observable
public final class ActivityModel {
    public var page: ActivityPage = .hosts
    public var filter = ""
    public var message: UserMessage?

    /// Web traffic: matches host and path.
    public var webFilter = ""
    public var selectedRequestID: String?
    /// Bodies fetched for the detail pane, by `StoredContent.id`.
    public private(set) var contents: [UUID: ContentLoad] = [:]
    @ObservationIgnored private var contentOrder: [UUID] = []
    public static let contentCacheLimit = 40

    @ObservationIgnored private let network: NetworkModel
    @ObservationIgnored private let processes: ProcessesModel
    @ObservationIgnored private let netd: NetdLink
    @ObservationIgnored private let editor: ConfigEditor
    @ObservationIgnored private let clock: AppClock

    public init(network: NetworkModel, processes: ProcessesModel, netd: NetdLink, editor: ConfigEditor, clock: AppClock = .live) {
        self.network = network
        self.processes = processes
        self.netd = netd
        self.editor = editor
        self.clock = clock
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
        let failed = hosts.filter { $0.status == "Failed" }.count
        if failed > 0 { parts.append("\(failed) failed") }
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

    // MARK: Web traffic (D42, D43)

    public var webRows: [WebRequestRow] {
        WebRequestRow.rows(netd.records, filter: webFilter)
    }

    public var selectedRequest: WebRequestRow? {
        guard let id = selectedRequestID else { return nil }
        return WebRequestRow.rows(netd.records).first { $0.id == id }
    }

    /// `42 requests · 3 blocked · 5 encrypted`.
    public var webSummary: String {
        let rows = webRows
        var parts = [Format.count(rows.count, "request")]
        let blocked = rows.filter(\.blocked).count
        if blocked > 0 { parts.append("\(blocked) blocked") }
        let encrypted = rows.filter { $0.visibility == .encrypted }.count
        if encrypted > 0 { parts.append("\(encrypted) encrypted") }
        return parts.joined(separator: " · ")
    }

    public var inspectionEnabled: Bool { editor.config.network.inspection.enabled }

    /// Why the list may be short: netd not carrying the web, or requests not recorded.
    public var webHint: String? {
        let network = editor.config.network
        switch network.mode {
        case .off, .open: return "Web traffic is visible only when it goes through netd. Choose Watch on the Overview."
        case .blocked: return "The sandbox has no network."
        case .watch, .proxyOnly: break
        }
        if !netd.isConnected { return "sandvault-netd is not running: nothing is recorded." }
        if !network.recording.requests { return "Recording requests is off in Settings > Recording; only connections are listed." }
        return nil
    }

    /// Shows only the requests to `host`.
    public func showAll(from host: String) {
        webFilter = host
        selectedRequestID = nil
    }

    public func content(_ meta: StoredContent) -> ContentLoad? {
        contents[meta.id]
    }

    /// Fetches a body from netd once; a failed fetch is tried again on the next call.
    public func loadContent(_ meta: StoredContent) async {
        switch contents[meta.id] {
        case .loading?, .text?, .binary?: return
        case .failed?, nil: break
        }
        store(.loading, for: meta.id)
        do {
            let (stored, data) = try await netd.content(id: meta.id)
            store(ContentLoad.make(stored, data), for: meta.id)
        } catch {
            store(.failed(Self.contentError(error)), for: meta.id)
        }
    }

    static func contentError(_ error: Error) -> String {
        switch error as? SandvaultError {
        case .notImplemented?: return "This netd does not keep contents yet."
        case .notInstalled?: return "sandvault-netd is not running."
        default: return UserMessage.describe(error)
        }
    }

    private func store(_ load: ContentLoad, for id: UUID) {
        if contents[id] == nil { contentOrder.append(id) }
        contents[id] = load
        while contentOrder.count > Self.contentCacheLimit {
            contents[contentOrder.removeFirst()] = nil
        }
    }

    /// Copy as curl, with the request body when it was kept as text and is loaded.
    public func curl(_ row: WebRequestRow) -> String? {
        var body: String?
        if let meta = row.summary?.requestContent, case .text(_, let text)? = contents[meta.id] { body = text }
        return row.curl(body: body)
    }

    /// `Blocked by your rule Deny example.com. Nothing left the Mac.`
    public func blockedNote(_ row: WebRequestRow) -> String? {
        guard row.blocked else { return nil }
        switch row.decision {
        case .askedDenied: return "You denied it when asked. Nothing left the Mac."
        case .timedOut: return "Nobody answered the request in time. Nothing left the Mac."
        case .denied, .allowed, .askedAllowed: break
        }
        if let id = row.ruleID, let rule = editor.config.network.domainRules.first(where: { $0.id == id }) {
            return "Blocked by your rule \(rule.action.displayName) \(rule.displayPattern). Nothing left the Mac."
        }
        return "Blocked by the default for unknown hosts. Nothing left the Mac."
    }

    /// For an encrypted row: what netd saw and how to see more.
    public func encryptedNote(_ row: WebRequestRow) -> String {
        let seen = "This connection was encrypted end to end. Sandvault saw the name \(row.host), how much went back and forth and how long it took."
        if !inspectionEnabled { return seen + " Turn on Look inside HTTPS to see the requests." }
        if canInspect(row.host) { return seen + " Look inside this host to see its requests from the next connection on." }
        return seen + " Look inside HTTPS is on, but no rule for this host has Inspect (Firewall & Proxy)."
    }

    /// Inspection is on and a rule for `host` could get Inspect: an existing rule, or in Watch a new allow rule
    /// (Watch allows everything anyway, so the new rule changes nothing but the inspection).
    public func canInspect(_ host: String) -> Bool {
        guard inspectionEnabled else { return false }
        if let rule = network.rule(for: host), rule.pattern != "*" { return !rule.inspect }
        return editor.config.network.mode == .watch
    }

    /// Turns on Inspect for the rule that decides `host` (or a new exact allow rule in Watch).
    public func inspect(_ host: String) async {
        guard canInspect(host) else { return }
        let existing = network.rule(for: host).flatMap { $0.pattern == "*" ? nil : $0 }
        let pattern = existing?.pattern ?? RegistrableDomain.rulePattern(for: host, scope: .host)
        let action = existing?.action ?? .allow
        let now = clock.now()
        do {
            let edit = try await editor.edit { config in
                try config.network.upsertDomainRule(pattern: pattern, action: action, inspect: true, now: now, port: existing?.port)
            }
            message = .success("Looking inside \(edit.value.pattern)", detail: netdReloadNote(edit.netdReloaded))
        } catch {
            message = UserMessage(error: error, action: "Inspect \(host)")
        }
    }
}

/// The three views of the Activity page.
public enum ActivityPage: String, CaseIterable, Identifiable, Sendable {
    case hosts, web, files

    public var id: String { rawValue }

    public var title: String {
        switch self {
        case .hosts: "Hosts"
        case .web: "Web traffic"
        case .files: "Files & programs"
        }
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
        let failed = !blocked && group.lastError != nil
        if failed, let error = group.lastError { parts.append(error) }
        self.init(
            kind: .host, title: group.host, detail: parts.joined(separator: " · "),
            status: blocked ? "Blocked" : failed ? "Failed" : "Allowed",
            tint: blocked ? .red : failed ? .orange : .green, host: group.host, blocked: blocked, lastSeen: group.lastSeen
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

    /// How the menu bar window names the state this level puts the sandbox in.
    public var statusWord: String {
        switch self {
        case .off: "Unprotected"
        case .watch: "Watching"
        case .ask: "Asking"
        case .blockAll: "Network blocked"
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
