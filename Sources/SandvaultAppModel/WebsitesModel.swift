import Foundation
import Observation
import SandvaultCore
import SandvaultNet

/// Websites page (D53): every website the sandbox used, in one list, with what decides it now (your rule, developer
/// basics, the protection level, a waiting ask), and the user's own domain rules. Records come from netd.
@MainActor @Observable
public final class WebsitesModel {
    public var search = ""
    public var filter: WebsiteFilter = .all
    public var message: UserMessage?

    @ObservationIgnored private let netd: NetdLink
    @ObservationIgnored private let editor: ConfigEditor
    @ObservationIgnored private let asks: AsksModel
    @ObservationIgnored private let clock: AppClock

    public init(netd: NetdLink, editor: ConfigEditor, asks: AsksModel, clock: AppClock = .live) {
        self.netd = netd
        self.editor = editor
        self.asks = asks
        self.clock = clock
    }

    // MARK: List

    /// Every website, waiting ones first, then newest first; neither filtered nor searched.
    public var allRows: [WebsiteRow] {
        WebsiteRow.rows(netd.records, pending: netd.pendingAsks, policy: editor.config.network)
    }

    /// The rows the filter and the search leave.
    public var rows: [WebsiteRow] {
        let wanted = search.trimmingCharacters(in: .whitespaces).lowercased()
        return allRows.filter { row in
            filter.includes(row) && (wanted.isEmpty || row.matches(wanted))
        }
    }

    /// `12 websites · 2 blocked · 1 waiting`.
    public var summary: String {
        let rows = allRows
        var parts = [Format.count(rows.count, "website")]
        let blocked = rows.filter(\.isBlocked).count
        if blocked > 0 { parts.append("\(blocked) blocked") }
        let waiting = rows.filter { $0.state == .waiting }.count
        if waiting > 0 { parts.append("\(waiting) waiting") }
        return parts.joined(separator: " · ")
    }

    /// One line in plain words: what Allow and Block do, and what happens to a website without a choice.
    public var hint: String {
        let network = editor.config.network
        switch network.mode {
        case .off, .open:
            return "Protection is off, so websites are not listed. Choose Watch or Ask on Home."
        case .blocked:
            return "The sandbox is offline. Allow and Block apply once it is back online."
        case .watch, .proxyOnly:
            break
        }
        if !netd.isConnected { return "sandvault-netd is not running, so no websites are listed and the sandbox has no web access." }
        if network.mode == .watch {
            return "Watch lets every website through. Block stops one now; Allow keeps it working when you switch to Ask."
        }
        switch network.defaultAction {
        case .ask: return "Allow and Block are remembered. A website without a choice waits for your answer."
        case .allow: return "Allow and Block are remembered. A website without a choice is allowed."
        case .deny: return "Allow and Block are remembered. A website without a choice is blocked."
        }
    }

    // MARK: Developer basics

    /// `GitHub, npm, Python packages and 5 more`; `nil` when developer basics are off.
    public var basicsSummary: String? {
        let groups = editor.config.network.developerBasics.activeGroups
        guard !groups.isEmpty else { return nil }
        let shown = groups.prefix(3).map(\.title).joined(separator: ", ")
        return groups.count > 3 ? "\(shown) and \(groups.count - 3) more" : shown
    }

    // MARK: Allow and block

    /// A waiting website is answered with a rule (netd saves it); any other gets a rule from here: the rule that
    /// decides it now flips when that changes the outcome, else `*.<domain>` is allowed.
    public func allow(_ row: WebsiteRow) async {
        if await answerWaiting(row, allow: true) { return }
        await save(row, allow: true)
    }

    /// Blocks exactly this website: its own exact rule flips, else an exact deny rule is added (it beats `*.domain`).
    public func block(_ row: WebsiteRow) async {
        if await answerWaiting(row, allow: false) { return }
        await save(row, allow: false)
    }

    /// The pattern and port `allow` or `block` would save for `row`.
    public func ruleTarget(for row: WebsiteRow, allow: Bool) -> (pattern: String, port: UInt16?) {
        let host = HostName.normalize(row.host)
        let deciding = PolicyEngine(policy: editor.config.network).rule(for: host, port: row.lastPort)
        let wanted: DomainAction = allow ? .allow : .deny
        if let rule = deciding, rule.pattern != "*", rule.action != wanted, allow || rule.pattern == host {
            return (rule.pattern, rule.port)
        }
        return (RegistrableDomain.rulePattern(for: host, scope: allow ? .domain : .host), nil)
    }

    private func answerWaiting(_ row: WebsiteRow, allow: Bool) async -> Bool {
        let waiting = asks.pending.filter { HostName.normalize($0.host) == HostName.normalize(row.host) }
        guard !waiting.isEmpty else { return false }
        for ask in waiting {
            await asks.answer(ask, allow ? .allowAlways : .denyAlways)
        }
        message = asks.message
        asks.message = nil
        return true
    }

    private func save(_ row: WebsiteRow, allow: Bool) async {
        let target = ruleTarget(for: row, allow: allow)
        let action: DomainAction = allow ? .allow : .deny
        let verb = allow ? "Allowed" : "Blocked"
        let now = clock.now()
        do {
            let edit = try await editor.edit { config in
                try config.network.upsertDomainRule(pattern: target.pattern, action: action, now: now, port: target.port)
            }
            message = .success("\(verb) \(edit.value.displayPattern)", detail: netdReloadNote(edit.netdReloaded))
        } catch {
            message = UserMessage(error: error, action: "\(allow ? "Allow" : "Block") \(row.host)")
        }
    }

    // MARK: Your rules

    /// The user's own domain rules, in the order config.json keeps them.
    public var rules: [DomainRule] { editor.config.network.domainRules }

    public func removeRule(_ rule: DomainRule) async {
        do {
            let edit = try await editor.edit { config -> Bool in
                let before = config.network.domainRules.count
                config.network.domainRules.removeAll { $0.id == rule.id }
                return config.network.domainRules.count < before
            }
            message = edit.value
                ? .success("Removed \(rule.displayPattern)", detail: netdReloadNote(edit.netdReloaded))
                : .info("\(rule.displayPattern) was already removed")
        } catch {
            message = UserMessage(error: error, action: "Remove \(rule.displayPattern)")
        }
    }
}

/// The filter of the Websites page.
public enum WebsiteFilter: String, CaseIterable, Identifiable, Sendable {
    case all, allowed, blocked

    public var id: String { rawValue }

    public var title: String {
        switch self {
        case .all: "All"
        case .allowed: "Allowed"
        case .blocked: "Blocked"
        }
    }

    public var symbolName: String {
        switch self {
        case .all: "globe"
        case .allowed: "checkmark.circle"
        case .blocked: "hand.raised"
        }
    }

    /// Waiting websites show only under All.
    public func includes(_ row: WebsiteRow) -> Bool {
        switch self {
        case .all: true
        case .allowed: row.isAllowed
        case .blocked: row.isBlocked
        }
    }
}

/// What decides a website now.
public enum WebsiteState: String, CaseIterable, Sendable {
    /// A request waits for your answer.
    case waiting
    /// Your allow rule.
    case allowedByYou
    /// A developer basics group, no rule of yours.
    case allowedByBasics
    /// Allowed by the protection level (Watch, or a default of Allow).
    case allowed
    /// Answered once (or not in time); it asks again next time.
    case asked
    /// Your deny rule, or the protection level.
    case blocked

    public var title: String {
        switch self {
        case .waiting: "Waiting"
        case .allowedByYou: "Allowed by you"
        case .allowedByBasics: "Developer basics"
        case .allowed: "Allowed"
        case .asked: "Asked"
        case .blocked: "Blocked"
        }
    }

    public var symbolName: String {
        switch self {
        case .waiting: "clock"
        case .allowedByYou: "checkmark.circle.fill"
        case .allowedByBasics: "checkmark.seal.fill"
        case .allowed: "checkmark.circle"
        case .asked: "questionmark.circle"
        case .blocked: "hand.raised.fill"
        }
    }

    public var tint: Tint {
        switch self {
        case .waiting: .orange
        case .allowedByYou, .allowedByBasics, .allowed: .green
        case .asked: .blue
        case .blocked: .red
        }
    }
}

/// One website of the Websites page: netd's records for one host name, and what decides it now.
public struct WebsiteRow: Identifiable, Sendable, Equatable {
    public var host: String
    public var state: WebsiteState
    /// Programs that used it, first seen first.
    public var processes: [String]
    public var lastSeen: Date
    /// Connections and lookups netd recorded.
    public var count: Int
    public var ports: [UInt16]
    /// Addresses DNS answered for it.
    public var addresses: [String]
    /// Only DNS lookups, no connection.
    public var lookupOnly: Bool
    public var lastDecision: ConnectionDecision
    /// The port of the newest connection; `nil` when only looked up.
    public var lastPort: UInt16?
    /// Your rule that decides it, if one does.
    public var rule: DomainRule?
    /// The developer basics group that allows it, when no rule of yours decides it.
    public var basics: DeveloperBasicsGroup?

    public var id: String { host }

    /// Allowed now or the last time; the Allowed filter.
    public var isAllowed: Bool {
        switch state {
        case .allowedByYou, .allowedByBasics, .allowed: true
        case .asked: !lastDecision.blocked
        case .waiting, .blocked: false
        }
    }

    /// Blocked now or the last time; the Blocked filter.
    public var isBlocked: Bool {
        switch state {
        case .blocked: true
        case .asked: lastDecision.blocked
        case .waiting, .allowedByYou, .allowedByBasics, .allowed: false
        }
    }

    /// Allow would change something: not already allowed by a rule of yours or by developer basics.
    public var canAllow: Bool { state != .allowedByBasics && rule?.action != .allow }

    /// Block would change something: no deny rule of yours decides it yet.
    public var canBlock: Bool { rule?.action != .deny }

    func matches(_ lowercased: String) -> Bool {
        host.lowercased().contains(lowercased) || processes.contains { $0.lowercased().contains(lowercased) }
    }

    /// `node, git · 12 times`; from Advanced with the ports, in Expert also the addresses.
    public func detail(mode: InterfaceMode) -> String {
        var parts: [String] = []
        if lookupOnly { parts.append("Looked up only") }
        if !processes.isEmpty { parts.append(processes.joined(separator: ", ")) }
        parts.append(Format.count(count, "time"))
        if mode >= .advanced, !ports.isEmpty {
            parts.append((ports.count == 1 ? "port " : "ports ") + ports.map(String.init).joined(separator: ", "))
        }
        if mode == .expert, !addresses.isEmpty {
            let shown = addresses.prefix(2).joined(separator: ", ")
            parts.append(addresses.count > 2 ? "\(shown) +\(addresses.count - 2)" : shown)
        }
        return parts.joined(separator: " · ")
    }

    /// Why it has its state, in one sentence. Easy names a rule without its port.
    public func note(mode: InterfaceMode) -> String {
        let pattern = rule.map { mode == .easy ? $0.pattern : $0.displayPattern }
        switch state {
        case .waiting: return "Waiting for your answer."
        case .allowedByYou: return "You allowed \(pattern ?? host)."
        case .allowedByBasics: return "Part of developer basics (\(basics?.title ?? "developer basics"))."
        case .allowed: return "Allowed by your protection level."
        case .asked:
            switch lastDecision {
            case .askedAllowed: return "You allowed it once. It asks again next time."
            case .askedDenied: return "You denied it once. It asks again next time."
            case .timedOut: return "Nobody answered in time, so it was blocked. It asks again next time."
            case .allowed, .denied: return "It asks again next time."
            }
        case .blocked:
            if let pattern, rule?.action == .deny { return "You blocked \(pattern)." }
            return "Blocked by your protection level."
        }
    }

    /// Groups `records` by host and decides each one's state against `policy` and the waiting asks.
    public static func rows(_ records: [ConnectionRecord], pending: [AskRequest], policy: NetworkPolicy) -> [WebsiteRow] {
        let engine = PolicyEngine(policy: policy)
        let waiting = Set(pending.map { HostName.normalize($0.host) })
        var groups: [String: [ConnectionRecord]] = [:]
        for record in records {
            groups[HostName.normalize(record.host), default: []].append(record)
        }
        // A waiting host netd has no record of yet still belongs in the list.
        for host in waiting where groups[host] == nil {
            groups[host] = []
        }
        var rows: [WebsiteRow] = []
        for (host, list) in groups {
            let sorted = list.sorted { $0.timestamp < $1.timestamp }
            let ask = pending.first { HostName.normalize($0.host) == host }
            let newest = sorted.last
            var processes: [String] = []
            for name in sorted.compactMap(\.process) + [ask?.process].compactMap({ $0 }) where !processes.contains(name) {
                processes.append(name)
            }
            var addresses: [String] = []
            for address in sorted.flatMap(\.dnsAnswers) where !addresses.contains(address) {
                addresses.append(address)
            }
            let connections = sorted.filter { $0.kind != .dns }
            let lastPort = connections.last?.port ?? (newest == nil ? ask?.port : nil)
            let ports = Array(Set(connections.compactMap(\.port) + [lastPort].compactMap { $0 })).sorted()
            let lastDecision = newest?.decision ?? .allowed

            let rule = engine.rule(for: host, port: lastPort)
            let basicsApply = lastPort.map(PolicyEngine.webPorts.contains) ?? true
            let group = rule == nil && basicsApply ? engine.basicsGroup(for: host) : nil
            let state: WebsiteState
            if waiting.contains(host) {
                state = .waiting
            } else if rule?.action == .allow {
                state = .allowedByYou
            } else if rule?.action == .deny {
                state = .blocked
            } else if group != nil {
                state = .allowedByBasics
            } else {
                switch lastDecision {
                case .askedAllowed, .askedDenied, .timedOut: state = .asked
                case .denied: state = .blocked
                case .allowed: state = .allowed
                }
            }
            rows.append(WebsiteRow(
                host: host, state: state, processes: processes, lastSeen: newest?.timestamp ?? ask?.createdAt ?? Date(timeIntervalSince1970: 0),
                count: sorted.count, ports: ports, addresses: addresses, lookupOnly: !sorted.isEmpty && connections.isEmpty,
                lastDecision: lastDecision, lastPort: lastPort, rule: rule, basics: group
            ))
        }
        return rows.sorted { lhs, rhs in
            let left = lhs.state == .waiting ? 0 : 1, right = rhs.state == .waiting ? 0 : 1
            if left != right { return left < right }
            if lhs.lastSeen != rhs.lastSeen { return lhs.lastSeen > rhs.lastSeen }
            return lhs.host < rhs.host
        }
    }
}

extension DomainRule {
    /// The rule as the Websites page lists it: `*` reads as every other website; Easy leaves out the port.
    public func websiteTitle(mode: InterfaceMode) -> String {
        if pattern == "*" { return "Every other website" }
        return mode == .easy ? pattern : displayPattern
    }

    /// What the pattern covers, in plain words.
    public var websiteScope: String {
        if pattern == "*" { return "Websites without a rule of their own" }
        if pattern.hasPrefix("*.") { return "\(pattern.dropFirst(2)) and every subdomain" }
        return "Only this website"
    }

    public var websiteActionTitle: String {
        switch action {
        case .allow: "Allowed"
        case .deny: "Blocked"
        case .ask: "Asks"
        }
    }

    public var websiteActionTint: Tint {
        switch action {
        case .allow: .green
        case .deny: .red
        case .ask: .orange
        }
    }
}
