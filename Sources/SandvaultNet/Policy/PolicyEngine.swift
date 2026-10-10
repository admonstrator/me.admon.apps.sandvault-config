import SandvaultCore

/// The outcome of matching one host and port against the network policy (before any ask or resolution).
public struct PolicyVerdict: Sendable, Equatable {
    public var action: DomainAction
    /// The rule that decided; `nil` for the default action and invalid hosts.
    public var rule: DomainRule?
    /// Decrypt this connection (the rule asks for it and inspection is enabled).
    public var inspect: Bool
    /// Human-readable cause, e.g. `rule *.example.com (deny)`.
    public var reason: String

    public init(action: DomainAction, rule: DomainRule?, inspect: Bool, reason: String) {
        self.action = action
        self.rule = rule
        self.inspect = inspect
        self.reason = reason
    }
}

/// Pure decision logic for proxy, transparent listeners and DNS.
///
/// Matching: an exact name beats `*.domain` (which also matches the apex), a longer suffix beats a shorter one,
/// `*` comes last; at equal specificity a rule with a port beats one without, then `deny` beats `allow` beats `ask`.
/// A rule with a port matches only that port (never DNS). No match yields `defaultAction`.
/// Ports other than 80 and 443 need an explicit `allow` rule and `ask` never applies to them, except in proxy-only
/// mode with `routeAllTCP` (D37): there every port follows the rules and the default action like the web ports.
/// In `FirewallMode.watch` only `deny` rules refuse; everything else is allowed, on every port.
public struct PolicyEngine: Sendable {
    public let policy: NetworkPolicy
    private let rules: [(pattern: DomainPattern, rule: DomainRule)]
    private let overrides: [(pattern: DomainPattern, override: DnsOverride)]

    public init(policy: NetworkPolicy) {
        self.policy = policy
        rules = policy.domainRules.compactMap { rule in (try? DomainPattern(rule.pattern)).map { ($0, rule) } }
        overrides = policy.dnsOverrides.compactMap { entry in
            guard AddressRange.parseAddress(entry.address) != nil, let pattern = try? DomainPattern(entry.pattern) else { return nil }
            return (pattern, entry)
        }
    }

    public static let webPorts: Set<UInt16> = [80, 443]

    /// Whether ports other than 80 and 443 follow the rules and the default action like the web ports.
    public var decidesEveryPort: Bool { policy.mode == .proxyOnly && policy.routeAllTCP }

    /// The most specific matching rule; `port` is `nil` for DNS, where only rules without a port match.
    public func rule(for host: String, port: UInt16? = nil) -> DomainRule? {
        let host = HostName.normalize(host)
        return rules
            .filter { $0.pattern.matches(host) && ($0.rule.port == nil || $0.rule.port == port) }
            .max { lhs, rhs in
                if lhs.pattern.specificity != rhs.pattern.specificity { return lhs.pattern.specificity < rhs.pattern.specificity }
                if (lhs.rule.port == nil) != (rhs.rule.port == nil) { return lhs.rule.port == nil }
                return Self.strength(lhs.rule.action) < Self.strength(rhs.rule.action)
            }?
            .rule
    }

    /// `port` is `nil` for DNS queries.
    public func evaluate(host rawHost: String, port: UInt16?) -> PolicyVerdict {
        let host = HostName.normalize(rawHost)
        guard HostName.isValid(host) else {
            return PolicyVerdict(action: .deny, rule: nil, inspect: false, reason: "invalid host name")
        }
        let rule = rule(for: host, port: port)
        let inspect = (rule?.inspect ?? false) && policy.inspection.enabled && !HostName.isIPLiteral(host)
        let ruleReason = rule.map { "rule \($0.displayPattern) (\($0.action.rawValue))" }

        if policy.mode == .watch {
            if rule?.action == .deny { return PolicyVerdict(action: .deny, rule: rule, inspect: false, reason: ruleReason!) }
            return PolicyVerdict(action: .allow, rule: rule, inspect: inspect, reason: ruleReason ?? "watch mode (allow)")
        }
        if let port, !Self.webPorts.contains(port), !decidesEveryPort {
            switch rule?.action {
            case .allow?: return PolicyVerdict(action: .allow, rule: rule, inspect: inspect, reason: ruleReason!)
            case .deny?: return PolicyVerdict(action: .deny, rule: rule, inspect: false, reason: ruleReason!)
            default:
                return PolicyVerdict(action: .deny, rule: rule, inspect: false, reason: "port \(port) needs an explicit allow rule")
            }
        }
        if let rule {
            return PolicyVerdict(action: rule.action, rule: rule, inspect: rule.action == .deny ? false : inspect, reason: ruleReason!)
        }
        return PolicyVerdict(
            action: policy.defaultAction, rule: nil, inspect: false, reason: "default action (\(policy.defaultAction.rawValue))"
        )
    }

    /// The most specific `DnsOverride` for `host`.
    public func override(for host: String) -> DnsOverride? {
        let host = HostName.normalize(host)
        return overrides.filter { $0.pattern.matches(host) }.max { $0.pattern.specificity < $1.pattern.specificity }?.override
    }

    /// Whether the proxy must not connect to `address` (private, loopback, link-local) under this policy.
    public func refusesDestination(_ address: String) -> Bool {
        policy.blockPrivateDestinations && PrivateNetworks.isPrivate(address)
    }

    private static func strength(_ action: DomainAction) -> Int {
        switch action {
        case .ask: 0
        case .allow: 1
        case .deny: 2
        }
    }
}
