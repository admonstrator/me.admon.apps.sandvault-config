import Foundation
import SandvaultCore

// Config mutations shared by svctl, the ask flow and the app. Patterns are validated and stored normalized;
// one rule per pattern (setting a pattern again replaces its action).

extension NetworkPolicy {
    /// Adds a rule or updates the rule with the same pattern. `inspect: nil` keeps an existing rule's flag.
    @discardableResult
    public mutating func upsertDomainRule(pattern: String, action: DomainAction, inspect: Bool? = nil, note: String? = nil, now: Date = Date()) throws -> DomainRule {
        let normalized = try DomainPattern(pattern).description
        if let index = domainRules.firstIndex(where: { (try? DomainPattern($0.pattern).description) == normalized }) {
            domainRules[index].action = action
            if let inspect { domainRules[index].inspect = inspect }
            if let note { domainRules[index].note = note }
            return domainRules[index]
        }
        let rule = DomainRule(pattern: normalized, action: action, inspect: inspect ?? false, note: note, createdAt: now)
        domainRules.append(rule)
        return rule
    }

    /// Removes the rule whose id starts with `selector` (unique) or whose pattern equals it.
    @discardableResult
    public mutating func removeDomainRule(selector: String) throws -> DomainRule {
        let index = try PolicySelector.index(of: selector, in: domainRules.map { ($0.id, $0.pattern) }, kind: "rule")
        return domainRules.remove(at: index)
    }

    @discardableResult
    public mutating func upsertDnsOverride(pattern: String, address: String, note: String? = nil) throws -> DnsOverride {
        let normalized = try DomainPattern(pattern).description
        let canonical = address.trimmingCharacters(in: .whitespaces).lowercased()
        guard AddressRange.parseAddress(canonical) != nil else {
            throw SandvaultError.invalidInput("'\(address)' is not an IPv4 or IPv6 address")
        }
        if let index = dnsOverrides.firstIndex(where: { (try? DomainPattern($0.pattern).description) == normalized }) {
            dnsOverrides[index].address = canonical
            if let note { dnsOverrides[index].note = note }
            return dnsOverrides[index]
        }
        let entry = DnsOverride(pattern: normalized, address: canonical, note: note)
        dnsOverrides.append(entry)
        return entry
    }

    @discardableResult
    public mutating func removeDnsOverride(selector: String) throws -> DnsOverride {
        let index = try PolicySelector.index(of: selector, in: dnsOverrides.map { ($0.id, $0.pattern) }, kind: "override")
        return dnsOverrides.remove(at: index)
    }
}

enum PolicySelector {
    /// Index of the single entry whose UUID starts with `selector` (case-insensitive) or whose pattern equals it.
    static func index(of selector: String, in entries: [(id: UUID, pattern: String)], kind: String) throws -> Int {
        let wanted = selector.trimmingCharacters(in: .whitespaces)
        guard !wanted.isEmpty else { throw SandvaultError.invalidInput("empty \(kind) selector") }
        let pattern = (try? DomainPattern(wanted).description) ?? wanted.lowercased()
        if let exact = entries.firstIndex(where: { (try? DomainPattern($0.pattern).description) == pattern }) {
            return exact
        }
        let prefix = wanted.lowercased()
        let matches = entries.indices.filter { entries[$0].id.uuidString.lowercased().hasPrefix(prefix) }
        switch matches.count {
        case 1: return matches[0]
        case 0: throw SandvaultError.invalidInput("no \(kind) matches '\(selector)'")
        default:
            let ids = matches.map { String(entries[$0].id.uuidString.prefix(8)).lowercased() }.joined(separator: ", ")
            throw SandvaultError.invalidInput("'\(selector)' matches several \(kind)s (\(ids)); use a longer prefix")
        }
    }
}
