import Foundation
import SandvaultCore

/// Any sandbox rule, for listing and removal across the three rule kinds.
public enum SandboxRule: Sendable, Equatable, Hashable, Identifiable {
    case file(FileRule)
    case mach(MachRule)
    case exec(ExecRule)

    public var id: UUID {
        switch self {
        case .file(let rule): rule.id
        case .mach(let rule): rule.id
        case .exec(let rule): rule.id
        }
    }

    public var kind: String {
        switch self {
        case .file: "file"
        case .mach: "mach"
        case .exec: "exec"
        }
    }

    public var effect: RuleEffect {
        switch self {
        case .file(let rule): rule.effect
        case .mach(let rule): rule.effect
        case .exec(let rule): rule.effect
        }
    }

    public var note: String? {
        switch self {
        case .file(let rule): rule.note
        case .mach(let rule): rule.note
        case .exec(let rule): rule.note
        }
    }

    /// `read-write subpath /opt/homebrew`, `mach com.apple.pasteboard.1`, `exec /usr/bin/osascript`.
    public var summary: String {
        switch self {
        case .file(let rule):
            let access = switch rule.access {
            case .read: "read"
            case .write: "write"
            case .readWrite: "read-write"
            }
            return "\(access) \(rule.match.rawValue) \(rule.path)"
        case .mach(let rule): return "mach \(rule.name)"
        case .exec(let rule): return "exec \(rule.path)"
        }
    }
}

extension SandboxSettings {
    /// All rules in the order they appear in the generated block (after the preset).
    public var rules: [SandboxRule] {
        fileRules.map(SandboxRule.file) + machRules.map(SandboxRule.mach) + execRules.map(SandboxRule.exec)
    }

    /// Validates and appends. Last match wins, so the new rule takes precedence over earlier ones; an identical
    /// rule (same target and effect) is moved to the end instead of being added twice.
    /// Returns the id of the rule now in effect.
    @discardableResult
    public mutating func add(_ rule: FileRule) throws -> UUID {
        _ = try SBPLGenerator.block(for: SandboxSettings(fileRules: [rule]))
        return Self.appendOnce(rule, to: &fileRules) { $0.path == rule.path && $0.match == rule.match && $0.access == rule.access && $0.effect == rule.effect }
    }

    @discardableResult
    public mutating func add(_ rule: MachRule) throws -> UUID {
        _ = try SBPLGenerator.block(for: SandboxSettings(machRules: [rule]))
        return Self.appendOnce(rule, to: &machRules) { $0.name == rule.name && $0.effect == rule.effect }
    }

    @discardableResult
    public mutating func add(_ rule: ExecRule) throws -> UUID {
        _ = try SBPLGenerator.block(for: SandboxSettings(execRules: [rule]))
        return Self.appendOnce(rule, to: &execRules) { $0.path == rule.path && $0.effect == rule.effect }
    }

    static func appendOnce<Rule: Identifiable>(_ rule: Rule, to rules: inout [Rule], sameAs: (Rule) -> Bool) -> UUID where Rule.ID == UUID {
        guard let index = rules.firstIndex(where: sameAs) else {
            rules.append(rule)
            return rule.id
        }
        let existing = rules.remove(at: index)
        rules.append(existing)
        return existing.id
    }

    /// Turns a learn-mode suggestion (agent A's `RuleSuggestion`) into a config rule.
    @discardableResult
    public mutating func add(_ proposal: RuleSuggestion.Proposal) throws -> UUID {
        switch proposal {
        case .file(let rule): try add(rule)
        case .mach(let rule): try add(rule)
        case .exec(let rule): try add(rule)
        }
    }

    /// Removes the one rule whose id starts with `idPrefix` (case-insensitive, at least 4 characters).
    @discardableResult
    public mutating func removeRule(idPrefix: String) throws -> SandboxRule {
        let rule = try IDPrefix.unique(idPrefix, in: rules, id: \.id, what: "rule")
        fileRules.removeAll { $0.id == rule.id }
        machRules.removeAll { $0.id == rule.id }
        execRules.removeAll { $0.id == rule.id }
        return rule
    }
}

extension NetworkPolicy {
    /// Validates (same rules as the pf generator) and appends; identical exceptions are not added twice.
    @discardableResult
    public mutating func add(_ exception: PortException) throws -> UUID {
        _ = try PFAnchorGenerator.destination(exception)
        _ = try PFAnchorGenerator.portClause(exception)
        if let existing = portExceptions.first(where: {
            $0.proto == exception.proto && $0.destination.lowercased() == exception.destination.lowercased() && $0.port == exception.port
        }) {
            return existing.id
        }
        portExceptions.append(exception)
        return exception.id
    }

    @discardableResult
    public mutating func removeException(idPrefix: String) throws -> PortException {
        let exception = try IDPrefix.unique(idPrefix, in: portExceptions, id: \.id, what: "exception")
        portExceptions.removeAll { $0.id == exception.id }
        return exception
    }
}

enum IDPrefix {
    static let minimumLength = 4

    static func unique<T>(_ prefix: String, in items: [T], id: KeyPath<T, UUID>, what: String) throws -> T {
        let needle = prefix.lowercased()
        guard needle.count >= minimumLength else {
            throw SandvaultError.invalidInput("\(what) id prefix needs at least \(minimumLength) characters")
        }
        let matches = items.filter { $0[keyPath: id].uuidString.lowercased().hasPrefix(needle) }
        guard let match = matches.first else { throw SandvaultError.invalidInput("no \(what) with id \(prefix)") }
        guard matches.count == 1 else { throw SandvaultError.invalidInput("\(matches.count) \(what)s match \(prefix); use more characters") }
        return match
    }
}
