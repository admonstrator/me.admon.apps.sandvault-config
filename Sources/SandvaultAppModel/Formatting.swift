import Foundation
import SandvaultCore
import SandvaultEnforce

/// Display strings, kept here so the SwiftUI layer only places them.
public enum Format {
    /// `512 B`, `1.2 kB`, `3.4 MB` (decimal units, like svctl).
    public static func bytes(_ count: Int64) -> String {
        let units = ["B", "kB", "MB", "GB", "TB"]
        var value = Double(count)
        var unit = 0
        while abs(value) >= 1000, unit < units.count - 1 {
            value /= 1000
            unit += 1
        }
        return unit == 0 ? "\(count) B" : String(format: "%.1f %@", value, units[unit])
    }

    public static func kibibytes(_ kib: Int) -> String {
        bytes(Int64(kib) * 1024)
    }

    /// `45s`, `12m 03s`, `3h 05m`, `2d 04h`.
    public static func duration(_ seconds: Int) -> String {
        let s = max(0, seconds)
        if s < 60 { return "\(s)s" }
        if s < 3600 { return String(format: "%dm %02ds", s / 60, s % 60) }
        if s < 86400 { return String(format: "%dh %02dm", s / 3600, (s % 3600) / 60) }
        return String(format: "%dd %02dh", s / 86400, (s % 86400) / 3600)
    }

    /// `0:27`, `1:05`.
    public static func countdown(_ seconds: Int) -> String {
        let s = max(0, seconds)
        return String(format: "%d:%02d", s / 60, s % 60)
    }

    public static func percent(_ value: Double) -> String {
        String(format: "%.1f", value)
    }

    public static func shortID(_ id: UUID) -> String {
        String(id.uuidString.prefix(8)).lowercased()
    }

    /// First block of an `SV_SESSION_ID`.
    public static func shortSession(_ id: String?) -> String {
        guard let id else { return "" }
        return String(id.prefix(8)).lowercased()
    }

    /// `host:port`, or the host alone for DNS.
    public static func endpoint(_ host: String, _ port: UInt16?) -> String {
        port.map { "\(host):\($0)" } ?? host
    }

    /// `14:03:27` in the local time zone.
    public static func time(_ date: Date) -> String {
        let formatter = DateFormatter()
        formatter.locale = Locale(identifier: "en_US_POSIX")
        formatter.dateFormat = "HH:mm:ss"
        return formatter.string(from: date)
    }
}

/// Colour family of a state, mapped to a SwiftUI colour in the app.
public enum Tint: String, Sendable {
    case green, orange, red, gray, blue
}

extension FirewallMode {
    public var displayName: String {
        switch self {
        case .off: "Off"
        case .open: "Open"
        case .proxyOnly: "Proxy only"
        case .blocked: "Blocked"
        }
    }

    public var explanation: String {
        switch self {
        case .off: "No firewall: the sandbox reaches the network directly (sv's default)."
        case .open: "Direct traffic allowed; LAN and localhost guards and port exceptions apply."
        case .proxyOnly: "Web and DNS go through sandvault-netd and its domain rules; everything else needs an exception."
        case .blocked: "No network for the sandbox user."
        }
    }
}

extension LocalhostPolicy {
    public var displayName: String {
        switch self {
        case .sandboxAndHelpers: "Sandbox listeners and sv helpers"
        case .allowAll: "Everything on this Mac"
        case .blockAll: "netd only"
        }
    }
}

extension DomainAction {
    public var displayName: String {
        switch self {
        case .allow: "Allow"
        case .deny: "Deny"
        case .ask: "Ask"
        }
    }
}

extension AskDecision {
    public var displayName: String {
        switch self {
        case .allowOnce: "Allow once"
        case .allowAlways: "Allow always"
        case .denyOnce: "Deny once"
        case .denyAlways: "Deny always"
        }
    }
}

extension ConnectionDecision {
    public var displayName: String {
        switch self {
        case .allowed: "Allowed"
        case .askedAllowed: "Allowed (asked)"
        case .denied: "Denied"
        case .askedDenied: "Denied (asked)"
        case .timedOut: "Denied (unanswered)"
        }
    }

    public var tint: Tint {
        switch self {
        case .allowed, .askedAllowed: .green
        case .denied, .askedDenied, .timedOut: .red
        }
    }
}

extension ConnectionKind {
    public var displayName: String {
        switch self {
        case .explicitProxy: "proxy"
        case .transparentHTTP: "http"
        case .transparentTLS: "tls"
        case .dns: "dns"
        }
    }
}

extension CheckState {
    public var symbolName: String {
        switch self {
        case .ok: "checkmark.circle.fill"
        case .skipped: "minus.circle"
        case .unknown: "questionmark.circle"
        case .warning: "exclamationmark.triangle.fill"
        case .failure: "xmark.octagon.fill"
        }
    }

    public var tint: Tint {
        switch self {
        case .ok: .green
        case .skipped, .unknown: .gray
        case .warning: .orange
        case .failure: .red
        }
    }
}

extension FindingSeverity {
    public var symbolName: String {
        switch self {
        case .info: "info.circle"
        case .warning: "exclamationmark.triangle.fill"
        case .blocker: "xmark.octagon.fill"
        }
    }

    public var tint: Tint {
        switch self {
        case .info: .gray
        case .warning: .orange
        case .blocker: .red
        }
    }
}

extension UserMessage.Kind {
    public var symbolName: String {
        switch self {
        case .success: "checkmark.circle.fill"
        case .info: "info.circle.fill"
        case .warning: "exclamationmark.triangle.fill"
        case .error: "xmark.octagon.fill"
        case .notAvailable: "hammer"
        }
    }

    public var tint: Tint {
        switch self {
        case .success: .green
        case .info, .notAvailable: .blue
        case .warning: .orange
        case .error: .red
        }
    }
}

extension AgentKind {
    public var displayName: String {
        switch self {
        case .claude: "Claude Code"
        case .codex: "Codex"
        case .opencode: "OpenCode"
        case .gemini: "Gemini CLI"
        case .pi: "Pi"
        case .muse: "Muse"
        case .shell: "Shell"
        }
    }
}

extension TerminalApp {
    public var displayName: String {
        switch self {
        case .terminal: "Terminal"
        case .iterm2: "iTerm2"
        case .ghostty: "Ghostty"
        }
    }
}

extension HandoffRequest.DeployKeyMode {
    public var displayName: String {
        switch self {
        case .none: "No deploy key"
        case .readOnly: "Read-only deploy key"
        case .readWrite: "Read-write deploy key"
        }
    }
}

extension ToolGrantMethod {
    public var displayName: String {
        switch self {
        case .available: "Already available"
        case .brew: "Install with Homebrew"
        case .copy: "Copy into user/bin"
        }
    }
}

extension MigrationItem {
    public var displayName: String {
        switch self {
        case .claudeSettings: "Claude settings"
        case .claudeMemory: "CLAUDE.md"
        case .claudeCommands: "Claude commands"
        case .claudeAgents: "Claude agents"
        case .claudeSkills: "Claude skills"
        case .gitIdentity: "git identity"
        case .zshrc: ".zshrc"
        case .zprofile: ".zprofile"
        case .zshenv: ".zshenv"
        }
    }
}

extension RuleEffect {
    public var displayName: String { self == .allow ? "Allow" : "Deny" }
}

extension FileAccess {
    public var displayName: String {
        switch self {
        case .read: "Read"
        case .write: "Write"
        case .readWrite: "Read and write"
        }
    }
}

extension PathMatch {
    public var displayName: String {
        switch self {
        case .subpath: "Directory tree"
        case .literal: "Exact path"
        case .prefix: "Path prefix"
        }
    }
}

extension SandboxPreset {
    public var displayName: String { self == .standard ? "Standard" : "Hardened" }
}

extension TransportProtocol {
    public var displayName: String { rawValue.uppercased() }
}

extension ProfileDrift {
    public var displayName: String {
        switch self {
        case .inSync: "In sync with the configuration"
        case .missing: "Block missing (sv --rebuild rewrites the profile)"
        case .outdated: "Block differs from the configuration"
        case .unexpected: "Block present, but no rules are configured"
        case .profileMissing: "sv's profile not found"
        }
    }

    public var tint: Tint {
        switch self {
        case .inSync: .green
        case .missing, .outdated, .unexpected: .orange
        case .profileMissing: .gray
        }
    }
}

extension RuleSuggestion {
    /// `allow read-write literal /path`, `allow mach com.example`.
    public var summary: String {
        let rule: SandboxRule = switch proposal {
        case .file(let file): .file(file)
        case .mach(let mach): .mach(mach)
        case .exec(let exec): .exec(exec)
        }
        return "\(rule.effect.rawValue) \(rule.summary)"
    }

    public var note: String? {
        switch proposal {
        case .file(let rule): rule.note
        case .mach(let rule): rule.note
        case .exec(let rule): rule.note
        }
    }
}

extension RepoStatus {
    /// `main · 3 new commits to fetch · uncommitted changes`.
    public var summary: String {
        var parts: [String] = [branch ?? "detached"]
        if let unfetchedCommits, unfetchedCommits > 0 { parts.append("\(unfetchedCommits) new commit\(unfetchedCommits == 1 ? "" : "s") to fetch") }
        if let aheadOfOrigin, aheadOfOrigin > 0 { parts.append("\(aheadOfOrigin) ahead of origin") }
        if let behindOrigin, behindOrigin > 0 { parts.append("\(behindOrigin) behind origin") }
        if dirty == true { parts.append("uncommitted changes") }
        if record == nil { parts.append("not handed off from this Mac") }
        return parts.joined(separator: " · ")
    }
}

extension ToolStatus {
    /// `/opt/homebrew/bin/jq (homebrew) · reachable in the sandbox`.
    public var summary: String {
        let place = hostPath.map { "\($0) (\(location.rawValue))" } ?? "not found on the host"
        return "\(place) · \(reachableInSandbox ? "reachable in the sandbox" : "not reachable in the sandbox")"
    }
}

extension MigrationEntry {
    /// `~/.claude/settings.json -> user/.claude/settings.json (1.2 kB)`.
    public var summary: String {
        "\(source) -> user/\(destination) (\(Format.bytes(Int64(bytes))))" + (overwrites ? ", replaces the existing file" : "")
    }
}
