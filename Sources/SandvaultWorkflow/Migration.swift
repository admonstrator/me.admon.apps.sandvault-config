import Foundation
import SandvaultCore

/// Copies host configuration into `$SHARED_WORKSPACE/user`, which sv rsyncs into the sandbox home on every
/// session (zsh files are sourced from there). Nothing that looks like a credential gets through: blocked files
/// stay in the plan with a reason, and `apply` checks every file again before it writes.
public struct ConfigMigration: MigrationService {
    public let layout: SharedLayout
    public let runner: CommandRunner

    static let maxBytes = 1 << 20
    static let maxFilesPerItem = 500

    public init(environment: SandvaultEnvironment, runner: CommandRunner, shared: SharedFiles? = nil) {
        layout = SharedLayout(environment: environment, shared: shared)
        self.runner = runner
    }

    /// Host source (relative to the home) and destination (relative to `$SHARED_WORKSPACE/user`) of each item.
    public static func location(of item: MigrationItem) -> (source: String, destination: String, isDirectory: Bool) {
        switch item {
        case .claudeSettings: (".claude/settings.json", ".claude/settings.json", false)
        case .claudeMemory: (".claude/CLAUDE.md", ".claude/CLAUDE.md", false)
        case .claudeCommands: (".claude/commands", ".claude/commands", true)
        case .claudeAgents: (".claude/agents", ".claude/agents", true)
        case .claudeSkills: (".claude/skills", ".claude/skills", true)
        case .gitIdentity: ("", ".gitconfig", false)
        case .zshrc: (".zshrc", ".zshrc", false)
        case .zprofile: (".zprofile", ".zprofile", false)
        case .zshenv: (".zshenv", ".zshenv", false)
        }
    }

    public func plan(_ items: [MigrationItem]) async throws -> MigrationPlan {
        MigrationPlan(entries: try await prepare(items).map(\.entry))
    }

    /// Writes the plan's copyable entries that still pass every check; returns what was written.
    public func apply(_ plan: MigrationPlan) async throws -> [MigrationEntry] {
        try layout.requireWorkspace()
        let approved = Set(plan.copyable.map { "\($0.source)\u{0}\($0.destination)" })
        var items: [MigrationItem] = []
        for entry in plan.copyable where !items.contains(entry.item) { items.append(entry.item) }
        var written: [MigrationEntry] = []
        for prepared in try await prepare(items) {
            let entry = prepared.entry
            guard entry.blockedReason == nil, let content = prepared.content,
                  approved.contains("\(entry.source)\u{0}\(entry.destination)")
            else { continue }
            try layout.shared.write(content, to: "\(layout.userRelative)/\(entry.destination)", permissions: prepared.mode)
            written.append(entry)
        }
        return written
    }

    // MARK: - Preparation

    struct Prepared {
        var entry: MigrationEntry
        var content: Data?
        var mode: Int
    }

    func prepare(_ items: [MigrationItem]) async throws -> [Prepared] {
        var result: [Prepared] = []
        let home = layout.environment.hostHome
        for item in items {
            let location = Self.location(of: item)
            switch item {
            case .gitIdentity:
                result.append(try await gitIdentity())
            case .claudeCommands, .claudeAgents, .claudeSkills:
                result += directory(item, source: home + "/" + location.source, destination: location.destination)
            default:
                result.append(file(item, source: home + "/" + location.source, destination: location.destination))
            }
        }
        return result
    }

    private func directory(_ item: MigrationItem, source: String, destination: String) -> [Prepared] {
        guard FileKind.of(source) == .directory else { return [file(item, source: source, destination: destination)] }
        var files: [String] = []
        var truncated = false
        func walk(_ relative: String, depth: Int) {
            let path = relative.isEmpty ? source : source + "/" + relative
            let names = ((try? FileManager.default.contentsOfDirectory(atPath: path)) ?? []).sorted()
            for name in names {
                let child = relative.isEmpty ? name : relative + "/" + name
                if FileKind.of(source + "/" + child) == .directory, depth < 8 {
                    walk(child, depth: depth + 1)
                } else if files.count < Self.maxFilesPerItem {
                    files.append(child)
                } else {
                    truncated = true
                }
            }
        }
        walk("", depth: 0)
        var result = files.map { file(item, source: source + "/" + $0, destination: destination + "/" + $0) }
        if truncated {
            result.append(Prepared(entry: MigrationEntry(item: item, source: source, destination: destination, bytes: 0,
                blockedReason: "more than \(Self.maxFilesPerItem) files; the rest is not copied"), content: nil, mode: 0))
        }
        return result
    }

    private func file(_ item: MigrationItem, source: String, destination: String) -> Prepared {
        let target = layout.absolute("\(layout.userRelative)/\(destination)")
        var entry = MigrationEntry(item: item, source: source, destination: destination, bytes: 0,
                                   overwrites: FileKind.of(target) != .missing)
        func blocked(_ reason: String) -> Prepared {
            entry.blockedReason = reason
            return Prepared(entry: entry, content: nil, mode: 0)
        }
        switch FileKind.of(source) {
        case .missing: return blocked("not found on the host")
        case .symlink:
            let destination = (try? FileManager.default.destinationOfSymbolicLink(atPath: source)) ?? "?"
            return blocked("symlink to \(destination); copy the file itself if you want it")
        case .directory, .other: return blocked("not a regular file")
        case .regular: break
        }
        let size = FileKind.size(source) ?? 0
        entry.bytes = size
        if size > Self.maxBytes { return blocked("larger than 1 MB") }
        if let reason = SecretScan.fileNameReason(ReadinessCheck.baseName(source)) { return blocked(reason) }
        guard var content = FileManager.default.contents(atPath: source) else { return blocked("cannot read the file") }
        let text = String(decoding: content, as: UTF8.self)
        if let reason = SecretScan.contentReason(text, fileName: ReadinessCheck.baseName(source)) { return blocked(reason) }

        if item == .zshenv {
            // Keep the network block netd maintains in the shared copy; drop blocks that belong to the host.
            var merged = ManagedBlock.zshenv.remove(from: SandvaultDefaults.block.remove(from: text))
            let existing: String?
            do {
                existing = try layout.shared.read("\(layout.userRelative)/\(destination)").map { String(decoding: $0, as: UTF8.self) }
            } catch {
                return blocked("cannot read the shared .zshenv safely: \(error)")
            }
            if let body = existing.flatMap(ManagedBlock.zshenv.extract(from:)) {
                merged = ManagedBlock.zshenv.replace(in: merged, with: body)
            }
            entry.overwrites = existing.map { !ManagedBlock.zshenv.remove(from: $0).trimmingCharacters(in: .whitespacesAndNewlines).isEmpty } ?? false
            content = Data(merged.utf8)
            entry.bytes = content.count
        }
        let executable = (FileKind.mode(source) ?? 0) & 0o111 != 0
        return Prepared(entry: entry, content: content, mode: executable ? 0o750 : 0o640)
    }

    /// A `.gitconfig` with the host's `[user]` name and email only.
    private func gitIdentity() async throws -> Prepared {
        let destination = Self.location(of: .gitIdentity).destination
        let target = layout.absolute("\(layout.userRelative)/\(destination)")
        var entry = MigrationEntry(item: .gitIdentity, source: "git config --global user.name, user.email",
                                   destination: destination, bytes: 0, overwrites: FileKind.of(target) != .missing)
        var values: [(String, String)] = []
        for key in ["name", "email"] {
            let result = try? await runner.run(CommandInvocation(GitSafe.gitPath, ["config", "--global", "--get", "user.\(key)"], timeout: 10))
            if let result, result.succeeded, !result.trimmedOutput.isEmpty { values.append((key, result.trimmedOutput)) }
        }
        guard !values.isEmpty else {
            entry.blockedReason = "no git identity on the host (git config --global user.name / user.email)"
            return Prepared(entry: entry, content: nil, mode: 0)
        }
        guard let text = Self.gitconfig(values) else {
            entry.blockedReason = "the git identity contains control characters"
            return Prepared(entry: entry, content: nil, mode: 0)
        }
        let content = Data(text.utf8)
        entry.bytes = content.count
        return Prepared(entry: entry, content: content, mode: 0o640)
    }

    static func gitconfig(_ values: [(String, String)]) -> String? {
        var lines = ["# Written by Sandvault Config from the host's git identity.", "[user]"]
        for (key, value) in values {
            guard !Text.hasControlCharacters(value) else { return nil }
            let escaped = value.replacingOccurrences(of: "\\", with: "\\\\").replacingOccurrences(of: "\"", with: "\\\"")
            lines.append("\t\(key) = \"\(escaped)\"")
        }
        return lines.joined(separator: "\n") + "\n"
    }
}

/// Credential files and token patterns that must not reach the sandbox.
public enum SecretScan {
    public struct Pattern: Sendable {
        public var label: String
        public var regex: String
        public var caseInsensitive: Bool
    }

    public static let patterns: [Pattern] = [
        Pattern(label: "an Anthropic API key", regex: "sk-ant-[A-Za-z0-9_-]{16,}", caseInsensitive: false),
        Pattern(label: "a GitHub token", regex: "ghp_[A-Za-z0-9]{16,}", caseInsensitive: false),
        Pattern(label: "a GitHub token", regex: "github_pat_[A-Za-z0-9_]{16,}", caseInsensitive: false),
        Pattern(label: "a GitHub OAuth token", regex: "gho_[A-Za-z0-9]{16,}", caseInsensitive: false),
        Pattern(label: "a Slack token", regex: "xox[abp]-[A-Za-z0-9-]{10,}", caseInsensitive: false),
        Pattern(label: "an AWS access key", regex: "AKIA[0-9A-Z]{16}", caseInsensitive: false),
        Pattern(label: "a private key", regex: "-----BEGIN [A-Z ]*PRIVATE KEY-----", caseInsensitive: false),
        // `"apiKey": "…"`, `"ANTHROPIC_API_KEY": "…"`, `"client_secret": "…"`; paths (`"apiKeyHelper": "~/bin/key"`) pass.
        Pattern(label: "a secret in a JSON value",
                regex: "\"[^\"\\n]*(api[_-]?key|token|secret)[^\"\\n]*\"\\s*:\\s*\"[^/~\"\\n][^\"\\n]{11,}\"", caseInsensitive: true),
        // `export OPENAI_API_KEY=sk-…`; values starting with `$`, `/` or `~` (expansions, paths) pass.
        Pattern(label: "a secret in a shell assignment",
                regex: "\\b[A-Za-z0-9_]*(api_?key|token|secret|password)[A-Za-z0-9_]*\\s*=\\s*['\"]?[A-Za-z0-9_+-][^\\s'\"]{11,}",
                caseInsensitive: true),
    ]

    public static func fileNameReason(_ name: String) -> String? {
        let lower = name.lowercased()
        if lower == ".credentials.json" { return "credentials file" }
        if [".pem", ".key", ".p12", ".pfx"].contains(where: lower.hasSuffix) { return "certificate or key file" }
        if lower.hasPrefix("id_"), !lower.hasSuffix(".pub") { return "SSH private key" }
        if lower == ".netrc" { return "netrc file (passwords)" }
        if ReadinessCheck.isDotenv(name) { return "dotenv file (secrets)" }
        return nil
    }

    /// The first pattern found, with its line number; never the matched text.
    public static func contentReason(_ text: String, fileName: String = "") -> String? {
        if fileName == ".npmrc", text.contains("_authToken") { return "npm auth token (_authToken)" }
        for pattern in patterns {
            let options: String.CompareOptions = pattern.caseInsensitive ? [.regularExpression, .caseInsensitive] : [.regularExpression]
            if let range = text.range(of: pattern.regex, options: options) {
                let line = text[..<range.lowerBound].reduce(1) { $1 == "\n" ? $0 + 1 : $0 }
                return "contains what looks like \(pattern.label) (line \(line))"
            }
        }
        return nil
    }
}
