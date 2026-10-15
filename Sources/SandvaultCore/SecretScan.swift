import Foundation

/// Credential files and token patterns: what migration never copies into the sandbox (D32) and what the lab
/// reports when sandboxed software writes it (D52).
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
        if isDotenv(name) { return "dotenv file (secrets)" }
        return nil
    }

    /// `.env`, `.env.local`; templates such as `.env.example` are not secrets.
    public static func isDotenv(_ name: String) -> Bool {
        guard name == ".env" || name.hasPrefix(".env.") else { return false }
        let templates = [".example", ".sample", ".template", ".dist", ".defaults", ".schema"]
        return !templates.contains { name.hasSuffix($0) }
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
