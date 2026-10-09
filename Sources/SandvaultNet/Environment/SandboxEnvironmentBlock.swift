import Foundation
import SandvaultCore

/// The managed block in `$SHARED_WORKSPACE/user/.zshenv` that points cooperative tools in the sandbox at
/// the explicit proxy and, with inspection, at the CA. Values come from typed config only.
/// The file is sandbox-writable, so it is only touched through `SharedFiles`.
public enum SandboxEnvironmentBlock {
    public enum State: String, Codable, Sendable {
        /// The file holds exactly the block the config asks for (or no block when the mode is `off`).
        case current
        /// A block is expected but absent.
        case missing
        /// A block exists but differs from the config (or exists while the mode is `off`).
        case stale
    }

    public enum Change: String, Codable, Sendable {
        case written, removed, unchanged
    }

    public static let noProxy = "localhost,127.0.0.1,::1"

    /// Ordered `NAME=value` pairs; empty when the firewall mode is `off`.
    public static func variables(policy: NetworkPolicy, paths: AppPaths) -> [(name: String, value: String)] {
        guard policy.mode != .off else { return [] }
        let proxy = "http://127.0.0.1:\(policy.ports.explicitProxy)"
        var result: [(String, String)] = [
            ("http_proxy", proxy), ("https_proxy", proxy), ("HTTP_PROXY", proxy), ("HTTPS_PROXY", proxy),
            ("NO_PROXY", noProxy), ("no_proxy", noProxy),
        ]
        if policy.inspection.enabled {
            result.append(("NODE_EXTRA_CA_CERTS", paths.publicCACertificate))
            for name in ["SSL_CERT_FILE", "REQUESTS_CA_BUNDLE", "CURL_CA_BUNDLE", "GIT_SSL_CAINFO", "AWS_CA_BUNDLE"] {
                result.append((name, paths.publicCABundle))
            }
        }
        return result
    }

    /// The block body, or `nil` when no block belongs in the file.
    public static func body(policy: NetworkPolicy, paths: AppPaths) -> String? {
        let pairs = variables(policy: policy, paths: paths)
        guard !pairs.isEmpty else { return nil }
        return pairs.map { "export \($0.name)=\(shellQuoted($0.value))" }.joined(separator: "\n")
    }

    public static func state(of text: String, policy: NetworkPolicy, paths: AppPaths) -> State {
        let existing = ManagedBlock.zshenv.extract(from: text)
        switch (body(policy: policy, paths: paths), existing) {
        case (nil, nil): return .current
        case (nil, _?): return .stale
        case (_?, nil): return .missing
        case let (expected?, actual?): return expected == actual ? .current : .stale
        }
    }

    /// Reads the file through `SharedFiles`, replaces or removes the block and writes it back.
    /// A planted symlink or non-regular file makes the read throw, so nothing is written.
    @discardableResult
    public static func apply(policy: NetworkPolicy, paths: AppPaths, shared: SharedFiles) throws -> Change {
        let relative = try paths.sharedRelative(paths.sharedZshenv)
        let current = try shared.read(relative).map { String(decoding: $0, as: UTF8.self) }
        let updated: String?
        if let body = body(policy: policy, paths: paths) {
            updated = ManagedBlock.zshenv.replace(in: current ?? "", with: body)
        } else if let current, ManagedBlock.zshenv.contains(in: current) {
            updated = ManagedBlock.zshenv.remove(from: current)
        } else {
            return .unchanged
        }
        guard let updated, updated != current else { return .unchanged }
        try shared.write(Data(updated.utf8), to: relative, permissions: 0o640)
        return body(policy: policy, paths: paths) == nil ? .removed : .written
    }

    /// Current state of the file; throws when it cannot be read safely.
    public static func check(policy: NetworkPolicy, paths: AppPaths, shared: SharedFiles) throws -> State {
        let relative = try paths.sharedRelative(paths.sharedZshenv)
        let text = try shared.read(relative).map { String(decoding: $0, as: UTF8.self) } ?? ""
        return state(of: text, policy: policy, paths: paths)
    }

    /// Single-quoted for zsh; embedded single quotes become `'\''`.
    static func shellQuoted(_ value: String) -> String {
        "'" + value.replacingOccurrences(of: "'", with: "'\\''") + "'"
    }
}
