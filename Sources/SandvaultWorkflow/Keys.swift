import Foundation
import SandvaultCore

/// Public keys in sv's host-only `authorized_keys.d`. sv concatenates every file there into the sandbox user's
/// `authorized_keys` on its next run (and aborts when one contains a private key), so changes apply then.
public struct AuthorizedKeyStore: KeyService {
    public let directory: String
    public let runner: CommandRunner

    public static let appliedNote = "sv applies authorized_keys.d on its next run (sv shell, sv claude, ...)"
    public static let knownTypes: Set<String> = [
        "ssh-ed25519", "ssh-rsa", "ecdsa-sha2-nistp256", "ecdsa-sha2-nistp384", "ecdsa-sha2-nistp521",
        "sk-ssh-ed25519@openssh.com", "sk-ecdsa-sha2-nistp256@openssh.com",
    ]

    public init(environment: SandvaultEnvironment, runner: CommandRunner) {
        self.init(directory: environment.authorizedKeysDir, runner: runner)
    }

    public init(directory: String, runner: CommandRunner) {
        self.directory = directory
        self.runner = runner
    }

    public func keys() async throws -> [AuthorizedKey] {
        guard FileKind.of(directory) == .directory else { return [] }
        let names = try FileManager.default.contentsOfDirectory(atPath: directory).filter { !$0.hasPrefix(".") }.sorted()
        var result: [AuthorizedKey] = []
        for name in names where FileManager.default.fileExists(atPath: directory + "/" + name) && FileKind.of(directory + "/" + name) != .directory {
            result.append(try await describe(name: name))
        }
        return result
    }

    public func add(name: String, publicKey: String) async throws -> AuthorizedKey {
        try Self.validate(name: name)
        let key = try Self.parse(publicKey)
        let path = directory + "/" + name
        guard FileKind.of(path) == .missing else { throw SandvaultError.invalidInput("a key named \(name) exists; remove it first") }
        try FileManager.default.createDirectory(atPath: directory, withIntermediateDirectories: true, attributes: [.posixPermissions: 0o700])
        try AtomicFile.write(Data((key.line + "\n").utf8), to: path, permissions: 0o600)
        guard let fingerprint = try await fingerprint(path) else {
            try? FileManager.default.removeItem(atPath: path)
            throw SandvaultError.invalidInput("ssh-keygen does not accept the key")
        }
        return AuthorizedKey(name: name, type: key.type, fingerprint: fingerprint, comment: key.comment)
    }

    public func remove(name: String) async throws {
        try Self.validate(name: name)
        let path = directory + "/" + name
        guard FileKind.of(path) != .missing else { throw SandvaultError.invalidInput("no key named \(name)") }
        do {
            try FileManager.default.removeItem(atPath: path)
        } catch {
            throw SandvaultError.io("cannot remove \(path): \(error)")
        }
    }

    // MARK: - Parsing

    public static func validate(name: String) throws {
        guard Text.matches(name, "^[A-Za-z0-9_-][A-Za-z0-9._-]{0,63}$") else {
            throw SandvaultError.invalidInput("key name '\(name)' must be 1-64 of [A-Za-z0-9._-] and not start with a dot")
        }
    }

    public struct ParsedKey: Equatable, Sendable {
        public var type: String
        public var comment: String?
        /// `<type> <base64> [comment]`, normalized to single spaces.
        public var line: String
    }

    /// One plain public key line of a known type; options (`command="…"`) and private keys are refused.
    public static func parse(_ text: String) throws -> ParsedKey {
        if text.contains("PRIVATE KEY") { throw SandvaultError.invalidInput("this is a private key; add the .pub file instead") }
        let lines = Text.lines(text).map { $0.trimmingCharacters(in: .whitespaces) }.filter { !$0.isEmpty && !$0.hasPrefix("#") }
        guard lines.count == 1, let line = lines.first else { throw SandvaultError.invalidInput("expected exactly one public key line") }
        guard !Text.hasControlCharacters(line.replacingOccurrences(of: "\t", with: " ")) else {
            throw SandvaultError.invalidInput("the key contains control characters")
        }
        let words = line.split(whereSeparator: { $0 == " " || $0 == "\t" }).map(String.init)
        guard words.count >= 2, knownTypes.contains(words[0]) else {
            throw SandvaultError.invalidInput("not a public key of a known type (\(knownTypes.sorted().joined(separator: ", ")); options are not supported)")
        }
        guard let blob = Data(base64Encoded: words[1]), blobType(blob) == words[0] else {
            throw SandvaultError.invalidInput("the key data is not valid base64 for \(words[0])")
        }
        let comment = words.count > 2 ? words[2...].joined(separator: " ") : nil
        return ParsedKey(type: words[0], comment: comment, line: ([words[0], words[1]] + (comment.map { [$0] } ?? [])).joined(separator: " "))
    }

    /// The SSH wire format starts with the key type as a length-prefixed string.
    static func blobType(_ blob: Data) -> String? {
        let bytes = [UInt8](blob)
        guard bytes.count >= 4 else { return nil }
        let length = Int(bytes[0]) << 24 | Int(bytes[1]) << 16 | Int(bytes[2]) << 8 | Int(bytes[3])
        guard length > 0, length <= 64, bytes.count >= 4 + length else { return nil }
        return String(bytes: bytes[4..<(4 + length)], encoding: .utf8)
    }

    /// `256 SHA256:… comment (ED25519)` from `ssh-keygen -l -f` -> `SHA256:…`.
    static func parseFingerprint(_ output: String) -> String? {
        guard let line = Text.lines(output).first else { return nil }
        let words = line.split(separator: " ")
        guard words.count >= 2, words[1].contains(":") else { return nil }
        return String(words[1])
    }

    private func fingerprint(_ path: String) async throws -> String? {
        let result = try await runner.run(CommandInvocation("/usr/bin/ssh-keygen", ["-l", "-f", path], timeout: 10))
        return result.succeeded ? Self.parseFingerprint(result.stdoutString) : nil
    }

    /// Mirrors what sv will do with the file: refuse private keys, ignore what ssh-keygen rejects.
    private func describe(name: String) async throws -> AuthorizedKey {
        let path = directory + "/" + name
        let text = (FileKind.size(path) ?? 0) <= 64 * 1024 ? (try? String(contentsOfFile: path, encoding: .utf8)) ?? "" : ""
        if text.contains("PRIVATE KEY") {
            return AuthorizedKey(name: name, type: "private key (sv refuses to start)", fingerprint: "")
        }
        guard let fingerprint = try await fingerprint(path) else {
            return AuthorizedKey(name: name, type: "invalid (sv ignores it)", fingerprint: "")
        }
        let words = (Text.lines(text).first { !$0.hasPrefix("#") && !$0.trimmingCharacters(in: .whitespaces).isEmpty } ?? "")
            .split(separator: " ").map(String.init)
        let comment = words.count > 2 ? words[2...].joined(separator: " ") : nil
        return AuthorizedKey(name: name, type: words.first ?? "unknown", fingerprint: fingerprint, comment: comment)
    }
}
