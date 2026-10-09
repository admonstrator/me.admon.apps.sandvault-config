import Foundation
import SandvaultCore

/// `pfctl` calls of the helper, always scoped to `AppPaths.pfAnchor`; rules go in on stdin.
struct PFControl: Sendable {
    static let pfctlPath = "/sbin/pfctl"

    let runner: CommandRunner
    var anchor: String { AppPaths.pfAnchor }

    /// Parses without loading (`pfctl -a <anchor> -n -f -`).
    func validate(_ rules: String) async throws {
        try await checked(["-a", anchor, "-n", "-f", "-"], stdin: rules, failure: "pfctl rejected the generated rules")
    }

    func load(_ rules: String) async throws {
        try await checked(["-a", anchor, "-f", "-"], stdin: rules, failure: "pfctl could not load the anchor")
    }

    /// Flushes rules, translation rules and tables of our anchor only.
    func flush() async throws {
        try await checked(["-a", anchor, "-F", "all"], failure: "pfctl could not flush the anchor")
    }

    func isEnabled() async throws -> Bool {
        let result = try await checked(["-s", "info"], failure: "pfctl -s info failed")
        guard let enabled = Self.parseEnabled(result.stdoutString + "\n" + result.stderrString) else {
            throw SandvaultError.io("cannot read the pf status from pfctl -s info")
        }
        return enabled
    }

    /// `pfctl -E` enables pf with a reference count and prints `Token : <n>` (on stderr on current macOS).
    func enable() async throws -> String {
        let result = try await checked(["-E"], failure: "pfctl -E failed")
        guard let token = Self.parseToken(result.stdoutString + "\n" + result.stderrString) else {
            throw SandvaultError.io("pfctl -E printed no token")
        }
        return token
    }

    /// Releases our reference; a stale token (after a reboot) fails harmlessly, so the result is only reported.
    func release(token: String) async throws -> Bool {
        guard Self.isToken(token) else { throw SandvaultError.invalidInput("stored pf token is not numeric") }
        return try await runner.run(CommandInvocation(Self.pfctlPath, ["-X", token])).succeeded
    }

    /// Translation and filter rules as pf holds them (normalized by pfctl, not our text).
    func loadedRules() async throws -> String {
        let nat = try await checked(["-a", anchor, "-sn"], failure: "pfctl -sn failed")
        let rules = try await checked(["-a", anchor, "-sr"], failure: "pfctl -sr failed")
        return nat.stdoutString + rules.stdoutString
    }

    @discardableResult
    private func checked(_ arguments: [String], stdin: String? = nil, failure: String) async throws -> CommandResult {
        let invocation = CommandInvocation(Self.pfctlPath, arguments, stdin: stdin.map { Data($0.utf8) })
        let result = try await runner.run(invocation)
        guard result.succeeded else {
            throw SandvaultError.commandFailed("\(failure): \(invocation.description)", result.exitCode, result.stderrString)
        }
        return result
    }

    static func parseToken(_ output: String) -> String? {
        for line in output.split(whereSeparator: \.isNewline) {
            let parts = line.split(separator: ":", maxSplits: 1).map { $0.trimmingCharacters(in: .whitespaces) }
            if parts.count == 2, parts[0] == "Token", isToken(parts[1]) { return parts[1] }
        }
        return nil
    }

    /// `Status: Enabled for 0 days 00:01:02 ...` or `Status: Disabled ...`.
    static func parseEnabled(_ output: String) -> Bool? {
        for line in output.split(whereSeparator: \.isNewline) where line.hasPrefix("Status:") {
            let words = line.dropFirst("Status:".count).split(separator: " ")
            switch words.first {
            case "Enabled": return true
            case "Disabled": return false
            default: return nil
            }
        }
        return nil
    }

    static func isToken(_ text: String) -> Bool {
        !text.isEmpty && text.count <= 20 && text.allSatisfy { $0.isASCII && $0.isNumber }
    }
}
