import Foundation
import SandvaultCore

/// Finds the executable of a process and how it is signed.
public protocol ProgramInspecting: Sendable {
    func program(pid: Int32) async -> AskProgram?
}

/// `ps -o comm= -p <pid>` for the path (absolute on macOS), `codesign -dv --verbose=2 <path>` for the signature.
/// Signatures are cached by path and modification date.
public final class LiveProgramInspector: ProgramInspecting, @unchecked Sendable {
    private struct Cached {
        var modified: Date
        var signature: AskProgram.Signature
    }

    public let runner: CommandRunner
    public let capacity: Int
    private let lock = NSLock()
    private var cache: [String: Cached] = [:]

    public init(runner: CommandRunner, capacity: Int = 512) {
        self.runner = runner
        self.capacity = capacity
    }

    public func program(pid: Int32) async -> AskProgram? {
        guard pid > 0,
              let result = try? await runner.run(CommandInvocation("/bin/ps", ["-o", "comm=", "-p", String(pid)], timeout: 2)),
              result.succeeded
        else { return nil }
        let path = result.stdoutString.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !path.isEmpty else { return nil }
        let temporary = Self.isTemporary(path)
        guard path.hasPrefix("/"),
              let modified = (try? FileManager.default.attributesOfItem(atPath: path))?[.modificationDate] as? Date
        else { return AskProgram(path: path, signature: .unknown, inTemporaryFolder: temporary) }

        if let cached = lock.withLock({ cache[path] }), cached.modified == modified {
            return AskProgram(path: path, signature: cached.signature, inTemporaryFolder: temporary)
        }
        let signature: AskProgram.Signature
        if let check = try? await runner.run(CommandInvocation("/usr/bin/codesign", ["-dv", "--verbose=2", path], timeout: 3)) {
            signature = CodesignOutput.signature(stderr: check.stderrString + check.stdoutString, exitCode: check.exitCode)
        } else {
            signature = .unknown
        }
        if signature != .unknown {
            lock.withLock {
                if cache.count >= capacity { cache.removeAll(keepingCapacity: true) }
                cache[path] = Cached(modified: modified, signature: signature)
            }
        }
        return AskProgram(path: path, signature: signature, inTemporaryFolder: temporary)
    }

    /// Under `/tmp`, `/private/tmp`, `/var/folders`, `/private/var/folders`, or a directory named `tmp`.
    public static func isTemporary(_ path: String) -> Bool {
        let prefixes = ["/tmp/", "/private/tmp/", "/var/folders/", "/private/var/folders/"]
        if prefixes.contains(where: path.hasPrefix) { return true }
        return path.split(separator: "/").dropLast().contains("tmp")
    }
}

/// Reads what `codesign -dv --verbose=2` writes to stderr.
public enum CodesignOutput {
    public static func signature(stderr text: String, exitCode: Int32) -> AskProgram.Signature {
        if text.contains("code object is not signed at all") { return .unsigned }
        guard exitCode == 0 else { return .unknown }
        var authorities: [String] = []
        var team: String?
        var adHoc = false
        for raw in text.split(whereSeparator: \.isNewline) {
            let line = raw.trimmingCharacters(in: .whitespaces)
            if line.hasPrefix("Authority=") {
                authorities.append(String(line.dropFirst("Authority=".count)))
            } else if line.hasPrefix("TeamIdentifier=") {
                let value = String(line.dropFirst("TeamIdentifier=".count))
                team = value == "not set" || value.isEmpty ? nil : value
            } else if line == "Signature=adhoc" || (line.hasPrefix("CodeDirectory ") && line.contains("adhoc")) {
                adHoc = true
            }
        }
        if let first = authorities.first {
            if first == "Software Signing" || first.hasPrefix("Apple Mac OS Application Signing") { return .apple }
            return .developer(team: team)
        }
        if adHoc { return .adHoc }
        return .unknown
    }
}
