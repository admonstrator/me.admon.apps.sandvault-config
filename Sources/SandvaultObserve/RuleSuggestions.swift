import Foundation
import SandvaultCore

/// Learn mode: turns violations into the smallest allow rules that would have prevented them.
///
/// - `file-read*` / `file-write*`: the file as `literal`; its directory as `subpath` once several files in
///   it were hit (never for directories fewer than three levels deep such as `/Users/alice`).
/// - `mach-lookup`: a `MachRule`. `process-exec*`: an `ExecRule` with `allow`.
/// - Network operations and everything else: no suggestion (the firewall handles network).
///
/// Suggestion and rule ids are derived from the rule itself, so repeated calls yield equal values.
public enum RuleSuggester {
    public static func suggestions(for violations: [SandboxViolation], environment: SandvaultEnvironment) -> [RuleSuggestion] {
        var files: [String: [String: [SandboxViolation]]] = [:]  // directory -> path -> hits
        var groups: [String: (proposal: RuleSuggestion.Proposal, hits: [SandboxViolation])] = [:]

        for violation in violations {
            guard let target = violation.target, !target.isEmpty else { continue }
            let operation = violation.operation
            if operation.hasPrefix("file-read") || operation.hasPrefix("file-write") {
                guard target.hasPrefix("/") else { continue }
                files[parent(of: target), default: [:]][target, default: []].append(violation)
            } else if operation == "mach-lookup" {
                let id = "mach:\(target)"
                groups[id, default: (.mach(MachRule(id: stableUUID(id), name: target, effect: .allow)), [])].hits.append(violation)
            } else if operation.hasPrefix("process-exec"), target.hasPrefix("/") {
                let id = "exec:\(target)"
                groups[id, default: (.exec(ExecRule(id: stableUUID(id), path: target, effect: .allow)), [])].hits.append(violation)
            }
        }

        for (directory, paths) in files {
            if paths.count > 1, depth(of: directory) >= 3 {
                let hits = paths.values.flatMap { $0 }
                let id = "file:subpath:\(directory)"
                groups[id] = (.file(fileRule(id: id, path: directory, match: .subpath, hits: hits, environment: environment)), hits)
            } else {
                for (path, hits) in paths {
                    let id = "file:literal:\(path)"
                    groups[id] = (.file(fileRule(id: id, path: path, match: .literal, hits: hits, environment: environment)), hits)
                }
            }
        }

        return groups.map { id, group in
            RuleSuggestion(
                id: id, proposal: group.proposal,
                occurrences: group.hits.reduce(0) { $0 + $1.occurrences },
                processes: Array(Set(group.hits.map(\.process))).sorted(),
                examples: examples(group.hits),
                lastSeen: group.hits.map(\.timestamp).max() ?? Date(timeIntervalSince1970: 0)
            )
        }
        .sorted { ($0.occurrences, $1.id) > ($1.occurrences, $0.id) }
    }

    static func fileRule(id: String, path: String, match: PathMatch, hits: [SandboxViolation], environment: SandvaultEnvironment) -> FileRule {
        let reads = hits.contains { $0.operation.hasPrefix("file-read") }
        let writes = hits.contains { $0.operation.hasPrefix("file-write") }
        let access: FileAccess = reads && writes ? .readWrite : (writes ? .write : .read)
        return FileRule(id: stableUUID(id), path: path, match: match, access: access, effect: .allow, note: foreignHomeNote(path, environment))
    }

    /// sv's profile denies `/Users` except the sandbox home and the shared workspace; the other homes are also
    /// closed by POSIX permissions, which a sandbox rule cannot open.
    static func foreignHomeNote(_ path: String, _ environment: SandvaultEnvironment) -> String? {
        let parts = path.split(separator: "/")
        guard parts.count >= 2, parts[0] == "Users", parts[1] != "Shared", parts[1] != Substring(environment.sandvaultUser) else { return nil }
        return "Inside /Users/\(parts[1]): \(environment.sandvaultUser) also needs POSIX permissions there (for example an ACL); the sandbox rule alone does not grant access."
    }

    static func examples(_ hits: [SandboxViolation]) -> [String] {
        var seen: Set<String> = []
        var result: [String] = []
        for hit in hits.sorted(by: { $0.timestamp > $1.timestamp }) {
            let text = "\(hit.operation) \(hit.target ?? "")"
            if seen.insert(text).inserted { result.append(text) }
            if result.count == 5 { break }
        }
        return result
    }

    static func parent(of path: String) -> String {
        guard let slash = path.dropLast().lastIndex(of: "/"), slash != path.startIndex else { return "/" }
        return String(path[..<slash])
    }

    static func depth(of path: String) -> Int {
        path.split(separator: "/").count
    }

    /// A UUID derived from `text` (two 64-bit FNV-1a hashes), so equal rules get equal ids.
    static func stableUUID(_ text: String) -> UUID {
        func fnv(_ seed: UInt64) -> UInt64 {
            var hash = seed
            for byte in text.utf8 {
                hash ^= UInt64(byte)
                hash &*= 0x0000_0100_0000_01B3
            }
            return hash
        }
        let high = fnv(0xCBF2_9CE4_8422_2325)
        let low = fnv(0x8422_2325_CBF2_9CE4)
        var bytes = (0..<8).map { UInt8(truncatingIfNeeded: high >> (56 - 8 * $0)) } + (0..<8).map { UInt8(truncatingIfNeeded: low >> (56 - 8 * $0)) }
        bytes[6] = (bytes[6] & 0x0F) | 0x50  // version and variant bits of a name-based UUID
        bytes[8] = (bytes[8] & 0x3F) | 0x80
        return UUID(uuid: (
            bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7],
            bytes[8], bytes[9], bytes[10], bytes[11], bytes[12], bytes[13], bytes[14], bytes[15]
        ))
    }
}
