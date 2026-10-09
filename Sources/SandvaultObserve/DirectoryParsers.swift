import Foundation

/// `dscl . -read <record> [attributes]`: `Key: v1 v2` lines; a value that contains spaces is printed on the
/// following line, indented by one space.
public enum DsclParser {
    public static func parse(_ text: String) -> [String: [String]] {
        var result: [String: [String]] = [:]
        var current: String?
        for line in text.split(separator: "\n", omittingEmptySubsequences: true) {
            if line.first == " ", let key = current {
                result[key, default: []].append(line.trimmingCharacters(in: .whitespaces))
                continue
            }
            guard let colon = line.firstIndex(of: ":") else { continue }
            let key = String(line[..<colon])
            current = key
            result[key] = line[line.index(after: colon)...].split(separator: " ").map(String.init)
        }
        return result
    }
}

/// `dseditgroup -o checkmember -m <user> <group>`: `yes <user> is a member of <group>` or
/// `no <user> is NOT a member of <group>`. `nil` for anything else (unknown user or group).
public enum MembershipParser {
    public static func isMember(_ text: String) -> Bool? {
        let trimmed = text.trimmingCharacters(in: .whitespacesAndNewlines)
        if trimmed.hasPrefix("yes "), trimmed.contains(" is a member of ") { return true }
        if trimmed.hasPrefix("no "), trimmed.contains(" is NOT a member of ") { return false }
        return nil
    }
}

/// One directory as `ls -led` prints it, ACL entries included.
public struct DirectoryListing: Sendable, Equatable {
    public struct ACLEntry: Sendable, Equatable {
        /// `group:sandvault-alice`, `user:alice`, `group:everyone`.
        public var principal: String
        public var allow: Bool
        public var inherited: Bool
        /// Rights and inheritance flags as listed (`list`, `add_file`, ..., `file_inherit`).
        public var rights: [String]
    }

    /// `drwxrwx---` without the trailing `+`/`@`.
    public var mode: String
    public var owner: String
    public var group: String
    public var acl: [ACLEntry]

    /// Permission bits from the mode string (`rwxrwx---` -> 0o770), ignoring setuid/sticky letters.
    public var permissions: Int {
        mode.dropFirst().prefix(9).enumerated().reduce(0) { bits, item in
            bits | (item.element == "-" || item.element == "S" || item.element == "T" ? 0 : 1 << (8 - item.offset))
        }
    }
}

public enum LsParser {
    /// Parses `ls -led <directory>`: the long line, then ` <n>: <principal> [inherited] allow|deny <rights>` lines.
    public static func parseDirectory(_ text: String) -> DirectoryListing? {
        let lines = text.split(separator: "\n", omittingEmptySubsequences: true)
        guard let first = lines.first else { return nil }
        let fields = first.split(separator: " ", omittingEmptySubsequences: true)
        guard fields.count >= 4, fields[0].count >= 10 else { return nil }
        var acl: [DirectoryListing.ACLEntry] = []
        for line in lines.dropFirst() {
            let words = line.split(separator: " ")
            guard words.count >= 3, words[0].hasSuffix(":"), Int(words[0].dropLast()) != nil else { continue }
            var rest = words.dropFirst()
            let principal = String(rest.removeFirst())
            let inherited = rest.first == "inherited"
            if inherited { rest.removeFirst() }
            guard let verdict = rest.first, verdict == "allow" || verdict == "deny" else { continue }
            rest.removeFirst()
            let rights = rest.joined(separator: " ").split(separator: ",").map { String($0) }
            acl.append(.init(principal: principal, allow: verdict == "allow", inherited: inherited, rights: rights))
        }
        return DirectoryListing(mode: String(fields[0].prefix(10)), owner: String(fields[2]), group: String(fields[3]), acl: acl)
    }
}

public enum SvVersionParser {
    /// `sv version 1.32.0` -> `1.32.0`.
    public static func parse(_ text: String) -> String? {
        guard let line = text.split(separator: "\n").first, let last = line.split(separator: " ").last,
              last.first?.isNumber == true, last.allSatisfy({ $0.isNumber || $0 == "." })
        else { return nil }
        return String(last)
    }
}
