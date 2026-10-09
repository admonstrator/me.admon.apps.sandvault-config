import Foundation
import SandvaultCore

/// Parsers for `ps` output and the logs of sv's host helpers.
public enum ProcessParser {
    /// Parses `ps -axww -o pid=,ppid=,user=,ruser=,%cpu=,%mem=,rss=,etime=,state=,command=`.
    /// Malformed lines are skipped. `%cpu`/`%mem` may use a decimal comma (ps honours the locale).
    public static func parse(_ text: String) -> [SandboxProcess] {
        text.split(separator: "\n").compactMap { line in
            guard let (fields, command) = splitFields(line, count: 9),
                  let pid = Int32(fields[0]), let ppid = Int32(fields[1]),
                  let elapsed = elapsedSeconds(String(fields[7]))
            else { return nil }
            return SandboxProcess(
                pid: pid, ppid: ppid, user: String(fields[2]), realUser: String(fields[3]),
                cpuPercent: decimal(fields[4]), memPercent: decimal(fields[5]), rssKiB: Int(fields[6]) ?? 0,
                elapsedSeconds: elapsed, state: String(fields[8]), command: String(command)
            )
        }
    }

    /// `[[dd-]hh:]mm:ss` as printed by `ps -o etime` into seconds.
    public static func elapsedSeconds(_ text: String) -> Int? {
        var days = 0
        var clock = Substring(text)
        if let dash = text.firstIndex(of: "-") {
            guard let value = Int(text[..<dash]) else { return nil }
            days = value
            clock = text[text.index(after: dash)...]
        }
        let parts = clock.split(separator: ":", omittingEmptySubsequences: false).map { Int($0) }
        guard (2...3).contains(parts.count), parts.allSatisfy({ $0 != nil && $0! >= 0 }) else { return nil }
        let values = parts.map { $0! }
        let seconds = values.reduce(0) { $0 * 60 + $1 }
        return days * 86_400 + seconds
    }

    /// Parses `ps -E -ww -o pid=,command=` into pid -> `SV_SESSION_ID`. Processes without one are omitted.
    public static func sessionIDs(_ text: String) -> [Int32: String] {
        var result: [Int32: String] = [:]
        for line in text.split(separator: "\n") {
            guard let (fields, rest) = splitFields(line, count: 1), let pid = Int32(fields[0]),
                  let id = sessionID(in: String(rest))
            else { continue }
            result[pid] = id
        }
        return result
    }

    /// The last `SV_SESSION_ID=<uuid>` word of a command line. `ps -E` appends the environment after the
    /// arguments, so the last occurrence is the real variable. Only a well-formed UUID is accepted.
    public static func sessionID(in commandLine: String) -> String? {
        let key = "SV_SESSION_ID="
        var found: String?
        var searchStart = commandLine.startIndex
        while let range = commandLine.range(of: key, range: searchStart..<commandLine.endIndex) {
            searchStart = range.upperBound
            if range.lowerBound > commandLine.startIndex, !commandLine[commandLine.index(before: range.lowerBound)].isWhitespace {
                continue
            }
            let value = commandLine[range.upperBound...].prefix { !$0.isWhitespace }
            if let uuid = normalizedUUID(value) { found = uuid }
        }
        return found
    }

    /// Uppercased UUID if `text` is exactly `8-4-4-4-12` hex digits.
    public static func normalizedUUID<S: StringProtocol>(_ text: S) -> String? {
        let groups = text.split(separator: "-", omittingEmptySubsequences: false)
        guard groups.map(\.count) == [8, 4, 4, 4, 12],
              groups.allSatisfy({ $0.allSatisfy(\.isHexDigit) && $0.allSatisfy(\.isASCII) })
        else { return nil }
        return text.uppercased()
    }

    /// The first `count` whitespace-separated fields and the remainder (leading blanks removed).
    static func splitFields(_ line: Substring, count: Int) -> ([Substring], Substring)? {
        var fields: [Substring] = []
        var index = line.startIndex
        while fields.count < count {
            while index < line.endIndex, line[index].isWhitespace { index = line.index(after: index) }
            guard index < line.endIndex else { return nil }
            let start = index
            while index < line.endIndex, !line[index].isWhitespace { index = line.index(after: index) }
            fields.append(line[start..<index])
        }
        while index < line.endIndex, line[index].isWhitespace { index = line.index(after: index) }
        return (fields, line[index...])
    }

    static func decimal(_ field: Substring) -> Double {
        Double(field.replacingOccurrences(of: ",", with: ".")) ?? 0
    }
}

/// Ports sv's host helpers write into their logs in `SandvaultEnvironment.sessionStateDir`.
public enum HelperLogParser {
    /// `chrome-<session>.log`: `DevTools listening on ws://127.0.0.1:<port>/devtools/browser/<id>`.
    public static func chromePort(_ log: String) -> UInt16? {
        port(after: "DevTools listening on ws://127.0.0.1:", in: log)
    }

    /// `ios-bridge-<session>.log`: `Bridge listening on http://127.0.0.1:<port>`.
    public static func bridgePort(_ log: String) -> UInt16? {
        port(after: "Bridge listening on http://127.0.0.1:", in: log)
    }

    static func port(after marker: String, in log: String) -> UInt16? {
        guard let range = log.range(of: marker) else { return nil }
        let digits = log[range.upperBound...].prefix(while: \.isNumber)
        guard let port = UInt16(digits), port > 0 else { return nil }
        return port
    }
}
