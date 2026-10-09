import Foundation

/// A marked region inside a file someone else owns (sv's sandbox profile, the sandbox user's `.zshenv`).
/// Exactly one block exists after `replace`; text outside the markers is never touched.
public struct ManagedBlock: Sendable, Equatable {
    public var begin: String
    public var end: String

    /// `commentPrefix` is `;;` for SBPL and `#` for shell files.
    public init(name: String, commentPrefix: String) {
        begin = "\(commentPrefix) >>> sandvault-config: \(name) (managed, do not edit) >>>"
        end = "\(commentPrefix) <<< sandvault-config: \(name) <<<"
    }

    public static let sandboxProfile = ManagedBlock(name: "rules", commentPrefix: ";;")
    public static let zshenv = ManagedBlock(name: "network", commentPrefix: "#")

    /// The body between the markers (without the marker lines), or `nil` when absent or malformed.
    public func extract(from text: String) -> String? {
        guard let range = blockRange(in: text) else { return nil }
        let inner = text[range].dropFirst(begin.count)
        guard let endRange = inner.range(of: end, options: .backwards) else { return nil }
        var body = String(inner[inner.startIndex..<endRange.lowerBound])
        if body.hasPrefix("\n") { body.removeFirst() }
        if body.hasSuffix("\n") { body.removeLast() }
        return body
    }

    public func contains(in text: String) -> Bool { extract(from: text) != nil }

    /// Replaces the existing block (or appends one) with `body`. Any duplicate blocks are collapsed into one.
    public func replace(in text: String, with body: String) -> String {
        var base = remove(from: text)
        if !base.isEmpty && !base.hasSuffix("\n") { base += "\n" }
        if !base.isEmpty && !base.hasSuffix("\n\n") { base += "\n" }
        let trimmedBody = body.hasSuffix("\n") ? String(body.dropLast()) : body
        return base + begin + "\n" + trimmedBody + "\n" + end + "\n"
    }

    /// Removes every block and the blank line that separated it from the preceding text.
    public func remove(from text: String) -> String {
        var result = text
        while let range = blockRange(in: result) {
            var lower = range.lowerBound
            var upper = range.upperBound
            if upper < result.endIndex, result[upper] == "\n" { upper = result.index(after: upper) }
            if lower > result.startIndex {
                let before = result.index(before: lower)
                if result[before] == "\n", before > result.startIndex, result[result.index(before: before)] == "\n" {
                    lower = before
                }
            }
            result.removeSubrange(lower..<upper)
        }
        return result
    }

    private func blockRange(in text: String) -> Range<String.Index>? {
        guard let start = text.range(of: begin),
              let stop = text.range(of: end, range: start.upperBound..<text.endIndex)
        else { return nil }
        return start.lowerBound..<stop.upperBound
    }
}
