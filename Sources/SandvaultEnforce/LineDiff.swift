import Foundation

/// One line of a line-based diff, ready for display.
public struct DiffLine: Codable, Sendable, Equatable, Hashable {
    public enum Kind: String, Codable, Sendable { case context, added, removed }

    public var kind: Kind
    public var text: String
    /// 1-based line number in the old text (`nil` for added lines).
    public var oldLine: Int?
    /// 1-based line number in the new text (`nil` for removed lines).
    public var newLine: Int?

    public init(kind: Kind, text: String, oldLine: Int?, newLine: Int?) {
        self.kind = kind
        self.text = text
        self.oldLine = oldLine
        self.newLine = newLine
    }
}

/// Minimal LCS line diff; profiles are a few hundred lines, so the quadratic table is fine.
public enum LineDiff {
    static let maxCells = 4_000_000

    /// Every line of both texts, in order, marked as context, added or removed.
    public static func lines(old: String, new: String) -> [DiffLine] {
        let a = split(old), b = split(new)
        guard a.count * b.count <= maxCells else {
            return a.enumerated().map { DiffLine(kind: .removed, text: $1, oldLine: $0 + 1, newLine: nil) }
                + b.enumerated().map { DiffLine(kind: .added, text: $1, oldLine: nil, newLine: $0 + 1) }
        }
        // lcs[i][j] = length of the longest common subsequence of a[i...] and b[j...].
        var lcs = Array(repeating: Array(repeating: 0, count: b.count + 1), count: a.count + 1)
        for i in stride(from: a.count - 1, through: 0, by: -1) {
            for j in stride(from: b.count - 1, through: 0, by: -1) {
                lcs[i][j] = a[i] == b[j] ? lcs[i + 1][j + 1] + 1 : max(lcs[i + 1][j], lcs[i][j + 1])
            }
        }
        var result: [DiffLine] = []
        var i = 0, j = 0
        while i < a.count || j < b.count {
            if i < a.count, j < b.count, a[i] == b[j] {
                result.append(DiffLine(kind: .context, text: a[i], oldLine: i + 1, newLine: j + 1))
                i += 1
                j += 1
            } else if i < a.count, j == b.count || lcs[i + 1][j] >= lcs[i][j + 1] {
                // Removals before additions, like diff -u.
                result.append(DiffLine(kind: .removed, text: a[i], oldLine: i + 1, newLine: nil))
                i += 1
            } else {
                result.append(DiffLine(kind: .added, text: b[j], oldLine: nil, newLine: j + 1))
                j += 1
            }
        }
        return result
    }

    /// `diff -u` style text with `context` lines around each change; empty when the texts are equal.
    public static func unified(old: String, new: String, oldName: String, newName: String, context: Int = 3) -> String {
        let all = lines(old: old, new: new)
        let changed = all.indices.filter { all[$0].kind != .context }
        guard !changed.isEmpty else { return "" }

        var hunks: [ClosedRange<Int>] = []
        for index in changed {
            let range = max(0, index - context)...min(all.count - 1, index + context)
            if let last = hunks.last, range.lowerBound <= last.upperBound + 1 {
                hunks[hunks.count - 1] = last.lowerBound...max(last.upperBound, range.upperBound)
            } else {
                hunks.append(range)
            }
        }

        var output = ["--- \(oldName)", "+++ \(newName)"]
        for hunk in hunks {
            let slice = all[hunk]
            let oldCount = slice.filter { $0.kind != .added }.count
            let newCount = slice.filter { $0.kind != .removed }.count
            let oldStart = slice.compactMap(\.oldLine).first ?? (precedingLine(all, before: hunk.lowerBound, \.oldLine))
            let newStart = slice.compactMap(\.newLine).first ?? (precedingLine(all, before: hunk.lowerBound, \.newLine))
            output.append("@@ -\(oldStart),\(oldCount) +\(newStart),\(newCount) @@")
            for line in slice {
                let marker = switch line.kind {
                case .context: " "
                case .added: "+"
                case .removed: "-"
                }
                output.append(marker + line.text)
            }
        }
        return output.joined(separator: "\n") + "\n"
    }

    /// For a hunk without lines on one side, `diff -u` names the line before it (0 at the start).
    private static func precedingLine(_ all: [DiffLine], before index: Int, _ key: KeyPath<DiffLine, Int?>) -> Int {
        all[..<index].reversed().compactMap { $0[keyPath: key] }.first ?? 0
    }

    static func split(_ text: String) -> [String] {
        guard !text.isEmpty else { return [] }
        var parts = text.split(separator: "\n", omittingEmptySubsequences: false).map(String.init)
        if parts.last == "" { parts.removeLast() }
        return parts
    }
}
