import Foundation
import SandvaultCore

/// Shared terminal output. Text goes to stdout, diagnostics to stderr; no colors when not a TTY.
enum Output {
    static func json<T: Encodable>(_ value: T) throws {
        let data = try JSONCoding.encoder.encode(value)
        FileHandle.standardOutput.write(data)
        FileHandle.standardOutput.write(Data("\n".utf8))
    }

    static func line(_ text: String = "") {
        print(text)
    }

    static func error(_ text: String) {
        FileHandle.standardError.write(Data("error: \(text)\n".utf8))
    }

    /// Left-aligned columns separated by two spaces; the last column is not padded.
    static func table(_ header: [String], _ rows: [[String]]) {
        let all = [header] + rows
        let widths = header.indices.map { column in all.map { $0.indices.contains(column) ? $0[column].count : 0 }.max() ?? 0 }
        for row in all {
            let cells = row.enumerated().map { index, cell in
                index == row.count - 1 ? cell : cell.padding(toLength: widths[index], withPad: " ", startingAt: 0)
            }
            print(cells.joined(separator: "  "))
        }
    }

    static func symbol(_ state: CheckState) -> String {
        switch state {
        case .ok: "ok"
        case .skipped: "skip"
        case .unknown: "?"
        case .warning: "WARN"
        case .failure: "FAIL"
        }
    }
}
