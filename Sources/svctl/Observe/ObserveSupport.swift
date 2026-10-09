import Foundation
import SandvaultCore
#if canImport(Darwin)
import Darwin
#elseif canImport(Glibc)
import Glibc
#endif

enum ObservePlatform {
    /// The observe commands read macOS-only tools (dscl, lsof as the sandbox user, nettop, log).
    static func require(_ command: String) throws {
        #if !os(macOS)
        throw SandvaultError.unsupportedPlatform("`svctl \(command)` inspects macOS accounts, processes, sockets and logs; run it on the Mac")
        #endif
    }
}

/// Text formatting shared by the observe commands.
enum Format {
    /// `2d 03:04:05`, `1:02:03`, `02:03`.
    static func duration(_ seconds: Int) -> String {
        let days = seconds / 86_400, hours = seconds / 3600 % 24, minutes = seconds / 60 % 60, rest = seconds % 60
        let clock = hours > 0 || days > 0
            ? String(format: "%02ld:%02ld:%02ld", hours, minutes, rest)
            : String(format: "%02ld:%02ld", minutes, rest)
        return days > 0 ? "\(days)d \(clock)" : clock
    }

    static func bytes(_ count: Int64) -> String {
        let units = ["B", "KB", "MB", "GB", "TB"]
        var value = Double(count)
        var unit = 0
        while value >= 1000, unit < units.count - 1 {
            value /= 1000
            unit += 1
        }
        return unit == 0 ? "\(count) B" : String(format: "%.1f ", value) + units[unit]
    }

    static func endpoint(_ address: String?, _ port: UInt16?, family: AddressFamily) -> String {
        guard let address else { return "-" }
        let host = family == .ipv6 && address != "*" ? "[\(address)]" : address
        return "\(host):\(port.map { $0 == 0 ? "*" : String($0) } ?? "*")"
    }

    static func shortSession(_ id: String?) -> String {
        id.map { String($0.prefix(8)) } ?? "-"
    }

    static func helper(_ helper: HostHelperProcess) -> String {
        "\(helper.kind.rawValue)" + (helper.port.map { ":\($0)" } ?? "")
    }

    /// Long command lines are cut on a terminal, kept whole when piped.
    static func command(_ text: String, indent: Int = 0) -> String {
        let line = String(repeating: "  ", count: indent) + text
        guard isatty(STDOUT_FILENO) == 1, line.count > 120 else { return line }
        return String(line.prefix(117)) + "..."
    }

    /// Local wall-clock time, `HH:mm:ss`.
    static func time(_ date: Date) -> String {
        let parts = Calendar.current.dateComponents([.hour, .minute, .second], from: date)
        return String(format: "%02ld:%02ld:%02ld", parts.hour ?? 0, parts.minute ?? 0, parts.second ?? 0)
    }
}
