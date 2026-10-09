import Foundation
import SandvaultCore

/// A running ICMP tool (`ping`, `traceroute`) of the sandbox. ICMP has no port and no TCP or UDP socket of the
/// sandbox user (`ping` is setuid root), so lsof, nettop and pf's `user` rules never see it. The target is taken
/// from the command line: it is what was typed, not a resolved address.
public struct ICMPActivity: Codable, Sendable, Equatable, Identifiable {
    public var pid: Int32
    /// `ping`, `ping6`, `traceroute`, `traceroute6`, `mtr`.
    public var tool: String
    /// The host argument, `nil` when the command line has none.
    public var target: String?
    public var sessionID: String?
    public var elapsedSeconds: Int

    public var id: Int32 { pid }

    public init(pid: Int32, tool: String, target: String?, sessionID: String? = nil, elapsedSeconds: Int = 0) {
        self.pid = pid
        self.tool = tool
        self.target = target
        self.sessionID = sessionID
        self.elapsedSeconds = elapsedSeconds
    }

    static let tools: Set<String> = ["ping", "ping6", "traceroute", "traceroute6", "mtr"]

    /// ICMP tools among `processes`, sorted by pid.
    public static func find(in processes: [SandboxProcess]) -> [ICMPActivity] {
        processes.compactMap { process in
            let words = process.command.split(separator: " ").map(String.init)
            guard let first = words.first, let tool = first.split(separator: "/").last.map(String.init), tools.contains(tool) else {
                return nil
            }
            return ICMPActivity(
                pid: process.pid, tool: tool, target: target(in: words.dropFirst()), sessionID: process.sessionID,
                elapsedSeconds: process.elapsedSeconds
            )
        }
        .sorted { $0.pid < $1.pid }
    }

    /// The last word that is not an option and not a bare number (option values like `-c 5`, traceroute's
    /// trailing packet size). ps does not keep quoting, which host names and addresses never need.
    static func target(in words: ArraySlice<String>) -> String? {
        words.last { !$0.hasPrefix("-") && !$0.allSatisfy(\.isNumber) }
    }
}
