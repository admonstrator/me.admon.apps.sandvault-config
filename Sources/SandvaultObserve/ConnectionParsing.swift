import Foundation
import SandvaultCore

/// Parses `lsof -F pcPtnT`: one field per line, `p` opens a process set, `f` a file set inside it.
public enum LsofParser {
    public static func parse(_ text: String) -> [SandboxConnection] {
        var result: [SandboxConnection] = []
        var pid: Int32?
        var command = ""
        var file = FileFields()

        func flush() {
            if let pid, let connection = file.connection(pid: pid, process: command) { result.append(connection) }
            file = FileFields()
        }

        for line in text.split(separator: "\n") {
            guard let tag = line.first else { continue }
            let value = String(line.dropFirst())
            switch tag {
            case "p":
                flush()
                pid = Int32(value)
                command = ""
            case "c": command = value
            case "f": flush()
            case "t": file.type = value
            case "P": file.proto = value
            case "n": file.name = value
            case "T" where value.hasPrefix("ST="): file.state = String(value.dropFirst(3))
            default: break
            }
        }
        flush()
        return result
    }

    /// `127.0.0.1:443`, `[::1]:8080`, `[fe80::1%lo0]:5000`, `*:5353`, `*:*` (port 0).
    public static func endpoint(_ text: String) -> (address: String, port: UInt16)? {
        let address: String
        let portText: Substring
        if text.hasPrefix("[") {
            guard let close = text.firstIndex(of: "]"), text[text.index(after: close)...].hasPrefix(":") else { return nil }
            address = String(text[text.index(after: text.startIndex)..<close])
            portText = text[text.index(close, offsetBy: 2)...]
        } else {
            guard let colon = text.lastIndex(of: ":") else { return nil }
            address = String(text[..<colon])
            portText = text[text.index(after: colon)...]
        }
        if portText == "*" { return (address, 0) }
        guard !address.isEmpty, let port = UInt16(portText) else { return nil }
        return (address, port)
    }

    struct FileFields {
        var type: String?
        var proto: String?
        var name: String?
        var state: String?

        func connection(pid: Int32, process: String) -> SandboxConnection? {
            guard let proto = proto.flatMap({ TransportProtocol(rawValue: $0.lowercased()) }),
                  let name, let type
            else { return nil }
            let family: AddressFamily
            switch type {
            case "IPv4": family = .ipv4
            case "IPv6": family = .ipv6
            default: return nil
            }
            let parts = name.components(separatedBy: "->")
            guard let local = LsofParser.endpoint(parts[0]) else { return nil }
            let remote = parts.count > 1 ? LsofParser.endpoint(parts[1]) : nil
            return SandboxConnection(
                pid: pid, process: process, proto: proto, family: family,
                localAddress: local.address, localPort: local.port,
                remoteAddress: remote?.address, remotePort: remote?.port,
                state: proto == .tcp ? state : nil
            )
        }
    }
}

/// Parses `nettop -P -L 1 -x -J bytes_in,bytes_out` (CSV; the process column is `name.pid`).
public enum NettopParser {
    public static func parse(_ text: String) -> [ProcessTraffic] {
        var nameIndex = 0
        var inIndex = 1
        var outIndex = 2
        var byPID: [Int32: ProcessTraffic] = [:]
        for line in text.split(separator: "\n") {
            let fields = line.split(separator: ",", omittingEmptySubsequences: false).map { $0.trimmingCharacters(in: .whitespaces) }
            if let bytesIn = fields.firstIndex(of: "bytes_in"), let bytesOut = fields.firstIndex(of: "bytes_out") {
                // Header: the process column has an empty title (after `time` when that column is present).
                inIndex = bytesIn
                outIndex = bytesOut
                nameIndex = fields.firstIndex(of: "") ?? 0
                continue
            }
            guard fields.indices.contains(max(nameIndex, inIndex, outIndex)),
                  let dot = fields[nameIndex].lastIndex(of: "."),
                  let pid = Int32(fields[nameIndex][fields[nameIndex].index(after: dot)...]),
                  let bytesIn = Int64(fields[inIndex]), let bytesOut = Int64(fields[outIndex])
            else { continue }
            let name = String(fields[nameIndex][..<dot])
            byPID[pid] = ProcessTraffic(pid: pid, process: name, bytesIn: bytesIn, bytesOut: bytesOut)
        }
        return byPID.values.sorted { $0.pid < $1.pid }
    }
}
