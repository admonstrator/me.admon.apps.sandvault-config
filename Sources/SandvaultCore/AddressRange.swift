import Foundation

/// An IPv4 or IPv6 network in CIDR notation. Used by the pf generator (LAN guard, exceptions)
/// and by the proxy (refusing private destinations).
public struct AddressRange: Sendable, Equatable, Hashable, CustomStringConvertible, Codable {
    public let family: AddressFamily
    /// Network address bytes (4 or 16), already masked.
    public let bytes: [UInt8]
    public let prefixLength: Int

    /// Parses `10.0.0.0/8`, `fe80::/10`, or a single address (`/32`, `/128` implied).
    public init?(_ text: String) {
        let parts = text.split(separator: "/", omittingEmptySubsequences: false)
        guard parts.count == 1 || parts.count == 2 else { return nil }
        guard let (family, raw) = AddressRange.parseAddress(String(parts[0])) else { return nil }
        let maxPrefix = raw.count * 8
        let prefix: Int
        if parts.count == 2 {
            guard let value = Int(parts[1]), (0...maxPrefix).contains(value) else { return nil }
            prefix = value
        } else {
            prefix = maxPrefix
        }
        self.family = family
        self.prefixLength = prefix
        self.bytes = AddressRange.mask(raw, prefix: prefix)
    }

    public func contains(_ address: String) -> Bool {
        guard let (family, raw) = AddressRange.parseAddress(address), family == self.family else { return false }
        return AddressRange.mask(raw, prefix: prefixLength) == bytes
    }

    public var description: String {
        let address: String
        switch family {
        case .ipv4:
            address = bytes.map(String.init).joined(separator: ".")
        case .ipv6:
            address = stride(from: 0, to: 16, by: 2)
                .map { String(UInt16(bytes[$0]) << 8 | UInt16(bytes[$0 + 1]), radix: 16) }
                .joined(separator: ":")
        }
        return "\(address)/\(prefixLength)"
    }

    public init(from decoder: Decoder) throws {
        let text = try decoder.singleValueContainer().decode(String.self)
        guard let range = AddressRange(text) else {
            throw DecodingError.dataCorrupted(.init(codingPath: decoder.codingPath, debugDescription: "invalid CIDR \(text)"))
        }
        self = range
    }

    public func encode(to encoder: Encoder) throws {
        var container = encoder.singleValueContainer()
        try container.encode(description)
    }

    /// Returns the family and raw bytes of a textual IPv4/IPv6 address (no zone ids).
    public static func parseAddress(_ text: String) -> (AddressFamily, [UInt8])? {
        if let v4 = parseIPv4(text) { return (.ipv4, v4) }
        if let v6 = parseIPv6(text) { return (.ipv6, v6) }
        return nil
    }

    static func parseIPv4(_ text: String) -> [UInt8]? {
        let parts = text.split(separator: ".", omittingEmptySubsequences: false)
        guard parts.count == 4 else { return nil }
        var result: [UInt8] = []
        for part in parts {
            guard !part.isEmpty, part.count <= 3, part.allSatisfy(\.isASCII), let value = UInt8(part) else { return nil }
            result.append(value)
        }
        return result
    }

    static func parseIPv6(_ text: String) -> [UInt8]? {
        guard text.contains(":"), !text.contains("%") else { return nil }
        var head: [UInt16] = []
        var tail: [UInt16] = []
        let halves = text.components(separatedBy: "::")
        guard halves.count <= 2 else { return nil }

        func groups(_ part: String) -> [UInt16]? {
            if part.isEmpty { return [] }
            var result: [UInt16] = []
            let pieces = part.split(separator: ":", omittingEmptySubsequences: false)
            for (index, piece) in pieces.enumerated() {
                if index == pieces.count - 1, piece.contains("."), let v4 = parseIPv4(String(piece)) {
                    result.append(UInt16(v4[0]) << 8 | UInt16(v4[1]))
                    result.append(UInt16(v4[2]) << 8 | UInt16(v4[3]))
                    continue
                }
                guard !piece.isEmpty, piece.count <= 4, let value = UInt16(piece, radix: 16) else { return nil }
                result.append(value)
            }
            return result
        }

        guard let first = groups(halves[0]) else { return nil }
        head = first
        if halves.count == 2 {
            guard let second = groups(halves[1]) else { return nil }
            tail = second
            guard head.count + tail.count < 8 else { return nil }
        } else {
            guard head.count == 8 else { return nil }
        }
        let all = head + Array(repeating: 0, count: 8 - head.count - tail.count) + tail
        return all.flatMap { [UInt8($0 >> 8), UInt8($0 & 0xFF)] }
    }

    static func mask(_ raw: [UInt8], prefix: Int) -> [UInt8] {
        raw.enumerated().map { index, byte in
            let bitsBefore = index * 8
            if prefix >= bitsBefore + 8 { return byte }
            if prefix <= bitsBefore { return 0 }
            let keep = prefix - bitsBefore
            return byte & UInt8(truncatingIfNeeded: 0xFF << (8 - keep))
        }
    }
}

/// Address ranges the sandbox should not reach directly (LAN guard) and the proxy must not connect to.
public enum PrivateNetworks {
    public static let loopback: [AddressRange] = ["127.0.0.0/8", "::1/128"].compactMap(AddressRange.init)

    /// RFC 1918, link-local, CGNAT, IPv6 ULA and link-local, multicast.
    public static let lan: [AddressRange] = [
        "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "169.254.0.0/16", "100.64.0.0/10",
        "224.0.0.0/4", "fc00::/7", "fe80::/10", "ff00::/8",
    ].compactMap(AddressRange.init)

    /// "This network" and other never-routable targets.
    public static let unroutable: [AddressRange] = ["0.0.0.0/8", "::/128"].compactMap(AddressRange.init)

    public static var all: [AddressRange] { loopback + lan + unroutable }

    public static func isPrivate(_ address: String) -> Bool {
        all.contains { $0.contains(address) }
    }
}
