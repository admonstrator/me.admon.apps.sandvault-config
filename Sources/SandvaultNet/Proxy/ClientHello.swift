/// Extracts the SNI host name from the first TLS handshake message (RFC 8446 §4.1.2, RFC 6066 §3).
/// The ClientHello may span several TLS records; everything is parsed from the buffered bytes, nothing consumed.
public enum ClientHelloParser {
    public enum Result: Sendable, Equatable {
        case needMoreData
        /// Not a TLS ClientHello (wrong content type, version or handshake type, or malformed).
        case invalid(String)
        /// A complete ClientHello; `serverName` is `nil` when it carries no SNI.
        case complete(serverName: String?)
    }

    /// Upper bound for buffering a ClientHello (records of up to 16 KiB, at most a few of them).
    public static let maximumLength = 64 * 1024

    public static func parse(_ bytes: [UInt8]) -> Result {
        // Reassemble the handshake layer from consecutive handshake records.
        var handshake: [UInt8] = []
        var offset = 0
        while true {
            if handshake.count >= 4 {
                let length = Int(handshake[1]) << 16 | Int(handshake[2]) << 8 | Int(handshake[3])
                if handshake.count >= 4 + length { break }
            }
            guard offset + 5 <= bytes.count else {
                return bytes.count >= maximumLength ? .invalid("ClientHello too large") : .needMoreData
            }
            guard bytes[offset] == 0x16 else { return .invalid("not a TLS handshake record") }
            guard bytes[offset + 1] == 0x03 else { return .invalid("unsupported record version") }
            let recordLength = Int(bytes[offset + 3]) << 8 | Int(bytes[offset + 4])
            guard recordLength > 0, recordLength <= 16_384 + 256 else { return .invalid("bad record length") }
            guard offset + 5 + recordLength <= bytes.count else {
                return bytes.count >= maximumLength ? .invalid("ClientHello too large") : .needMoreData
            }
            handshake.append(contentsOf: bytes[(offset + 5)..<(offset + 5 + recordLength)])
            offset += 5 + recordLength
        }
        guard handshake[0] == 0x01 else { return .invalid("first handshake message is not a ClientHello") }
        let length = Int(handshake[1]) << 16 | Int(handshake[2]) << 8 | Int(handshake[3])
        return parseBody(Array(handshake[4..<(4 + length)]))
    }

    private static func parseBody(_ body: [UInt8]) -> Result {
        var cursor = Cursor(bytes: body)
        guard cursor.skip(2 + 32),  // legacy_version, random
              cursor.skipVector(lengthBytes: 1),  // legacy_session_id
              cursor.skipVector(lengthBytes: 2),  // cipher_suites
              cursor.skipVector(lengthBytes: 1)  // legacy_compression_methods
        else { return .invalid("truncated ClientHello") }
        if cursor.isAtEnd { return .complete(serverName: nil) }
        guard let extensionsLength = cursor.u16(), let extensions = cursor.take(Int(extensionsLength)) else {
            return .invalid("truncated extensions")
        }
        var list = Cursor(bytes: extensions)
        while !list.isAtEnd {
            guard let type = list.u16(), let length = list.u16(), let data = list.take(Int(length)) else {
                return .invalid("truncated extension")
            }
            guard type == 0x0000 else { continue }
            var names = Cursor(bytes: data)
            guard let listLength = names.u16(), let entries = names.take(Int(listLength)) else {
                return .invalid("truncated server_name")
            }
            var entry = Cursor(bytes: entries)
            while !entry.isAtEnd {
                guard let nameType = entry.u8(), let nameLength = entry.u16(), let name = entry.take(Int(nameLength)) else {
                    return .invalid("truncated server_name entry")
                }
                if nameType == 0 {
                    guard name.allSatisfy({ $0 > 0x20 && $0 < 0x7F }) else { return .invalid("non-ASCII server_name") }
                    return .complete(serverName: String(decoding: name, as: UTF8.self))
                }
            }
            return .complete(serverName: nil)
        }
        return .complete(serverName: nil)
    }

    private struct Cursor {
        let bytes: [UInt8]
        var offset = 0

        var isAtEnd: Bool { offset >= bytes.count }

        mutating func u8() -> UInt8? {
            guard offset < bytes.count else { return nil }
            defer { offset += 1 }
            return bytes[offset]
        }

        mutating func u16() -> UInt16? {
            guard offset + 2 <= bytes.count else { return nil }
            defer { offset += 2 }
            return UInt16(bytes[offset]) << 8 | UInt16(bytes[offset + 1])
        }

        mutating func take(_ count: Int) -> [UInt8]? {
            guard offset + count <= bytes.count else { return nil }
            defer { offset += count }
            return Array(bytes[offset..<(offset + count)])
        }

        mutating func skip(_ count: Int) -> Bool {
            take(count) != nil
        }

        mutating func skipVector(lengthBytes: Int) -> Bool {
            let length: Int?
            if lengthBytes == 1 { length = u8().map(Int.init) } else { length = u16().map(Int.init) }
            guard let length else { return false }
            return skip(length)
        }
    }
}
