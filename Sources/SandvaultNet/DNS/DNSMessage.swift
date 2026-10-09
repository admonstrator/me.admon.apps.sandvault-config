import SandvaultCore

/// Minimal DNS wire format (RFC 1035): header, questions and answer records. Names are read with
/// compression pointers; synthesized answers point back at the question name. Authority and additional
/// sections are skipped, upstream answers are relayed as received.
public struct DNSMessage: Sendable, Equatable {
    public var id: UInt16
    public var flags: UInt16
    public var questions: [DNSQuestion]
    public var answers: [DNSRecord]

    public init(id: UInt16, flags: UInt16, questions: [DNSQuestion], answers: [DNSRecord] = []) {
        self.id = id
        self.flags = flags
        self.questions = questions
        self.answers = answers
    }

    public var isResponse: Bool { flags & 0x8000 != 0 }
    public var opcode: UInt8 { UInt8((flags >> 11) & 0x0F) }
    public var isTruncated: Bool { flags & 0x0200 != 0 }
    public var recursionDesired: Bool { flags & 0x0100 != 0 }
    public var rcode: DNSResponseCode { DNSResponseCode(rawValue: UInt8(flags & 0x000F)) ?? .serverFailure }

    /// Addresses of the A and AAAA answers, in order.
    public var answerAddresses: [String] { answers.compactMap(\.address) }

    // MARK: Decoding

    public init(bytes: [UInt8]) throws {
        var reader = DNSReader(bytes: bytes)
        id = try reader.u16()
        flags = try reader.u16()
        let questionCount = try reader.u16()
        let answerCount = try reader.u16()
        _ = try reader.u16()  // authority
        _ = try reader.u16()  // additional
        questions = []
        for _ in 0..<questionCount {
            questions.append(DNSQuestion(name: try reader.name(), type: try reader.u16(), recordClass: try reader.u16()))
        }
        answers = []
        for _ in 0..<answerCount {
            let name = try reader.name()
            let type = try reader.u16()
            let recordClass = try reader.u16()
            let ttl = try reader.u32()
            let length = Int(try reader.u16())
            answers.append(DNSRecord(name: name, type: type, recordClass: recordClass, ttl: ttl, data: try reader.bytes(length)))
        }
    }

    // MARK: Encoding

    /// Header, questions (uncompressed) and answers; answer names equal to the first question point at it.
    public func encoded() -> [UInt8] {
        var out: [UInt8] = []
        out.appendU16(id)
        out.appendU16(flags)
        out.appendU16(UInt16(questions.count))
        out.appendU16(UInt16(answers.count))
        out.appendU16(0)
        out.appendU16(0)
        for question in questions {
            out.appendName(question.name)
            out.appendU16(question.type)
            out.appendU16(question.recordClass)
        }
        let first = questions.first?.name.lowercased()
        for answer in answers {
            if let first, answer.name.lowercased() == first {
                out.appendU16(0xC00C)
            } else {
                out.appendName(answer.name)
            }
            out.appendU16(answer.type)
            out.appendU16(answer.recordClass)
            out.appendU32(answer.ttl)
            out.appendU16(UInt16(answer.data.count))
            out.append(contentsOf: answer.data)
        }
        return out
    }

    /// A response to `query` with its first question echoed, recursion available, and `rcode`.
    public static func response(to query: DNSMessage, rcode: DNSResponseCode, answers: [DNSRecord] = []) -> DNSMessage {
        let flags: UInt16 = 0x8000 | (query.flags & 0x7800) | (query.flags & 0x0100) | 0x0080 | UInt16(rcode.rawValue)
        return DNSMessage(id: query.id, flags: flags, questions: Array(query.questions.prefix(1)), answers: answers)
    }

    /// Best-effort error reply for bytes that did not parse; `nil` when not even the header is readable.
    public static func formatError(for bytes: [UInt8]) -> [UInt8]? {
        guard bytes.count >= 12 else { return nil }
        let id = UInt16(bytes[0]) << 8 | UInt16(bytes[1])
        return DNSMessage(id: id, flags: 0x8000 | UInt16(DNSResponseCode.formatError.rawValue), questions: []).encoded()
    }
}

public enum DNSResponseCode: UInt8, Sendable, CaseIterable {
    case noError = 0, formatError = 1, serverFailure = 2, nameError = 3, notImplemented = 4, refused = 5
}

public enum DNSRecordType {
    public static let a: UInt16 = 1
    public static let aaaa: UInt16 = 28
    public static let classIN: UInt16 = 1
}

public struct DNSQuestion: Sendable, Equatable {
    /// Dotted name without the trailing dot, as received.
    public var name: String
    public var type: UInt16
    public var recordClass: UInt16

    public init(name: String, type: UInt16, recordClass: UInt16 = DNSRecordType.classIN) {
        self.name = name
        self.type = type
        self.recordClass = recordClass
    }
}

public struct DNSRecord: Sendable, Equatable {
    public var name: String
    public var type: UInt16
    public var recordClass: UInt16
    public var ttl: UInt32
    public var data: [UInt8]

    public init(name: String, type: UInt16, recordClass: UInt16 = DNSRecordType.classIN, ttl: UInt32, data: [UInt8]) {
        self.name = name
        self.type = type
        self.recordClass = recordClass
        self.ttl = ttl
        self.data = data
    }

    /// An A or AAAA record for a textual address; `nil` when the text is not an address.
    public static func address(name: String, address: String, ttl: UInt32) -> DNSRecord? {
        guard let (family, bytes) = AddressRange.parseAddress(address) else { return nil }
        return DNSRecord(name: name, type: family == .ipv4 ? DNSRecordType.a : DNSRecordType.aaaa, ttl: ttl, data: bytes)
    }

    /// Textual address of an A or AAAA record.
    public var address: String? {
        if type == DNSRecordType.a, data.count == 4 {
            return data.map(String.init).joined(separator: ".")
        }
        if type == DNSRecordType.aaaa, data.count == 16 {
            return DNSRecord.formatIPv6(data)
        }
        return nil
    }

    /// RFC 5952 text: lowercase hex, longest zero run (at least two groups) compressed.
    static func formatIPv6(_ bytes: [UInt8]) -> String {
        let groups = stride(from: 0, to: 16, by: 2).map { UInt16(bytes[$0]) << 8 | UInt16(bytes[$0 + 1]) }
        var bestStart = -1, bestLength = 0, start = -1
        for (index, group) in groups.enumerated() {
            if group == 0 {
                if start < 0 { start = index }
                if index - start + 1 > bestLength { bestStart = start; bestLength = index - start + 1 }
            } else {
                start = -1
            }
        }
        let hex = groups.map { String($0, radix: 16) }
        guard bestLength >= 2 else { return hex.joined(separator: ":") }
        let head = hex[..<bestStart].joined(separator: ":")
        let tail = hex[(bestStart + bestLength)...].joined(separator: ":")
        return head + "::" + tail
    }
}

struct DNSReader {
    let bytes: [UInt8]
    var offset = 0

    init(bytes: [UInt8]) {
        self.bytes = bytes
    }

    mutating func u16() throws -> UInt16 {
        guard offset + 2 <= bytes.count else { throw DNSError.truncated }
        defer { offset += 2 }
        return UInt16(bytes[offset]) << 8 | UInt16(bytes[offset + 1])
    }

    mutating func u32() throws -> UInt32 {
        UInt32(try u16()) << 16 | UInt32(try u16())
    }

    mutating func bytes(_ count: Int) throws -> [UInt8] {
        guard offset + count <= bytes.count else { throw DNSError.truncated }
        defer { offset += count }
        return Array(bytes[offset..<offset + count])
    }

    /// Reads a possibly compressed name; pointers must point backwards (no loops).
    mutating func name() throws -> String {
        var labels: [String] = []
        var position = offset
        var jumped = false
        var length = 0
        while true {
            guard position < bytes.count else { throw DNSError.truncated }
            let count = Int(bytes[position])
            switch count & 0xC0 {
            case 0x00:
                if count == 0 {
                    if !jumped { offset = position + 1 }
                    return labels.joined(separator: ".")
                }
                guard position + 1 + count <= bytes.count else { throw DNSError.truncated }
                length += count + 1
                guard length <= 255 else { throw DNSError.malformed("name too long") }
                labels.append(String(decoding: bytes[(position + 1)...(position + count)], as: UTF8.self))
                position += 1 + count
            case 0xC0:
                guard position + 1 < bytes.count else { throw DNSError.truncated }
                let target = (count & 0x3F) << 8 | Int(bytes[position + 1])
                guard target < position else { throw DNSError.malformed("forward compression pointer") }
                if !jumped { offset = position + 2 }
                jumped = true
                position = target
            default:
                throw DNSError.malformed("unsupported label type")
            }
        }
    }
}

enum DNSError: Error, Equatable {
    case truncated
    case malformed(String)
}

extension [UInt8] {
    mutating func appendU16(_ value: UInt16) {
        append(UInt8(value >> 8))
        append(UInt8(value & 0xFF))
    }

    mutating func appendU32(_ value: UInt32) {
        appendU16(UInt16(value >> 16))
        appendU16(UInt16(value & 0xFFFF))
    }

    mutating func appendName(_ name: String) {
        for label in name.split(separator: ".") where !label.isEmpty {
            let bytes = Array(label.utf8.prefix(63))
            append(UInt8(bytes.count))
            append(contentsOf: bytes)
        }
        append(0)
    }
}
