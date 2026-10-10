import Foundation
import SandvaultCore

/// One line of iptoasn.com's `ip2asn-v4.tsv`: `range_start range_end AS_number country_code AS_description`, tab separated.
public struct NetworkRange: Sendable, Equatable {
    public var start: UInt32
    public var end: UInt32
    public var asn: UInt32
    public var country: String?
    public var owner: String?
}

/// The IPv4 address-to-network table, sorted by range start and searched in O(log n). IPv6 is not covered.
public struct NetworkTable: Sendable {
    private struct Range {
        var start: UInt32
        var end: UInt32
        var asn: UInt32
        /// Two ASCII letters packed, 0 when unknown.
        var country: UInt16
    }

    private let ranges: [Range]
    private let owners: [UInt32: String]

    public var count: Int { ranges.count }

    /// Parses the TSV text. Lines that do not parse and unrouted ranges (AS 0) are skipped.
    public init(tsv data: Data) {
        var ranges: [Range] = []
        var owners: [UInt32: String] = [:]
        ranges.reserveCapacity(data.count / 40)
        data.withUnsafeBytes { (raw: UnsafeRawBufferPointer) in
            let bytes = raw.bindMemory(to: UInt8.self)
            var lineStart = 0
            for index in 0...bytes.count {
                guard index == bytes.count || bytes[index] == 0x0A else { continue }
                if index > lineStart, let range = Self.parse(UnsafeBufferPointer(rebasing: bytes[lineStart..<index]), owners: &owners) {
                    ranges.append(range)
                }
                lineStart = index + 1
            }
        }
        if !zip(ranges, ranges.dropFirst()).allSatisfy({ $0.start <= $1.start }) {
            ranges.sort { $0.start < $1.start }
        }
        self.ranges = ranges
        self.owners = owners
    }

    /// Parses one line; `nil` for malformed lines and AS 0.
    public static func parseLine(_ line: String) -> NetworkRange? {
        var owners: [UInt32: String] = [:]
        let bytes = Array(line.utf8)
        return bytes.withUnsafeBufferPointer { buffer in
            parse(buffer, owners: &owners).map { range in
                NetworkRange(start: range.start, end: range.end, asn: range.asn, country: unpack(range.country), owner: owners[range.asn])
            }
        }
    }

    /// Five tab-separated fields with two IPv4 addresses and an AS number (AS 0, "Not routed", included).
    public static func isWellFormed(_ line: String) -> Bool {
        let fields = line.split(separator: "\t", omittingEmptySubsequences: false)
        guard fields.count == 5 else { return false }
        return Array(fields[0].utf8).withUnsafeBufferPointer { ipv4($0) != nil }
            && Array(fields[1].utf8).withUnsafeBufferPointer { ipv4($0) != nil }
            && Array(fields[2].utf8).withUnsafeBufferPointer { number($0) != nil }
    }

    public func lookup(_ address: String) -> NetworkRange? {
        guard let (family, bytes) = AddressRange.parseAddress(address), family == .ipv4 else { return nil }
        let value = bytes.reduce(UInt32(0)) { $0 << 8 | UInt32($1) }
        var low = 0, high = ranges.count
        while low < high {
            let mid = (low + high) / 2
            if ranges[mid].start <= value { low = mid + 1 } else { high = mid }
        }
        guard low > 0 else { return nil }
        let range = ranges[low - 1]
        guard value <= range.end else { return nil }
        return NetworkRange(start: range.start, end: range.end, asn: range.asn, country: Self.unpack(range.country), owner: owners[range.asn])
    }

    private static func parse(_ line: UnsafeBufferPointer<UInt8>, owners: inout [UInt32: String]) -> Range? {
        var fields: [UnsafeBufferPointer<UInt8>] = []
        var fieldStart = 0
        for index in 0..<line.count where line[index] == 0x09 && fields.count < 4 {
            fields.append(UnsafeBufferPointer(rebasing: line[fieldStart..<index]))
            fieldStart = index + 1
        }
        var last = UnsafeBufferPointer(rebasing: line[fieldStart...])
        if last.last == 0x0D { last = UnsafeBufferPointer(rebasing: last[..<(last.count - 1)]) }
        fields.append(last)
        guard fields.count == 5, let start = ipv4(fields[0]), let end = ipv4(fields[1]), start <= end,
              let asn = number(fields[2]), asn != 0
        else { return nil }
        var country: UInt16 = 0
        if fields[3].count == 2, fields[3].allSatisfy({ (0x41...0x5A).contains($0) || (0x61...0x7A).contains($0) }) {
            country = UInt16(fields[3][0] & 0xDF) << 8 | UInt16(fields[3][1] & 0xDF)
        }
        if owners[asn] == nil {
            let owner = String(decoding: fields[4], as: UTF8.self)
            if !owner.isEmpty, owner != "Not routed" { owners[asn] = owner }
        }
        return Range(start: start, end: end, asn: asn, country: country)
    }

    private static func ipv4(_ text: UnsafeBufferPointer<UInt8>) -> UInt32? {
        var value: UInt32 = 0, octet: UInt32 = 0, dots = 0, digits = 0
        for byte in text {
            if byte == 0x2E {
                guard digits > 0, dots < 3 else { return nil }
                value = value << 8 | octet
                octet = 0
                digits = 0
                dots += 1
            } else if (0x30...0x39).contains(byte) {
                octet = octet * 10 + UInt32(byte - 0x30)
                digits += 1
                guard digits <= 3, octet <= 255 else { return nil }
            } else {
                return nil
            }
        }
        guard dots == 3, digits > 0 else { return nil }
        return value << 8 | octet
    }

    private static func number(_ text: UnsafeBufferPointer<UInt8>) -> UInt32? {
        guard !text.isEmpty, text.count <= 10 else { return nil }
        var value: UInt64 = 0
        for byte in text {
            guard (0x30...0x39).contains(byte) else { return nil }
            value = value * 10 + UInt64(byte - 0x30)
        }
        return value <= UInt64(UInt32.max) ? UInt32(value) : nil
    }

    private static func unpack(_ country: UInt16) -> String? {
        guard country != 0 else { return nil }
        return String(decoding: [UInt8(country >> 8), UInt8(country & 0xFF)], as: UTF8.self)
    }
}

/// The table at `AppPaths.networkDatabase`, loaded on first use in the background and again when the file changes.
public final class NetworkDatabase: @unchecked Sendable {
    public let path: String
    private let lock = NSLock()
    private var table: NetworkTable?
    private var loadedDate: Date?
    private var loading: Task<NetworkTable?, Never>?

    public init(path: String) {
        self.path = path
    }

    /// Starts loading if the file is there and not loaded yet; returns at once.
    public func prepare() {
        _ = currentLoad()
    }

    /// The range holding `address`; waits for a load in progress (callers bound the wait).
    public func lookup(_ address: String) async -> NetworkRange? {
        guard let load = currentLoad() else { return lock.withLock { table }?.lookup(address) }
        return await load.value?.lookup(address)
    }

    /// A load task when one is needed or running; `nil` when the loaded table is current (or there is no file).
    private func currentLoad() -> Task<NetworkTable?, Never>? {
        let date = (try? FileManager.default.attributesOfItem(atPath: path))?[.modificationDate] as? Date
        return lock.withLock {
            if let loading { return loading }
            guard let date else {
                table = nil
                loadedDate = nil
                return nil
            }
            if table != nil, loadedDate == date { return nil }
            let path = self.path
            let task = Task.detached(priority: .utility) { [weak self] () -> NetworkTable? in
                let loaded = (try? Data(contentsOf: URL(fileURLWithPath: path), options: .mappedIfSafe)).map(NetworkTable.init(tsv:))
                self?.finish(loaded, date: date)
                return loaded
            }
            loading = task
            return task
        }
    }

    private func finish(_ loaded: NetworkTable?, date: Date) {
        lock.withLock {
            table = loaded
            loadedDate = loaded == nil ? nil : date
            loading = nil
        }
    }
}
