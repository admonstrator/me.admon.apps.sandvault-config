import Foundation
import SandvaultCore

/// Which records `svctl netlog` and the app show.
public struct ConnectionFilter: Sendable, Equatable {
    public var deniedOnly: Bool
    /// Case-insensitive substring of the host.
    public var host: String?

    public init(deniedOnly: Bool = false, host: String? = nil) {
        self.deniedOnly = deniedOnly
        self.host = host
    }

    public func matches(_ record: ConnectionRecord) -> Bool {
        if deniedOnly && !record.decision.blocked { return false }
        if let host, !host.isEmpty, !record.host.lowercased().contains(host.lowercased()) { return false }
        return true
    }
}

extension ConnectionDecision {
    /// Denied by a rule, by an answer, or by the fallback after an unanswered ask.
    public var blocked: Bool {
        switch self {
        case .denied, .askedDenied, .timedOut: true
        case .allowed, .askedAllowed: false
        }
    }
}

/// JSON Lines file of `ConnectionRecord`s (rotated at `maxBytes`, `keep` old files) plus an in-memory ring buffer.
public final class ConnectionLog: @unchecked Sendable {
    public let path: String
    public let maxBytes: Int
    public let keep: Int
    public let capacity: Int

    private let lock = NSLock()
    private var ring: [ConnectionRecord] = []
    private var handle: FileHandle?
    private var size = 0
    private var lastError: String?

    public init(path: String, maxBytes: Int = 10 << 20, keep: Int = 3, capacity: Int = 1000) {
        self.path = path
        self.maxBytes = maxBytes
        self.keep = keep
        self.capacity = capacity
    }

    /// Appends to the ring buffer and the file. File errors are remembered (see `takeError`) but never thrown,
    /// so logging cannot break a connection.
    public func append(_ record: ConnectionRecord) {
        lock.withLock {
            ring.append(record)
            if ring.count > capacity { ring.removeFirst(ring.count - capacity) }
            do {
                var line = try JSONCoding.lineEncoder.encode(record)
                line.append(0x0A)
                try write(line)
            } catch {
                lastError = "\(error)"
            }
        }
    }

    /// The most recent `limit` records, oldest first.
    public func recent(limit: Int) -> [ConnectionRecord] {
        lock.withLock { Array(ring.suffix(max(0, limit))) }
    }

    /// The last file error since the previous call.
    public func takeError() -> String? {
        lock.withLock {
            defer { lastError = nil }
            return lastError
        }
    }

    public func close() {
        lock.withLock {
            try? handle?.close()
            handle = nil
        }
    }

    private func write(_ line: Data) throws {
        if handle == nil { try open() }
        if size + line.count > maxBytes, size > 0 {
            try rotate()
            try open()
        }
        try handle?.write(contentsOf: line)
        size += line.count
    }

    private func open() throws {
        let directory = (path as NSString).deletingLastPathComponent
        try FileManager.default.createDirectory(atPath: directory, withIntermediateDirectories: true, attributes: [.posixPermissions: 0o700])
        if !FileManager.default.fileExists(atPath: path) {
            guard FileManager.default.createFile(atPath: path, contents: nil, attributes: [.posixPermissions: 0o600]) else {
                throw SandvaultError.io("cannot create \(path)")
            }
        }
        let fileHandle = try FileHandle(forWritingTo: URL(fileURLWithPath: path))
        size = Int(try fileHandle.seekToEnd())
        handle = fileHandle
    }

    private func rotate() throws {
        try handle?.close()
        handle = nil
        let manager = FileManager.default
        let oldest = "\(path).\(keep)"
        if manager.fileExists(atPath: oldest) { try manager.removeItem(atPath: oldest) }
        if keep > 1 {
            for index in stride(from: keep - 1, through: 1, by: -1) where manager.fileExists(atPath: "\(path).\(index)") {
                try manager.moveItem(atPath: "\(path).\(index)", toPath: "\(path).\(index + 1)")
            }
        }
        if keep > 0 {
            try manager.moveItem(atPath: path, toPath: "\(path).1")
        } else {
            try manager.removeItem(atPath: path)
        }
        size = 0
    }

    /// Reads the newest `limit` matching records from the file and its rotations, oldest first.
    /// Lines that do not decode are skipped.
    public static func read(path: String, limit: Int, filter: ConnectionFilter = ConnectionFilter(), keep: Int = 3) throws -> [ConnectionRecord] {
        var result: [ConnectionRecord] = []
        let files = [path] + (1...max(1, keep)).map { "\(path).\($0)" }
        for file in files where FileManager.default.fileExists(atPath: file) {
            let text = try String(contentsOfFile: file, encoding: .utf8)
            let records = text.split(separator: "\n").compactMap { line in
                try? JSONCoding.decoder.decode(ConnectionRecord.self, from: Data(line.utf8))
            }.filter(filter.matches)
            result = records + result
            if result.count >= limit { break }
        }
        return Array(result.suffix(max(0, limit)))
    }
}
