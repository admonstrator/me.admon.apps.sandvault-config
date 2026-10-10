import Foundation
import SandvaultCore
#if canImport(Darwin)
import Darwin
#elseif canImport(Glibc)
import Glibc
#endif

/// `FileActivityEvent`s as JSON Lines in `AppPaths.activityLog` (D45): file 0600, directory 0700.
/// Appends use O_APPEND, so svctl and the app can record at the same time without tearing lines.
public actor ActivityStore {
    public let path: String

    public init(path: String) {
        self.path = path
    }

    public func append(_ events: [FileActivityEvent]) throws {
        guard !events.isEmpty else { return }
        let data = try Self.encode(events)
        let directory = (path as NSString).deletingLastPathComponent
        try FileManager.default.createDirectory(atPath: directory, withIntermediateDirectories: true, attributes: [.posixPermissions: 0o700])
        let fd = open(path, O_WRONLY | O_APPEND | O_CREAT, 0o600)
        guard fd >= 0 else { throw SandvaultError.io("cannot open \(path): errno \(errno)") }
        defer { close(fd) }
        let failed = data.withUnsafeBytes { buffer -> Bool in
            guard var base = buffer.baseAddress else { return false }
            var remaining = buffer.count
            while remaining > 0 {
                let written = write(fd, base, remaining)
                if written < 0 {
                    if errno == EINTR { continue }
                    return true
                }
                remaining -= written
                base += written
            }
            return false
        }
        if failed { throw SandvaultError.io("cannot write \(path): errno \(errno)") }
    }

    /// Stored events, oldest first, newer than `since` when given. Entries older than `retentionDays`
    /// (when above 0) and lines that do not decode are removed from the file.
    public func read(since: Date?, retentionDays: Int, now: Date) throws -> [FileActivityEvent] {
        guard let data = FileManager.default.contents(atPath: path) else { return [] }
        let cutoff = retentionDays > 0 ? now.addingTimeInterval(-Double(retentionDays) * 86_400) : nil
        var kept: [FileActivityEvent] = []
        var dropped = false
        for line in data.split(separator: 0x0A) where !line.isEmpty {
            guard let event = try? JSONCoding.decoder.decode(FileActivityEvent.self, from: Data(line)) else {
                dropped = true
                continue
            }
            if let cutoff, event.timestamp < cutoff {
                dropped = true
                continue
            }
            kept.append(event)
        }
        if dropped { try rewrite(kept) }
        guard let since else { return kept }
        return kept.filter { $0.timestamp > since }
    }

    public func clear() throws {
        guard FileManager.default.fileExists(atPath: path) else { return }
        do {
            try FileManager.default.removeItem(atPath: path)
        } catch {
            throw SandvaultError.io("cannot delete \(path): \(error)")
        }
    }

    public func sizeBytes() -> Int64 {
        let size = (try? FileManager.default.attributesOfItem(atPath: path))?[.size]
        return (size as? NSNumber)?.int64Value ?? 0
    }

    private func rewrite(_ events: [FileActivityEvent]) throws {
        try AtomicFile.write(try Self.encode(events), to: path, permissions: 0o600)
    }

    static func encode(_ events: [FileActivityEvent]) throws -> Data {
        var data = Data()
        for event in events {
            data.append(try JSONCoding.lineEncoder.encode(event))
            data.append(0x0A)
        }
        return data
    }
}
