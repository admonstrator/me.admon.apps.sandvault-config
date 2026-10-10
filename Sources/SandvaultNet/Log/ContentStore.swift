import Foundation
import SandvaultCore

/// Request and response bodies netd kept (D43): `<directory>/<id>` holds the bytes, `<directory>/<id>.json` the
/// `StoredContent`. Writes run on a serial queue, away from the event loops; reads wait for the writes queued before.
public final class ContentStore: @unchecked Sendable {
    /// Upper bound for one kept body whatever the settings say, so a served content fits a control line.
    public static let maxBodyBytes = 16 << 20

    public let directory: String
    private let queue = DispatchQueue(label: "sandvault-netd.contents")
    private let log: @Sendable (String) -> Void
    /// Bytes under `directory`; `nil` until the first scan. Confined to `queue`.
    private var total: Int64?

    public init(directory: String, log: @escaping @Sendable (String) -> Void = { _ in }) {
        self.directory = directory
        self.log = log
    }

    /// Writes the bytes and their sidecar in the background. A failure is logged, never thrown.
    func save(_ meta: StoredContent, _ data: Data) {
        queue.async { [self] in
            do {
                try prepareDirectory()
                let sidecar = try JSONCoding.lineEncoder.encode(meta)
                try write(data, to: dataPath(meta.id))
                try write(sidecar, to: sidecarPath(meta.id))
                total = total.map { $0 + Int64(data.count + sidecar.count) }
            } catch {
                log("stored content \(meta.id.uuidString.lowercased()): \(error)")
            }
        }
    }

    /// The content with `id`, or `nil` when there is none (never stored, removed, or unreadable).
    public func content(id: UUID) -> (StoredContent, Data)? {
        queue.sync {
            guard let sidecar = FileManager.default.contents(atPath: sidecarPath(id)),
                  let meta = try? JSONCoding.decoder.decode(StoredContent.self, from: sidecar), meta.id == id,
                  let data = FileManager.default.contents(atPath: dataPath(id))
            else { return nil }
            return (meta, data)
        }
    }

    /// Deletes every file under the directory.
    public func clear() throws {
        try queue.sync {
            for name in try names() {
                try FileManager.default.removeItem(atPath: "\(directory)/\(name)")
            }
            total = 0
        }
    }

    /// Deletes files last modified more than `retentionDays` (at least one) before `now`; returns how many.
    @discardableResult
    public func prune(retentionDays: Int, now: Date = Date()) -> Int {
        queue.sync {
            let cutoff = now.addingTimeInterval(-Double(max(1, retentionDays)) * 86_400)
            var removed = 0
            var bytes: Int64 = 0
            for (path, attributes) in files() {
                let modified = attributes[.modificationDate] as? Date ?? now
                if modified < cutoff, (try? FileManager.default.removeItem(atPath: path)) != nil {
                    removed += 1
                } else {
                    bytes += Self.size(attributes)
                }
            }
            total = bytes
            return removed
        }
    }

    /// Bytes on disk, data and sidecars together.
    public var totalBytes: Int64 {
        queue.sync {
            if let total { return total }
            let bytes = files().reduce(Int64(0)) { $0 + Self.size($1.1) }
            total = bytes
            return bytes
        }
    }

    // MARK: - Internals

    private func dataPath(_ id: UUID) -> String { "\(directory)/\(id.uuidString)" }
    private func sidecarPath(_ id: UUID) -> String { "\(directory)/\(id.uuidString).json" }

    private func names() throws -> [String] {
        guard FileManager.default.fileExists(atPath: directory) else { return [] }
        return try FileManager.default.contentsOfDirectory(atPath: directory)
    }

    private func files() -> [(String, [FileAttributeKey: Any])] {
        ((try? names()) ?? []).compactMap { name in
            let path = "\(directory)/\(name)"
            guard let attributes = try? FileManager.default.attributesOfItem(atPath: path) else { return nil }
            return (path, attributes)
        }
    }

    private static func size(_ attributes: [FileAttributeKey: Any]) -> Int64 {
        (attributes[.size] as? NSNumber)?.int64Value ?? 0
    }

    /// Creates the directory (0700) or tightens an existing one.
    private func prepareDirectory() throws {
        try FileManager.default.createDirectory(atPath: directory, withIntermediateDirectories: true, attributes: [.posixPermissions: 0o700])
        try FileManager.default.setAttributes([.posixPermissions: 0o700], ofItemAtPath: directory)
    }

    private func write(_ data: Data, to path: String) throws {
        guard FileManager.default.createFile(atPath: path, contents: data, attributes: [.posixPermissions: 0o600]) else {
            throw SandvaultError.io("cannot write \(path)")
        }
    }
}
