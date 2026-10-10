import Foundation
import SandvaultCore

/// What of the helper's events is stored (D45). A value type driven only by the events' own timestamps,
/// so the same input always gives the same output.
public struct ActivityFilter: Sendable {
    /// Repeated opens and writes of one file by one program within this time are kept once.
    public static let window: TimeInterval = 60
    /// Reads of these locations are dropped with `hideSystemFiles`.
    public static let systemPrefixes = [
        "/System/", "/usr/", "/Library/", "/private/var/db/", "/bin/", "/sbin/", "/dev/",
        "/System/Volumes/Preboot/Cryptexes/",
    ]
    /// Bounds the memory of the per-minute rule when a program touches very many files.
    static let maxRemembered = 50_000

    public var settings: ActivityRecordingSettings
    private var lastKept: [Key: Date] = [:]

    public init(settings: ActivityRecordingSettings) {
        self.settings = settings
    }

    struct Key: Hashable {
        var kind: FileActivityEvent.Kind
        var forWriting: Bool
        var process: String
        var path: String
    }

    /// `true` when the event is to be stored. Remembers kept opens and writes for the per-minute rule.
    public mutating func admit(_ event: FileActivityEvent) -> Bool {
        if settings.hideSystemFiles, Self.isRead(event), Self.isSystemPath(event.path) { return false }
        if settings.openAndClose { return true }
        switch event.kind {
        case .exec, .create, .rename, .delete: return true
        case .close: return event.modified
        case .open, .write: return firstInWindow(event)
        }
    }

    private mutating func firstInWindow(_ event: FileActivityEvent) -> Bool {
        let key = Key(kind: event.kind, forWriting: event.forWriting, process: event.executable ?? event.process, path: event.path)
        if let last = lastKept[key], event.timestamp.timeIntervalSince(last) < Self.window, event.timestamp >= last {
            return false
        }
        if lastKept.count >= Self.maxRemembered {
            lastKept = lastKept.filter { event.timestamp.timeIntervalSince($0.value) < Self.window }
            if lastKept.count >= Self.maxRemembered { lastKept.removeAll() }
        }
        lastKept[key] = event.timestamp
        return true
    }

    /// An open that is not for writing, or a close that changed nothing.
    public static func isRead(_ event: FileActivityEvent) -> Bool {
        switch event.kind {
        case .open: !event.forWriting
        case .close: !event.modified
        default: false
        }
    }

    public static func isSystemPath(_ path: String) -> Bool {
        systemPrefixes.contains { path.hasPrefix($0) }
    }
}
