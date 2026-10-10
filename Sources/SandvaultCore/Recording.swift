import Foundation

// What Sandvault records for the user to look at later (D42-D46): web requests with optional contents (netd),
// and files and programs the sandbox touched (the helper runs macOS's `eslogger`, the app stores the events).

// MARK: - Web traffic

/// Request or response contents netd kept for one `HTTPSummary` (D43). The bytes live in
/// `AppPaths.httpContentDir/<id>`; clients fetch them with `ControlRequest.content(id:)`.
public struct StoredContent: Codable, Sendable, Equatable, Hashable {
    public var id: UUID
    public var contentType: String?
    /// Size of the body on the wire after the transfer encoding is removed; `nil` when the stream ended early.
    public var size: Int64?
    /// Bytes kept, at most `WebRecordingSettings.maxContentBytes`.
    public var storedBytes: Int
    /// Not text (images, archives, compressed bodies netd did not decode); the app shows a note instead.
    public var binary: Bool

    public init(id: UUID = UUID(), contentType: String?, size: Int64?, storedBytes: Int, binary: Bool) {
        self.id = id
        self.contentType = contentType
        self.size = size
        self.storedBytes = storedBytes
        self.binary = binary
    }

    /// Fewer bytes kept than were sent.
    public var truncated: Bool {
        guard let size else { return true }
        return Int64(storedBytes) < size
    }
}

/// Settings > Recording > Web traffic. Lives in `NetworkPolicy`, because netd records.
public struct WebRecordingSettings: Codable, Sendable, Equatable {
    /// Method, address, status, sizes and redacted headers of each request netd can see (plain HTTP, and HTTPS
    /// only with inspection). Off: connections are still logged, without `HTTPSummary`s.
    public var requests: Bool
    /// Also keep request and response bodies (D43). Bodies are stored as sent; only headers are redacted.
    public var contents: Bool
    public var maxContentBytes: Int
    /// Stored contents older than this are deleted.
    public var retentionDays: Int

    public init(requests: Bool = true, contents: Bool = false, maxContentBytes: Int = 1_048_576, retentionDays: Int = 7) {
        self.requests = requests
        self.contents = contents
        self.maxContentBytes = maxContentBytes
        self.retentionDays = retentionDays
    }

    enum CodingKeys: String, CodingKey { case requests, contents, maxContentBytes, retentionDays }

    public init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        let d = WebRecordingSettings()
        requests = try c.value(.requests, default: d.requests)
        contents = try c.value(.contents, default: d.contents)
        maxContentBytes = try c.value(.maxContentBytes, default: d.maxContentBytes)
        retentionDays = try c.value(.retentionDays, default: d.retentionDays)
    }
}

// MARK: - Files and programs

/// One thing a sandbox process did, as the helper reports it from `eslogger` (D44).
public struct FileActivityEvent: Codable, Sendable, Equatable, Hashable, Identifiable {
    public enum Kind: String, Codable, Sendable, CaseIterable {
        /// A program was started (`path` is the executable, `arguments` its argv).
        case exec
        case open
        case close
        case create
        /// Data was written to an open file.
        case write
        /// `path` was renamed or moved to `destination`.
        case rename
        /// `path` was removed (unlink).
        case delete
    }

    public var id: UUID
    public var timestamp: Date
    public var kind: Kind
    public var path: String
    /// `rename` only.
    public var destination: String?
    public var pid: Int32
    /// Short name of the process (`claude`, `node`).
    public var process: String
    /// Full path of the process's executable.
    public var executable: String?
    /// `open` only: opened for writing.
    public var forWriting: Bool
    /// `close` only: the file was changed while open.
    public var modified: Bool
    /// `exec` only.
    public var arguments: [String]

    public init(
        id: UUID = UUID(), timestamp: Date, kind: Kind, path: String, destination: String? = nil, pid: Int32,
        process: String, executable: String? = nil, forWriting: Bool = false, modified: Bool = false, arguments: [String] = []
    ) {
        self.id = id
        self.timestamp = timestamp
        self.kind = kind
        self.path = path
        self.destination = destination
        self.pid = pid
        self.process = process
        self.executable = executable
        self.forWriting = forWriting
        self.modified = modified
        self.arguments = arguments
    }
}

/// Settings > Recording > Files & programs. Lives in `AppConfig`, because the app runs the recorder.
public struct ActivityRecordingSettings: Codable, Sendable, Equatable {
    /// Off by default: the recorder needs the helper and Full Disk Access (D44).
    public var enabled: Bool
    /// Keep every `open` and `close`; without it only closes that changed a file, plus create, write, rename,
    /// delete and exec are stored, and plain reads are kept as one `open` per file and minute.
    public var openAndClose: Bool
    /// Drop reads under `/System`, `/usr`, `/Library`, `/private/var/db` and the dyld cache before storing.
    public var hideSystemFiles: Bool
    public var retentionDays: Int

    public init(enabled: Bool = false, openAndClose: Bool = false, hideSystemFiles: Bool = true, retentionDays: Int = 7) {
        self.enabled = enabled
        self.openAndClose = openAndClose
        self.hideSystemFiles = hideSystemFiles
        self.retentionDays = retentionDays
    }

    enum CodingKeys: String, CodingKey { case enabled, openAndClose, hideSystemFiles, retentionDays }

    public init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        let d = ActivityRecordingSettings()
        enabled = try c.value(.enabled, default: d.enabled)
        openAndClose = try c.value(.openAndClose, default: d.openAndClose)
        hideSystemFiles = try c.value(.hideSystemFiles, default: d.hideSystemFiles)
        retentionDays = try c.value(.retentionDays, default: d.retentionDays)
    }
}

/// Why recording files and programs cannot run.
public enum ActivityRecorderFailure: Error, Codable, Sendable, Equatable, CustomStringConvertible {
    /// macOS refused the event recorder: Sandvault Config needs Full Disk Access.
    case needsFullDiskAccess
    /// The helper is not installed, or its sudoers rule predates `activity-record` (reinstall it).
    case needsHelper
    case unavailable(String)

    public var description: String {
        switch self {
        case .needsFullDiskAccess: "Sandvault Config needs Full Disk Access to record files and programs."
        case .needsHelper: "Install or reinstall the helper to record files and programs."
        case .unavailable(let detail): "Recording files and programs is unavailable: \(detail)"
        }
    }
}

/// One NDJSON line of `svctl-helper activity-record --json` on stdout.
public enum ActivityStreamLine: Codable, Sendable, Equatable {
    /// `eslogger` is running for the sandbox user's uid.
    case started(uid: UInt32)
    case event(FileActivityEvent)
    /// The recorder stopped; the helper exits non-zero after this line.
    case failed(ActivityRecorderFailure)
}

/// The app's recorder: runs the helper stream, filters by the settings and stores what it keeps.
public protocol ActivityRecording: Sendable {
    /// Events as they are stored. Finishes when the task is cancelled; throws `ActivityRecorderFailure`.
    func record(settings: ActivityRecordingSettings) -> AsyncThrowingStream<FileActivityEvent, Error>
    /// Stored events, oldest first, newer than `since` when given; drops what is older than the retention.
    func stored(since: Date?, retentionDays: Int) async throws -> [FileActivityEvent]
    func clear() async throws
    /// Bytes on disk.
    func storageBytes() async -> Int64
}

/// No recorder (tests, and the app until the live one is wired).
public struct NoActivityRecorder: ActivityRecording {
    public init() {}

    public func record(settings: ActivityRecordingSettings) -> AsyncThrowingStream<FileActivityEvent, Error> {
        AsyncThrowingStream { $0.finish(throwing: ActivityRecorderFailure.unavailable("not wired")) }
    }

    public func stored(since: Date?, retentionDays: Int) async throws -> [FileActivityEvent] { [] }
    public func clear() async throws {}
    public func storageBytes() async -> Int64 { 0 }
}
