import Foundation

// Lab mode (D52): while a lab session runs, the root helper takes checkpoints of the sandbox's files as APFS
// clones (sandbox home and shared workspace), records what changed between them, and can put the files back to
// any checkpoint. These types travel between the app or svctl and `svctl-helper lab` (stdin `LabRequest`,
// stdout `LabResponse`); the pure parts (change lists, findings, pruning) live here so both sides and the tests
// share them.

/// The two trees a checkpoint covers.
public enum LabRoot: String, Codable, Sendable, CaseIterable, Comparable {
    /// `/Users/sandvault-<user>`.
    case home
    /// `/Users/Shared/sv-<user>`.
    case workspace

    public func path(in environment: SandvaultEnvironment) -> String {
        switch self {
        case .home: environment.sandvaultHome
        case .workspace: environment.sharedWorkspace
        }
    }

    public var displayName: String {
        switch self {
        case .home: "Sandbox home"
        case .workspace: "Shared workspace"
        }
    }

    public static func < (lhs: LabRoot, rhs: LabRoot) -> Bool { lhs.rawValue < rhs.rawValue }
}

/// A path inside one of the roots, relative and without `.`/`..` components.
public struct LabPath: Codable, Sendable, Hashable, Comparable {
    public var root: LabRoot
    public var path: String

    public init(root: LabRoot, path: String) {
        self.root = root
        self.path = path
    }

    /// `home/.ssh/id_ed25519`: the key in manifests and change lists.
    public var key: String { "\(root.rawValue)/\(path)" }

    public init?(key: String) {
        guard let slash = key.firstIndex(of: "/"), let root = LabRoot(rawValue: String(key[..<slash])) else { return nil }
        self.init(root: root, path: String(key[key.index(after: slash)...]))
    }

    /// `~/.zshrc` for the sandbox home, `Workspace/repos/x` for the shared workspace.
    public var display: String {
        switch root {
        case .home: "~/\(path)"
        case .workspace: "Workspace/\(path)"
        }
    }

    public var name: String { path.split(separator: "/").last.map(String.init) ?? path }

    public static func < (lhs: LabPath, rhs: LabPath) -> Bool { (lhs.root, lhs.path) < (rhs.root, rhs.path) }

    /// Relative, at most 1024 bytes, no empty, `.` or `..` components, no NUL.
    public static func validate(_ path: String) throws {
        let parts = path.split(separator: "/", omittingEmptySubsequences: false)
        guard !path.isEmpty, path.utf8.count <= 1024, !path.contains("\0"),
              parts.allSatisfy({ !$0.isEmpty && $0 != "." && $0 != ".." })
        else { throw SandvaultError.invalidInput("invalid lab path '\(path)'") }
    }
}

public struct LabSettings: Codable, Sendable, Equatable {
    /// Seconds between automatic checkpoints; one is taken only when something changed.
    public var intervalSeconds: Int
    /// A checkpoint when the sandbox starts a program it did not run before in this session.
    public var checkpointOnProgramStart: Bool
    /// Older checkpoints are removed beyond this many (the start and the current one never).
    public var maxCheckpoints: Int
    /// Older checkpoints are removed while the estimated extra space exceeds this.
    public var maxStoreBytes: Int64
    /// No new checkpoint while the volume has less free space than this.
    public var minFreeBytes: Int64
    /// Paths left out of checkpoints and rewinds: they keep whatever they hold now.
    public var excludes: [LabPath]
    /// Off: only the sandbox home is checkpointed and rewound.
    public var includeWorkspace: Bool

    public static let defaultExcludes = [
        // Host-owned and read-only for the sandbox (D48); large, and the sandbox cannot change it.
        LabPath(root: .workspace, path: "android/sdk"),
    ]

    public init(
        intervalSeconds: Int = 60, checkpointOnProgramStart: Bool = true, maxCheckpoints: Int = 120,
        maxStoreBytes: Int64 = 10_000_000_000, minFreeBytes: Int64 = 5_000_000_000, excludes: [LabPath] = LabSettings.defaultExcludes,
        includeWorkspace: Bool = true
    ) {
        self.intervalSeconds = intervalSeconds
        self.checkpointOnProgramStart = checkpointOnProgramStart
        self.maxCheckpoints = maxCheckpoints
        self.maxStoreBytes = maxStoreBytes
        self.minFreeBytes = minFreeBytes
        self.excludes = excludes
        self.includeWorkspace = includeWorkspace
    }

    enum CodingKeys: String, CodingKey {
        case intervalSeconds, checkpointOnProgramStart, maxCheckpoints, maxStoreBytes, minFreeBytes, excludes, includeWorkspace
    }

    public init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        let d = LabSettings()
        intervalSeconds = try c.value(.intervalSeconds, default: d.intervalSeconds)
        checkpointOnProgramStart = try c.value(.checkpointOnProgramStart, default: d.checkpointOnProgramStart)
        maxCheckpoints = try c.value(.maxCheckpoints, default: d.maxCheckpoints)
        maxStoreBytes = try c.value(.maxStoreBytes, default: d.maxStoreBytes)
        minFreeBytes = try c.value(.minFreeBytes, default: d.minFreeBytes)
        excludes = try c.value(.excludes, default: d.excludes)
        includeWorkspace = try c.value(.includeWorkspace, default: d.includeWorkspace)
    }

    /// The roots a session with these settings covers.
    public var roots: [LabRoot] { includeWorkspace ? LabRoot.allCases : [.home] }

    /// The helper takes these from stdin, so it checks every value.
    public func validated() throws -> LabSettings {
        guard (10...3600).contains(intervalSeconds) else { throw SandvaultError.invalidInput("lab interval must be 10 to 3600 seconds") }
        guard (3...1000).contains(maxCheckpoints) else { throw SandvaultError.invalidInput("lab checkpoints must be 3 to 1000") }
        guard maxStoreBytes >= 100 << 20 else { throw SandvaultError.invalidInput("lab space limit must be at least 100 MB") }
        guard minFreeBytes >= 0 else { throw SandvaultError.invalidInput("lab free space must not be negative") }
        guard excludes.count <= 100 else { throw SandvaultError.invalidInput("at most 100 lab excludes") }
        for exclude in excludes { try LabPath.validate(exclude.path) }
        return self
    }
}

// MARK: - Manifests and changes

/// One file system object as a checkpoint saw it. Directories compare by type, mode and owner only (their
/// times change with every entry), files also by size and modification time.
public struct LabEntry: Codable, Sendable, Hashable {
    public enum Kind: String, Codable, Sendable { case file = "f", directory = "d", symlink = "l", other = "o" }

    public var kind: Kind
    public var size: Int64
    /// Permission bits.
    public var mode: UInt16
    public var uid: UInt32
    /// Modification time in nanoseconds since 1970.
    public var mtime: Int64
    /// Symlink target.
    public var target: String?

    public init(kind: Kind, size: Int64 = 0, mode: UInt16 = 0o644, uid: UInt32 = 0, mtime: Int64 = 0, target: String? = nil) {
        self.kind = kind
        self.size = size
        self.mode = mode
        self.uid = uid
        self.mtime = mtime
        self.target = target
    }

    enum CodingKeys: String, CodingKey {
        case kind = "k", size = "s", mode = "m", uid = "u", mtime = "t", target = "l"
    }

    public func sameContent(as other: LabEntry) -> Bool {
        guard kind == other.kind, mode == other.mode, uid == other.uid else { return false }
        switch kind {
        case .directory: return true
        case .symlink: return target == other.target
        case .file, .other: return size == other.size && mtime == other.mtime
        }
    }

    /// Bytes a clone holds for this entry.
    public var dataBytes: Int64 { kind == .file ? size : 0 }
}

/// Every entry below the roots, keyed by `LabPath.key`.
public typealias LabManifest = [String: LabEntry]

public struct LabChange: Codable, Sendable, Hashable, Identifiable {
    public enum Kind: String, Codable, Sendable { case created, changed, deleted }

    public var path: LabPath
    public var kind: Kind
    public var old: LabEntry?
    public var new: LabEntry?
    /// Why the new content looks like a secret (`SecretScan`), set by the helper.
    public var secret: String?

    public init(path: LabPath, kind: Kind, old: LabEntry?, new: LabEntry?, secret: String? = nil) {
        self.path = path
        self.kind = kind
        self.old = old
        self.new = new
        self.secret = secret
    }

    public var id: String { path.key }

    /// Only the mode or the owner changed.
    public var attributesOnly: Bool {
        guard kind == .changed, let old, let new else { return false }
        return old.kind == new.kind && old.size == new.size && old.mtime == new.mtime && old.target == new.target
    }
}

public enum LabDiff {
    /// What turns `old` into `new`, sorted by path.
    public static func changes(from old: LabManifest, to new: LabManifest) -> [LabChange] {
        var result: [LabChange] = []
        for (key, entry) in new {
            guard let path = LabPath(key: key) else { continue }
            if let before = old[key] {
                if !before.sameContent(as: entry) { result.append(LabChange(path: path, kind: .changed, old: before, new: entry)) }
            } else {
                result.append(LabChange(path: path, kind: .created, old: nil, new: entry))
            }
        }
        for (key, entry) in old where new[key] == nil {
            guard let path = LabPath(key: key) else { continue }
            result.append(LabChange(path: path, kind: .deleted, old: entry, new: nil))
        }
        return result.sorted { $0.path < $1.path }
    }

    public static func apply(_ changes: [LabChange], to manifest: LabManifest) -> LabManifest {
        var result = manifest
        for change in changes { result[change.path.key] = change.new }
        return result
    }

    /// `first` then `second` as one list: what turns the state before `first` into the state after `second`.
    public static func compose(_ first: [LabChange], _ second: [LabChange]) -> [LabChange] {
        var merged: [String: LabChange] = [:]
        for change in first { merged[change.path.key] = change }
        for change in second {
            guard let earlier = merged[change.path.key] else {
                merged[change.path.key] = change
                continue
            }
            let old = earlier.old
            let new = change.new
            let secret = change.secret ?? (new == nil ? nil : earlier.secret)
            switch (old, new) {
            case (nil, nil): merged[change.path.key] = nil
            case (nil, .some): merged[change.path.key] = LabChange(path: change.path, kind: .created, old: nil, new: new, secret: secret)
            case (.some, nil): merged[change.path.key] = LabChange(path: change.path, kind: .deleted, old: old, new: nil)
            case (.some(let before), .some(let after)):
                merged[change.path.key] = before.sameContent(as: after)
                    ? nil : LabChange(path: change.path, kind: .changed, old: before, new: after, secret: secret)
            }
        }
        return merged.values.sorted { $0.path < $1.path }
    }

    /// Sizes of what a list adds (created and changed files, new content) and what it replaces (old content).
    public static func bytes(of changes: [LabChange]) -> (added: Int64, removed: Int64) {
        var added: Int64 = 0
        var removed: Int64 = 0
        for change in changes where !change.attributesOnly {
            added += change.new?.dataBytes ?? 0
            removed += change.old?.dataBytes ?? 0
        }
        return (added, removed)
    }
}

// MARK: - Session

public struct LabCheckpoint: Codable, Sendable, Equatable, Identifiable {
    public enum Reason: String, Codable, Sendable {
        case start, interval, program, manual
        /// Taken automatically right before a rewind, so the rewind can be undone.
        case beforeRewind
    }

    public var id: Int
    /// The checkpoint the changes are counted from; `nil` for the start.
    public var parent: Int?
    public var takenAt: Date
    public var reason: Reason
    public var label: String
    public var created: Int
    public var changed: Int
    public var deleted: Int
    /// Bytes of the files this checkpoint added or changed.
    public var addedBytes: Int64
    /// Bytes of the files it replaced or deleted (still held by older checkpoints).
    public var removedBytes: Int64
    /// Changes that look like secrets, keys or login items (`LabFindings`).
    public var findings: Int

    public init(
        id: Int, parent: Int?, takenAt: Date, reason: Reason, label: String, created: Int = 0, changed: Int = 0, deleted: Int = 0,
        addedBytes: Int64 = 0, removedBytes: Int64 = 0, findings: Int = 0
    ) {
        self.id = id
        self.parent = parent
        self.takenAt = takenAt
        self.reason = reason
        self.label = label
        self.created = created
        self.changed = changed
        self.deleted = deleted
        self.addedBytes = addedBytes
        self.removedBytes = removedBytes
        self.findings = findings
    }

    public var changeCount: Int { created + changed + deleted }

    /// Fills the counters from the change list against `parent`.
    public mutating func summarize(_ changes: [LabChange]) {
        created = changes.count { $0.kind == .created }
        changed = changes.count { $0.kind == .changed }
        deleted = changes.count { $0.kind == .deleted }
        (addedBytes, removedBytes) = LabDiff.bytes(of: changes)
        findings = LabFindings.findings(in: changes).count
    }
}

public struct LabRewind: Codable, Sendable, Equatable {
    public var at: Date
    public var to: Int
    /// The checkpoint taken right before, when something had changed.
    public var savedAs: Int?

    public init(at: Date, to: Int, savedAs: Int?) {
        self.at = at
        self.to = to
        self.savedAs = savedAs
    }
}

public struct LabSession: Codable, Sendable, Equatable {
    public var id: UUID
    public var startedAt: Date
    public var settings: LabSettings
    /// Roots that existed at the start; the others are left alone.
    public var roots: [LabRoot]
    public var checkpoints: [LabCheckpoint]
    /// The checkpoint the live files descend from (the last one taken or rewound to).
    public var head: Int
    public var rewinds: [LabRewind]
    /// Checkpoints removed to stay within the limits.
    public var pruned: Int
    public var nextID: Int

    public init(
        id: UUID = UUID(), startedAt: Date, settings: LabSettings, roots: [LabRoot], checkpoints: [LabCheckpoint] = [],
        head: Int = 0, rewinds: [LabRewind] = [], pruned: Int = 0, nextID: Int = 0
    ) {
        self.id = id
        self.startedAt = startedAt
        self.settings = settings
        self.roots = roots
        self.checkpoints = checkpoints
        self.head = head
        self.rewinds = rewinds
        self.pruned = pruned
        self.nextID = nextID
    }

    public func checkpoint(_ id: Int) -> LabCheckpoint? { checkpoints.first { $0.id == id } }

    public var start: LabCheckpoint? { checkpoints.first { $0.reason == .start } }

    /// `id` and its parents up to the start, oldest first.
    public func chain(to id: Int) -> [LabCheckpoint] {
        var result: [LabCheckpoint] = []
        var next: Int? = id
        var seen: Set<Int> = []
        while let current = next, seen.insert(current).inserted, let checkpoint = checkpoint(current) {
            result.append(checkpoint)
            next = checkpoint.parent
        }
        return result.reversed()
    }

    /// Estimated space the checkpoints hold beyond the live files: content they replaced on the way to the
    /// current state, plus everything added on branches a rewind left behind. APFS shares unchanged blocks,
    /// so this counts whole files where only some blocks may differ; it is an upper bound.
    public var estimatedBytes: Int64 {
        let live = Set(chain(to: head).map(\.id))
        return checkpoints.reduce(0) { sum, checkpoint in
            sum + checkpoint.removedBytes + (live.contains(checkpoint.id) ? 0 : checkpoint.addedBytes)
        }
    }

    /// The checkpoints to remove so that the session fits `settings`, oldest automatic ones first.
    /// The start and the head are never removed. `sizeAfter` re-estimates after each removal.
    public func pruningCandidates() -> [Int] {
        let order: [LabCheckpoint.Reason] = [.interval, .program, .beforeRewind, .manual]
        return checkpoints
            .filter { $0.reason != .start && $0.id != head }
            .sorted { (order.firstIndex(of: $0.reason) ?? 0, $0.id) < (order.firstIndex(of: $1.reason) ?? 0, $1.id) }
            .map(\.id)
    }

    public var overLimits: Bool {
        checkpoints.count > settings.maxCheckpoints || estimatedBytes > settings.maxStoreBytes
    }
}

// MARK: - Requests and responses

public enum LabRequest: Codable, Sendable, Equatable {
    /// The running session, if any, and the free space.
    case status
    /// Starts a session with a first checkpoint ("Start").
    case start(LabSettings)
    /// A new checkpoint; with `onlyIfChanged` none is taken when nothing changed since the last one.
    case checkpoint(reason: LabCheckpoint.Reason, label: String?, onlyIfChanged: Bool)
    /// What changed from checkpoint `from` to checkpoint `to`, or to the live files when `to` is `nil`.
    case compare(from: Int, to: Int?)
    /// A file's content at a checkpoint, or now when `at` is `nil` (text only, `LabFileContent.maxBytes`).
    case file(LabPath, at: Int?)
    /// Terminates the sandbox's processes and puts the files back to the checkpoint.
    case rewind(to: Int)
    /// Ends the session: `keep` leaves the files as they are, otherwise they go back to the start first.
    case finish(keep: Bool)
}

public struct LabComparison: Codable, Sendable, Equatable {
    public var from: Int
    /// `nil`: the live files.
    public var to: Int?
    /// At most `LabComparison.maxChanges`, sorted by path.
    public var changes: [LabChange]
    public var created: Int
    public var changed: Int
    public var deleted: Int

    public static let maxChanges = 5000

    public init(from: Int, to: Int?, changes allChanges: [LabChange]) {
        self.from = from
        self.to = to
        created = allChanges.count { $0.kind == .created }
        changed = allChanges.count { $0.kind == .changed }
        deleted = allChanges.count { $0.kind == .deleted }
        changes = Array(allChanges.prefix(Self.maxChanges))
    }

    public var total: Int { created + changed + deleted }
    public var truncated: Bool { changes.count < total }
}

public struct LabFileContent: Codable, Sendable, Equatable {
    public var path: LabPath
    public var at: Int?
    public var exists: Bool
    public var size: Int64
    /// UTF-8 text, `nil` for binary content or anything that is not a regular file.
    public var text: String?
    public var truncated: Bool

    public static let maxBytes = 256 << 10

    public init(path: LabPath, at: Int?, exists: Bool, size: Int64 = 0, text: String? = nil, truncated: Bool = false) {
        self.path = path
        self.at = at
        self.exists = exists
        self.size = size
        self.text = text
        self.truncated = truncated
    }
}

public struct LabResponse: Codable, Sendable, Equatable {
    public var ok: Bool
    public var message: String
    public var session: LabSession?
    /// Free bytes on the volume of the checkpoints.
    public var freeBytes: Int64?
    /// The checkpoint just taken; `nil` when nothing changed.
    public var checkpoint: LabCheckpoint?
    public var comparison: LabComparison?
    public var file: LabFileContent?

    public init(
        ok: Bool, message: String, session: LabSession? = nil, freeBytes: Int64? = nil, checkpoint: LabCheckpoint? = nil,
        comparison: LabComparison? = nil, file: LabFileContent? = nil
    ) {
        self.ok = ok
        self.message = message
        self.session = session
        self.freeBytes = freeBytes
        self.checkpoint = checkpoint
        self.comparison = comparison
        self.file = file
    }

    public static func failure(_ error: Error) -> LabResponse {
        LabResponse(ok: false, message: (error as? SandvaultError)?.description ?? "\(error)")
    }
}

// MARK: - Findings

/// What deserves a look in a change list: keys, credentials, keychains, login items, shell startup files.
public struct LabFinding: Codable, Sendable, Hashable, Identifiable {
    public enum Kind: String, Codable, Sendable, CaseIterable {
        case key, credential, keychain, loginItem, shellStartup, sshAccess

        public var title: String {
            switch self {
            case .key: "Key"
            case .credential: "Credential"
            case .keychain: "Keychain"
            case .loginItem: "Starts by itself"
            case .shellStartup: "Shell startup file"
            case .sshAccess: "SSH access"
            }
        }

        public var symbolName: String {
            switch self {
            case .key: "key"
            case .credential: "lock.doc"
            case .keychain: "key.icloud"
            case .loginItem: "power"
            case .shellStartup: "terminal"
            case .sshAccess: "person.badge.key"
            }
        }
    }

    public var kind: Kind
    public var path: LabPath
    public var change: LabChange.Kind
    /// One sentence in plain words.
    public var detail: String

    public var id: String { "\(kind.rawValue):\(path.key)" }

    public init(kind: Kind, path: LabPath, change: LabChange.Kind, detail: String) {
        self.kind = kind
        self.path = path
        self.change = change
        self.detail = detail
    }
}

public enum LabFindings {
    static let shellStartup: Set<String> = [
        ".zshrc", ".zshenv", ".zprofile", ".zlogin", ".zlogout", ".bashrc", ".bash_profile", ".bash_login", ".profile",
        ".config/fish/config.fish",
    ]
    static let credentialFiles: [String: String] = [
        ".npmrc": "npm settings, often with a token", ".pypirc": "PyPI upload credentials", ".git-credentials": "stored git passwords",
        ".docker/config.json": "Docker registry logins", ".aws/credentials": "AWS access keys", ".config/gh/hosts.yml": "GitHub CLI login",
        ".kube/config": "Kubernetes cluster access", ".netrc": "passwords for servers",
    ]

    /// Findings for created and changed entries; deletions are not findings.
    public static func findings(in changes: [LabChange]) -> [LabFinding] {
        changes.compactMap(finding).sorted { ($0.kind.rawValue, $0.path) < ($1.kind.rawValue, $1.path) }
    }

    static func finding(_ change: LabChange) -> LabFinding? {
        guard change.kind != .deleted, let entry = change.new, entry.kind != .directory else { return nil }
        let path = change.path
        let verb = change.kind == .created ? "created" : "changed"
        func make(_ kind: LabFinding.Kind, _ detail: String) -> LabFinding {
            LabFinding(kind: kind, path: path, change: change.kind, detail: detail)
        }
        if path.root == .home {
            let p = path.path
            if p.hasPrefix("Library/Keychains/") { return make(.keychain, "A keychain was \(verb): the software stored passwords or keys there.") }
            if p.hasPrefix("Library/LaunchAgents/") { return make(.loginItem, "A launch agent was \(verb): this starts a program automatically.") }
            if p.hasPrefix("Library/Application Support/com.apple.backgroundtaskmanagementagent/") {
                return make(.loginItem, "The list of login items was \(verb).")
            }
            if shellStartup.contains(p) { return make(.shellStartup, "\(path.name) was \(verb): every new shell runs it.") }
            if p == ".ssh/authorized_keys" || p == ".ssh/authorized_keys2" {
                return make(.sshAccess, "Someone with a matching key can now log in as the sandbox user.")
            }
            if p.hasPrefix(".gnupg/private-keys") { return make(.key, "A GnuPG private key was \(verb).") }
            if let reason = credentialFiles[p] { return make(.credential, "\(path.name) was \(verb) (\(reason)).") }
        }
        if let reason = SecretScan.fileNameReason(path.name) {
            let kind: LabFinding.Kind = reason.contains("key") ? .key : .credential
            return make(kind, "A \(reason) was \(verb)" + (change.secret.map { "; it \($0)." } ?? "."))
        }
        if let secret = change.secret { return make(.credential, "\(path.name) \(secret).") }
        return nil
    }
}

// MARK: - Program starts

/// Notices programs the sandbox starts, from successive process lists, for "a checkpoint when a program starts".
public struct LabProgramWatch: Sendable {
    /// Shells, sv's own plumbing and short-lived helpers do not count as "a program started".
    public static let ignored: Set<String> = [
        "zsh", "-zsh", "bash", "-bash", "sh", "fish", "login", "sshd", "sshd-session", "sudo", "ssh", "sv", "tmux", "screen",
        "ps", "sleep", "cat", "ls", "grep", "sed", "awk", "head", "tail", "env", "true", "false", "test", "which", "dirname",
        "basename", "uname", "tput", "stty", "id", "date", "tr", "cut", "wc", "sort", "mkdir", "rm", "cp", "mv", "chmod",
    ]

    private var seenPIDs: Set<Int32> = []
    private var seenPrograms: Set<String> = []
    private var primed = false

    public init() {}

    /// Names of programs that appeared since the last call and were not seen before in this session. The first
    /// call only learns what already runs.
    public mutating func newPrograms(in processes: [SandboxProcess]) -> [String] {
        var result: [String] = []
        for process in processes where !seenPIDs.contains(process.pid) {
            seenPIDs.insert(process.pid)
            let name = Self.programName(process.command)
            guard !name.isEmpty, !Self.ignored.contains(name), seenPrograms.insert(name).inserted else { continue }
            if primed { result.append(name) }
        }
        seenPIDs.formIntersection(processes.map(\.pid))
        primed = true
        return result
    }

    /// `/opt/homebrew/bin/node /x/y.js` -> `node`; `npm install` -> `npm`.
    public static func programName(_ command: String) -> String {
        let first = command.split(separator: " ", maxSplits: 1).first.map(String.init) ?? ""
        return first.split(separator: "/").last.map(String.init) ?? first
    }
}

/// When to take automatic checkpoints, for the app and `svctl lab watch`: call `tick` every `pollSeconds`.
public struct LabAutopilot: Sendable {
    public static let pollSeconds: Double = 5
    /// At most one "program started" checkpoint per this many seconds; names in between are collected.
    public static let programSpacing: Double = 15

    public var settings: LabSettings
    private var lastInterval: Date
    private var lastProgram: Date?
    private var pending: [String] = []
    private var watch = LabProgramWatch()

    public init(settings: LabSettings, now: Date) {
        self.settings = settings
        lastInterval = now
    }

    /// The checkpoints due now. `processes` is `nil` when the process list could not be read.
    public mutating func tick(now: Date, processes: [SandboxProcess]?) -> [LabRequest] {
        var requests: [LabRequest] = []
        if settings.checkpointOnProgramStart, let processes {
            for name in watch.newPrograms(in: processes) where !pending.contains(name) { pending.append(name) }
            if !pending.isEmpty, lastProgram.map({ now.timeIntervalSince($0) >= Self.programSpacing }) ?? true {
                let names = pending.prefix(3).joined(separator: ", ") + (pending.count > 3 ? " and \(pending.count - 3) more" : "")
                requests.append(.checkpoint(reason: .program, label: "Started \(names)", onlyIfChanged: false))
                pending = []
                lastProgram = now
                lastInterval = now
            }
        }
        if now.timeIntervalSince(lastInterval) >= Double(settings.intervalSeconds) {
            requests.append(.checkpoint(reason: .interval, label: nil, onlyIfChanged: true))
            lastInterval = now
        }
        return requests
    }
}

// MARK: - Client

/// Unprivileged side of `svctl-helper lab`.
public struct LabClient: Sendable {
    public var runner: CommandRunner

    public init(runner: CommandRunner) {
        self.runner = runner
    }

    /// Checkpoints of large trees and rewinds take longer than the helper's usual minute.
    public static let timeout: Double = 900

    public func send(_ request: LabRequest) async throws -> LabResponse {
        var invocation = CommandInvocation.viaHelper(HelperSubcommand.lab.rawValue, ["--json"], stdin: try JSONCoding.lineEncoder.encode(request))
        invocation.timeout = Self.timeout
        let result = try await runner.run(invocation)
        if let response = try? JSONCoding.decoder.decode(LabResponse.self, from: result.stdout) {
            guard response.ok else { throw SandvaultError.io(response.message) }
            return response
        }
        if result.stderrString.contains("a password is required") || result.stderrString.contains("not allowed") {
            throw SandvaultError.permissionDenied("the helper's sudoers rule has no lab command yet; reinstall the helper (`svctl helper install`)")
        }
        throw SandvaultError.commandFailed("svctl-helper lab", result.exitCode, result.stderrString)
    }
}

// MARK: - Servers

/// A server the sandbox contacted during a session, from netd's connection log.
public struct LabServer: Codable, Sendable, Hashable, Identifiable {
    public var host: String
    public var connections: Int
    public var blocked: Int
    public var bytesIn: Int64
    public var bytesOut: Int64
    public var first: Date
    public var last: Date
    public var programs: [String]

    public var id: String { host }

    public init(host: String, connections: Int, blocked: Int, bytesIn: Int64, bytesOut: Int64, first: Date, last: Date, programs: [String]) {
        self.host = host
        self.connections = connections
        self.blocked = blocked
        self.bytesIn = bytesIn
        self.bytesOut = bytesOut
        self.first = first
        self.last = last
        self.programs = programs
    }

    /// One entry per host with records in `from..<to` (open end: until now), in order of first contact.
    public static func summarize(_ records: [ConnectionRecord], from: Date, to: Date? = nil) -> [LabServer] {
        var servers: [String: LabServer] = [:]
        for record in records where record.timestamp >= from && (to.map { record.timestamp < $0 } ?? true) && !record.host.isEmpty {
            var server = servers[record.host] ?? LabServer(
                host: record.host, connections: 0, blocked: 0, bytesIn: 0, bytesOut: 0, first: record.timestamp, last: record.timestamp, programs: []
            )
            server.connections += 1
            switch record.decision {
            case .denied, .askedDenied, .timedOut: server.blocked += 1
            case .allowed, .askedAllowed: break
            }
            server.bytesIn += record.bytesIn
            server.bytesOut += record.bytesOut
            server.first = min(server.first, record.timestamp)
            server.last = max(server.last, record.timestamp)
            if let program = record.process, !program.isEmpty, !server.programs.contains(program) { server.programs.append(program) }
            servers[record.host] = server
        }
        return servers.values.sorted { ($0.first, $0.host) < ($1.first, $1.host) }
    }
}
