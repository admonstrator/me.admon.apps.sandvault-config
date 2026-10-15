import Foundation
#if canImport(Darwin)
import Darwin
#elseif canImport(Glibc)
import Glibc
#endif
import SandvaultCore

/// `svctl-helper lab` (D52): one `LabRequest` from stdin, one `LabResponse`. The store is root-only
/// (`<rootStateDir>/lab`, 0700) on the Data volume, the same APFS volume as `/Users`, so checkpoints are clones:
///
///     lab/session.json         LabSession
///     lab/base.json            manifest of the start
///     lab/head.json            manifest of the head (what the next checkpoint is compared with)
///     lab/checkpoints/<id>/    home/, workspace/ (clones) and changes.json (against the parent)
///     lab/trash/               replaced and pruned trees on their way out
extension PrivilegedHelper {
    public func lab(_ input: Data?) async -> LabResponse {
        do {
            guard let input, !input.isEmpty else { throw SandvaultError.invalidInput("expected a LabRequest on stdin") }
            guard input.count <= Self.maxInputBytes else { throw SandvaultError.invalidInput("stdin exceeds \(Self.maxInputBytes) bytes") }
            let request: LabRequest
            do {
                request = try JSONCoding.decoder.decode(LabRequest.self, from: input)
            } catch {
                throw SandvaultError.invalidInput("stdin is not a LabRequest: \(error)")
            }
            try ensureStateDir()
            let store = LabStore(helper: self, environment: try sudoEnvironment())
            return try await store.handle(request)
        } catch {
            return .failure(error)
        }
    }
}

struct LabStore {
    let helper: PrivilegedHelper
    let environment: SandvaultEnvironment

    static let pgrepPath = "/usr/bin/pgrep"
    /// Changed files up to this size are scanned for secrets, at most `secretScanLimit` per checkpoint.
    static let secretScanBytes = 256 << 10
    static let secretScanLimit = 500

    var context: HelperContext { helper.context }
    var files: RootFiles { helper.files }
    var directory: String { context.stateDir + "/lab" }
    var sessionPath: String { directory + "/session.json" }
    var basePath: String { directory + "/base.json" }
    var headPath: String { directory + "/head.json" }
    var checkpointsDir: String { directory + "/checkpoints" }
    var trashDir: String { directory + "/trash" }

    func livePath(_ root: LabRoot) -> String { context.root + root.path(in: environment) }
    func checkpointDir(_ id: Int) -> String { "\(checkpointsDir)/\(id)" }

    // MARK: Dispatch

    func handle(_ request: LabRequest) async throws -> LabResponse {
        try files.makeDirectory(directory, mode: 0o700)
        let lock = try Lock(path: directory + "/lock", wait: !Self.skipsWhenBusy(request))
        guard lock.held else { return LabResponse(ok: true, message: "another lab operation is running; skipped", session: loadSession()) }
        defer { lock.release() }

        switch request {
        case .status:
            return LabResponse(ok: true, message: loadSession() == nil ? "no lab session" : "lab session running", session: loadSession(), freeBytes: free)
        case .start(let settings): return try start(try settings.validated())
        case .checkpoint(let reason, let label, let onlyIfChanged):
            var session = try requireSession()
            let taken = try checkpoint(&session, reason: reason, label: label, onlyIfChanged: onlyIfChanged)
            try save(session)
            let message = taken.map { "checkpoint \($0.id): \($0.changeCount) changes" } ?? "nothing changed"
            return LabResponse(ok: true, message: message, session: session, freeBytes: free, checkpoint: taken)
        case .compare(let from, let to): return try compare(from: from, to: to)
        case .file(let path, let at): return try file(path, at: at)
        case .rewind(let id): return try await rewind(to: id)
        case .finish(let keep): return try await finish(keep: keep)
        }
    }

    /// Timer checkpoints give way to a running operation instead of queueing behind it.
    static func skipsWhenBusy(_ request: LabRequest) -> Bool {
        if case .checkpoint(_, _, true) = request { return true }
        return false
    }

    var free: Int64? { LabTree.freeBytes(directory) }

    // MARK: Start

    func start(_ settings: LabSettings) throws -> LabResponse {
        guard loadSession() == nil else { throw SandvaultError.invalidInput("a lab session is already running; finish it first") }
        let roots = settings.roots.filter { isDirectory(livePath($0)) }
        guard !roots.isEmpty else {
            throw SandvaultError.notInstalled("the sandbox (\(environment.sandvaultHome) and \(environment.sharedWorkspace)); run sv once")
        }
        for root in roots where LabTree.device(livePath(root)) != LabTree.device(directory) {
            throw SandvaultError.io("\(livePath(root)) is on another volume than \(directory); checkpoints need APFS clones on one volume")
        }
        // Leftovers of an interrupted session hold no session.json; start clean.
        try files.removeTree(checkpointsDir)
        try files.removeTree(trashDir)
        try files.makeDirectory(checkpointsDir, mode: 0o700)

        var session = LabSession(startedAt: context.now(), settings: settings, roots: roots)
        let manifest = try walk(session)
        try ensureFree(session)
        try cloneLive(session, into: 0)
        var first = LabCheckpoint(id: 0, parent: nil, takenAt: context.now(), reason: .start, label: "Start")
        first.summarize([])
        session.checkpoints = [first]
        session.head = 0
        session.nextID = 1
        try writeJSON(manifest, to: basePath)
        try writeJSON(manifest, to: headPath)
        try writeJSON([LabChange](), to: checkpointDir(0) + "/changes.json")
        try save(session)
        return LabResponse(ok: true, message: "lab session started (\(manifest.count) files)", session: session, freeBytes: free, checkpoint: first)
    }

    // MARK: Checkpoints

    /// `prune: false` leaves pruning to the caller (a rewind must not lose its target on the way).
    func checkpoint(
        _ session: inout LabSession, reason: LabCheckpoint.Reason, label: String?, onlyIfChanged: Bool, prune pruning: Bool = true
    ) throws -> LabCheckpoint? {
        guard reason != .start else { throw SandvaultError.invalidInput("the start checkpoint is taken by start") }
        let live = try walk(session)
        let previous = try headManifest(session)
        var changes = dropUnchangedContent(LabDiff.changes(from: previous, to: live), old: directories(ofCheckpoint: session.head), new: liveDirectories(session))
        if changes.isEmpty, onlyIfChanged { return nil }
        try ensureFree(session)

        let id = session.nextID
        try files.makeDirectory(checkpointsDir, mode: 0o700)
        try cloneLive(session, into: id)
        changes = scanSecrets(changes, inCheckpoint: id)
        try writeJSON(changes, to: checkpointDir(id) + "/changes.json")

        var checkpoint = LabCheckpoint(
            id: id, parent: session.head, takenAt: context.now(), reason: reason, label: Self.label(label, reason: reason)
        )
        checkpoint.summarize(changes)
        session.checkpoints.append(checkpoint)
        session.head = id
        session.nextID = id + 1
        try writeJSON(live, to: headPath)
        if pruning { try prune(&session) }
        return checkpoint
    }

    static func label(_ given: String?, reason: LabCheckpoint.Reason) -> String {
        let cleaned = String((given ?? "").unicodeScalars.filter { !CharacterSet.controlCharacters.contains($0) })
            .trimmingCharacters(in: .whitespaces)
        if !cleaned.isEmpty { return String(cleaned.prefix(120)) }
        return switch reason {
        case .start: "Start"
        case .interval: "Automatic"
        case .program: "Program started"
        case .manual: "Marked"
        case .beforeRewind: "Before rewind"
        }
    }

    func cloneLive(_ session: LabSession, into id: Int) throws {
        let target = checkpointDir(id)
        try files.makeDirectory(target, mode: 0o700)
        let destination = try LabTree.openDirectory(target)
        defer { close(destination) }
        for root in session.roots {
            let path = livePath(root)
            let parent = try LabTree.openDirectory(URL(fileURLWithPath: path).deletingLastPathComponent().path)
            defer { close(parent) }
            try LabTree.clone(parent, URL(fileURLWithPath: path).lastPathComponent, to: destination, as: root.rawValue, excludes: excludes(session, root))
        }
    }

    func excludes(_ session: LabSession, _ root: LabRoot) -> [String] {
        session.settings.excludes.filter { $0.root == root }.map(\.path)
    }

    func walk(_ session: LabSession) throws -> LabManifest {
        var manifest = LabManifest()
        for root in session.roots {
            try LabTree.walk(livePath(root), root: root, excludes: Set(excludes(session, root)), into: &manifest)
        }
        return manifest
    }

    func ensureFree(_ session: LabSession) throws {
        guard let free, free < session.settings.minFreeBytes else { return }
        throw SandvaultError.io("only \(free >> 20) MB free on the disk; no checkpoint below \(session.settings.minFreeBytes >> 20) MB")
    }

    /// Marks created and changed files whose content looks like a secret, reading them from checkpoint `id`.
    func scanSecrets(_ changes: [LabChange], inCheckpoint id: Int) -> [LabChange] {
        let directories = Dictionary(uniqueKeysWithValues: LabRoot.allCases.map { ($0, "\(checkpointDir(id))/\($0.rawValue)") })
        return scanSecrets(changes, rootDirectories: directories)
    }

    func scanSecrets(_ changes: [LabChange], rootDirectories: [LabRoot: String]) -> [LabChange] {
        var scanned = 0
        var opened: [LabRoot: Int32] = [:]
        defer { opened.values.forEach { close($0) } }
        return changes.map { change in
            guard change.kind != .deleted, let entry = change.new, entry.kind == .file, entry.size > 0, entry.size <= Self.secretScanBytes,
                  scanned < Self.secretScanLimit, let rootPath = rootDirectories[change.path.root]
            else { return change }
            scanned += 1
            if opened[change.path.root] == nil { opened[change.path.root] = try? LabTree.openDirectory(rootPath) }
            guard let directory = opened[change.path.root],
                  let file = try? LabTree.readFile(directory, relative: change.path.path, maxBytes: Self.secretScanBytes),
                  !file.data.contains(0),
                  let reason = SecretScan.contentReason(String(decoding: file.data, as: UTF8.self), fileName: change.path.name)
            else { return change }
            var marked = change
            marked.secret = reason
            return marked
        }
    }

    /// sv copies the user's dotfiles into the sandbox home at every session start, which renews their times
    /// without changing them. A file whose size, mode and owner stayed and whose bytes are the same in `old` and
    /// `new` (each a directory per root) is not a change.
    func dropUnchangedContent(_ changes: [LabChange], old: [LabRoot: String], new: [LabRoot: String]) -> [LabChange] {
        var compared = 0
        var opened: [String: Int32] = [:]
        defer { opened.values.forEach { close($0) } }
        func directory(_ path: String?) -> Int32? {
            guard let path else { return nil }
            if let fd = opened[path] { return fd }
            guard let fd = try? LabTree.openDirectory(path) else { return nil }
            opened[path] = fd
            return fd
        }
        return changes.filter { change in
            guard change.kind == .changed, let before = change.old, let after = change.new, before.kind == .file, after.kind == .file,
                  before.size == after.size, before.mode == after.mode, before.uid == after.uid, after.size <= Self.contentCompareBytes,
                  compared < Self.contentCompareLimit,
                  let oldDirectory = directory(old[change.path.root]), let newDirectory = directory(new[change.path.root])
            else { return true }
            compared += 1
            let maxBytes = Int(Self.contentCompareBytes) + 1
            guard let a = try? LabTree.readFile(oldDirectory, relative: change.path.path, maxBytes: maxBytes),
                  let b = try? LabTree.readFile(newDirectory, relative: change.path.path, maxBytes: maxBytes)
            else { return true }
            return a.data != b.data
        }
    }

    static let contentCompareBytes: Int64 = 1 << 20
    static let contentCompareLimit = 2000

    func directories(ofCheckpoint id: Int) -> [LabRoot: String] {
        Dictionary(uniqueKeysWithValues: LabRoot.allCases.map { ($0, "\(checkpointDir(id))/\($0.rawValue)") })
    }

    func liveDirectories(_ session: LabSession) -> [LabRoot: String] {
        Dictionary(uniqueKeysWithValues: session.roots.map { ($0, livePath($0)) })
    }

    // MARK: Pruning

    /// Removes checkpoints until the session fits its limits; children of a removed one count from its parent.
    func prune(_ session: inout LabSession) throws {
        while session.overLimits, let victim = session.pruningCandidates().first {
            try remove(victim, from: &session)
        }
    }

    func remove(_ id: Int, from session: inout LabSession) throws {
        guard let checkpoint = session.checkpoint(id) else { return }
        let own = try changes(of: id)
        for index in session.checkpoints.indices where session.checkpoints[index].parent == id {
            let child = session.checkpoints[index].id
            let merged = LabDiff.compose(own, try changes(of: child))
            try writeJSON(merged, to: checkpointDir(child) + "/changes.json")
            session.checkpoints[index].parent = checkpoint.parent
            session.checkpoints[index].summarize(merged)
        }
        session.checkpoints.removeAll { $0.id == id }
        session.pruned += 1
        try discard(checkpointDir(id))
    }

    /// Moves a tree into the trash and deletes it there.
    func discard(_ path: String) throws {
        guard FileManager.default.fileExists(atPath: path) else { return }
        try files.makeDirectory(trashDir, mode: 0o700)
        let target = "\(trashDir)/\(UUID().uuidString)"
        guard rename(path, target) == 0 else { throw LabTree.posixError("move \(path) to the trash") }
        try files.removeTree(target)
    }

    // MARK: Compare and files

    func compare(from: Int, to: Int?) throws -> LabResponse {
        let session = try requireSession()
        let before = try manifest(of: from, in: session)
        let changes: [LabChange]
        if let to {
            let all = LabDiff.changes(from: before, to: try manifest(of: to, in: session))
            changes = scanSecrets(dropUnchangedContent(all, old: directories(ofCheckpoint: from), new: directories(ofCheckpoint: to)), inCheckpoint: to)
        } else {
            let all = LabDiff.changes(from: before, to: try walk(session))
            changes = scanSecrets(dropUnchangedContent(all, old: directories(ofCheckpoint: from), new: liveDirectories(session)), rootDirectories: liveDirectories(session))
        }
        let comparison = LabComparison(from: from, to: to, changes: changes)
        return LabResponse(ok: true, message: "\(comparison.total) changes", session: session, freeBytes: free, comparison: comparison)
    }

    func file(_ path: LabPath, at id: Int?) throws -> LabResponse {
        try LabPath.validate(path.path)
        let session = try requireSession()
        let base: String
        if let id {
            guard session.checkpoint(id) != nil else { throw SandvaultError.invalidInput("no checkpoint \(id)") }
            base = "\(checkpointDir(id))/\(path.root.rawValue)"
        } else {
            base = livePath(path.root)
        }
        var content = LabFileContent(path: path, at: id, exists: false)
        if isDirectory(base) {
            let directory = try LabTree.openDirectory(base)
            defer { close(directory) }
            if let file = try LabTree.readFile(directory, relative: path.path, maxBytes: LabFileContent.maxBytes) {
                content.exists = true
                content.size = file.size
                content.truncated = file.size > Int64(file.data.count)
                if !file.data.contains(0), let text = String(data: file.data, encoding: .utf8) { content.text = text }
            }
        }
        return LabResponse(ok: true, message: content.exists ? "\(content.size) bytes" : "no such file", session: session, file: content)
    }

    // MARK: Rewind and finish

    func rewind(to id: Int) async throws -> LabResponse {
        var session = try requireSession()
        guard session.checkpoint(id) != nil else { throw SandvaultError.invalidInput("no checkpoint \(id)") }
        await terminateSandbox()
        let saved = try checkpoint(&session, reason: .beforeRewind, label: "Before rewind to #\(id)", onlyIfChanged: true, prune: false)
        try save(session)
        try restore(session, to: id)
        session.head = id
        session.rewinds.append(LabRewind(at: context.now(), to: id, savedAs: saved?.id))
        try writeJSON(try manifest(of: id, in: session), to: headPath)
        try prune(&session)
        try save(session)
        let note = saved.map { "; the state before is checkpoint \($0.id)" } ?? ""
        return LabResponse(ok: true, message: "rewound to checkpoint \(id)\(note)", session: session, freeBytes: free, checkpoint: saved)
    }

    func restore(_ session: LabSession, to id: Int) throws {
        try files.makeDirectory(trashDir, mode: 0o700)
        let trash = try LabTree.openDirectory(trashDir)
        defer { close(trash) }
        for root in session.roots {
            let saved = "\(checkpointDir(id))/\(root.rawValue)"
            guard isDirectory(saved), isDirectory(livePath(root)) else { continue }
            let from = try LabTree.openDirectory(saved)
            defer { close(from) }
            let into = try LabTree.openDirectory(livePath(root))
            defer { close(into) }
            try LabTree.restore(from: from, into: into, excludes: excludes(session, root), trash: trash)
        }
        try files.removeTree(trashDir)
    }

    func finish(keep: Bool) async throws -> LabResponse {
        let session = try requireSession()
        if !keep, let start = session.start {
            await terminateSandbox()
            try restore(session, to: start.id)
        }
        for path in [sessionPath, basePath, headPath] { try files.remove(path) }
        try files.removeTree(checkpointsDir)
        try files.removeTree(trashDir)
        return LabResponse(
            ok: true, message: keep ? "lab session finished; the files stay as they are" : "lab session finished; the files are back at the start",
            freeBytes: free
        )
    }

    /// Stops what could write while files are put back: the sandbox user's launchd domain, then every process
    /// (TERM, up to three seconds, then KILL).
    func terminateSandbox() async {
        let user = environment.sandvaultUser
        if let uid = try? await helper.resolveUID(environment) {
            _ = try? await context.runner.run(CommandInvocation(PrivilegedHelper.launchctlPath, ["bootout", "user/\(uid)"]))
        }
        _ = try? await context.runner.run(CommandInvocation(PrivilegedHelper.pkillPath, ["-TERM", "-u", user]))
        for _ in 0..<10 {
            let alive = try? await context.runner.run(CommandInvocation(Self.pgrepPath, ["-u", user]))
            guard alive?.exitCode == 0 else { return }
            try? await Task.sleep(nanoseconds: 300_000_000)
        }
        _ = try? await context.runner.run(CommandInvocation(PrivilegedHelper.pkillPath, ["-9", "-u", user]))
    }

    // MARK: State

    func loadSession() -> LabSession? {
        guard let data = try? files.read(sessionPath) else { return nil }
        return try? JSONCoding.decoder.decode(LabSession.self, from: data)
    }

    func requireSession() throws -> LabSession {
        guard let session = loadSession() else { throw SandvaultError.invalidInput("no lab session; start one first") }
        return session
    }

    func save(_ session: LabSession) throws {
        try writeJSON(session, to: sessionPath)
    }

    func changes(of id: Int) throws -> [LabChange] {
        guard let data = try files.read(checkpointDir(id) + "/changes.json", maxBytes: 1 << 30) else { return [] }
        return try JSONCoding.decoder.decode([LabChange].self, from: data)
    }

    /// The start plus every change list on the way to `id`.
    func manifest(of id: Int, in session: LabSession) throws -> LabManifest {
        let chain = session.chain(to: id)
        guard let first = chain.first, first.reason == .start else { throw SandvaultError.invalidInput("no checkpoint \(id)") }
        guard let data = try files.read(basePath, maxBytes: 1 << 30) else { throw SandvaultError.io("the lab's start manifest is missing") }
        var manifest = try JSONCoding.decoder.decode(LabManifest.self, from: data)
        for checkpoint in chain.dropFirst() { manifest = LabDiff.apply(try changes(of: checkpoint.id), to: manifest) }
        return manifest
    }

    func headManifest(_ session: LabSession) throws -> LabManifest {
        if let data = try? files.read(headPath, maxBytes: 1 << 30), let manifest = try? JSONCoding.decoder.decode(LabManifest.self, from: data) {
            return manifest
        }
        return try manifest(of: session.head, in: session)
    }

    func writeJSON<T: Encodable>(_ value: T, to path: String) throws {
        let encoder = JSONEncoder()
        encoder.dateEncodingStrategy = .iso8601
        try files.write(try encoder.encode(value), to: path, mode: 0o600)
    }

    func isDirectory(_ path: String) -> Bool {
        var info = stat()
        return lstat(path, &info) == 0 && info.st_mode & S_IFMT == S_IFDIR
    }

    /// `flock` on the store's lock file; released on close.
    final class Lock {
        private var fd: Int32
        let held: Bool

        init(path: String, wait: Bool) throws {
            fd = open(path, O_RDWR | O_CREAT | O_NOFOLLOW | O_CLOEXEC, 0o600)
            guard fd >= 0 else { throw LabTree.posixError("open \(path)") }
            held = flock(fd, LOCK_EX | (wait ? 0 : LOCK_NB)) == 0
        }

        func release() {
            guard fd >= 0 else { return }
            close(fd)
            fd = -1
        }
    }
}
