import Foundation
import Observation
import SandvaultCore
import SandvaultEnforce
import SandvaultNet

/// The lab's checkpoints through the helper, and the servers from netd's log (D52).
public protocol LabService: Sendable {
    func send(_ request: LabRequest) async throws -> LabResponse
    /// netd's connection records since `date`, oldest first.
    func connections(since date: Date) async -> [ConnectionRecord]
}

/// `svctl-helper lab` and netd's connection log file.
public struct LiveLab: LabService {
    public var client: LabClient
    public var connectionLog: String

    public init(client: LabClient, connectionLog: String) {
        self.client = client
        self.connectionLog = connectionLog
    }

    public func send(_ request: LabRequest) async throws -> LabResponse {
        #if os(macOS)
        return try await client.send(request)
        #else
        throw SandvaultError.unsupportedPlatform("lab mode needs the helper and APFS on macOS")
        #endif
    }

    public func connections(since date: Date) async -> [ConnectionRecord] {
        let records = (try? ConnectionLog.read(path: connectionLog, limit: 50_000)) ?? []
        return records.filter { $0.timestamp >= date }
    }
}

/// Builds without the lab.
public struct UnavailableLab: LabService {
    public init() {}
    public func send(_ request: LabRequest) async throws -> LabResponse { throw SandvaultError.notImplemented("lab mode") }
    public func connections(since date: Date) async -> [ConnectionRecord] { [] }
}

/// Lab: a session of checkpoints, what changed, findings, rewind (D52). While a session runs and the app is open,
/// checkpoints come by themselves (`LabAutopilot`): every interval when something changed, and when a program starts.
@MainActor @Observable
public final class LabModel {
    public private(set) var session: LabSession?
    public private(set) var freeBytes: Int64?
    /// Start to now, for the findings and the totals at the top.
    public private(set) var overall: LabComparison?
    public private(set) var servers: [LabServer] = []
    public private(set) var availability = Availability.unknown
    /// What runs right now ("Rewinding..."), `nil` when idle.
    public private(set) var activity: String?
    public var message: UserMessage?

    /// The checkpoint whose changes are shown, and the comparison shown for it.
    public private(set) var selected: Int?
    public private(set) var comparison: LabComparison?
    /// The change whose content is compared line by line.
    public private(set) var diff: LabFileDiff?
    public var markLabel = ""

    @ObservationIgnored private let service: LabService
    @ObservationIgnored private let processes: ProcessSource
    @ObservationIgnored private let editor: ConfigEditor
    @ObservationIgnored private let clock: AppClock
    @ObservationIgnored private var autopilotTask: Task<Void, Never>?

    public init(service: LabService, processes: ProcessSource, editor: ConfigEditor, clock: AppClock) {
        self.service = service
        self.processes = processes
        self.editor = editor
        self.clock = clock
    }

    public var isBusy: Bool { activity != nil }
    public var isRunning: Bool { session != nil }
    public var settings: LabSettings { session?.settings ?? editor.config.lab }

    // MARK: Session

    /// Reads the session, the totals since the start and the servers; starts automatic checkpoints when a session runs.
    public func refresh() async {
        await perform("Read the lab session", busy: nil) {
            try await self.load(self.service.send(.status))
            if let start = self.session?.start {
                self.overall = try await self.service.send(.compare(from: start.id, to: nil)).comparison
            } else {
                self.overall = nil
            }
            await self.refreshServers()
        }
        updateAutopilot()
    }

    public func start() async {
        let settings = editor.config.lab
        await perform("Start the lab", busy: "Taking the first checkpoint...") {
            try await self.load(self.service.send(.start(settings)))
            self.overall = nil
            self.servers = []
            self.select(nil)
            self.message = .success("Lab started", detail: "Everything the sandbox changes from now on can be compared and undone.")
        }
        updateAutopilot()
    }

    public func mark() async {
        let label = markLabel.trimmingCharacters(in: .whitespaces)
        await perform("Take a checkpoint", busy: "Taking a checkpoint...") {
            let response = try await self.service.send(.checkpoint(reason: .manual, label: label.isEmpty ? nil : label, onlyIfChanged: false))
            try self.load(response)
            self.markLabel = ""
            await self.refreshOverall()
        }
    }

    /// Terminates the sandbox's programs and puts its files back to `id`; the state before stays a checkpoint.
    public func rewind(to id: Int) async {
        await perform("Rewind", busy: "Rewinding to checkpoint \(id)...") {
            let response = try await self.service.send(.rewind(to: id))
            try self.load(response)
            self.select(nil)
            await self.refreshOverall()
            self.message = .success(
                "Back at checkpoint \(id)",
                detail: response.checkpoint.map { "The state before the rewind is checkpoint \($0.id): \($0.label)." }
                    ?? "Nothing had changed since the last checkpoint."
            )
        }
    }

    /// Ends the session. `keep` leaves the files as they are; otherwise everything goes back to the start.
    public func finish(keep: Bool) async {
        await perform(keep ? "Finish the lab" : "Discard the lab's changes", busy: keep ? "Finishing..." : "Putting everything back...") {
            let response = try await self.service.send(.finish(keep: keep))
            self.session = nil
            self.freeBytes = response.freeBytes
            self.overall = nil
            self.servers = []
            self.select(nil)
            self.message = .success(keep ? "Lab finished" : "Everything is back at the start", detail: keep ? "The sandbox keeps its files as they are." : nil)
        }
        updateAutopilot()
    }

    // MARK: Comparing

    /// Shows what changed in `id` against its parent (the checkpoint before it).
    public func show(_ id: Int) async {
        guard let checkpoint = session?.checkpoint(id) else { return }
        select(id)
        guard let parent = checkpoint.parent else { return comparison = LabComparison(from: id, to: id, changes: []) }
        await perform("Compare checkpoints", busy: nil) {
            self.comparison = try await self.service.send(.compare(from: parent, to: id)).comparison
        }
    }

    /// Shows everything that changed from `id` to the files now.
    public func compareWithNow(_ id: Int) async {
        select(id)
        await perform("Compare with now", busy: "Comparing with now...") {
            self.comparison = try await self.service.send(.compare(from: id, to: nil)).comparison
        }
    }

    /// Line by line for a text file: its content at the comparison's start and end.
    public func showDiff(_ change: LabChange) async {
        guard let comparison else { return }
        await perform("Show the file", busy: nil) {
            let before = change.old?.kind == .file ? try await self.service.send(.file(change.path, at: comparison.from)).file : nil
            let after = change.new?.kind == .file ? try await self.service.send(.file(change.path, at: comparison.to)).file : nil
            self.diff = LabFileDiff(change: change, before: before, after: after)
        }
    }

    public func closeDiff() { diff = nil }

    private func select(_ id: Int?) {
        selected = id
        comparison = nil
        diff = nil
    }

    // MARK: Settings

    public func setInterval(_ seconds: Int) async { await editSettings { $0.intervalSeconds = seconds } }
    public func setCheckpointOnProgramStart(_ on: Bool) async { await editSettings { $0.checkpointOnProgramStart = on } }
    public func setMaxStoreBytes(_ bytes: Int64) async { await editSettings { $0.maxStoreBytes = bytes } }
    public func setIncludeWorkspace(_ on: Bool) async { await editSettings { $0.includeWorkspace = on } }

    /// Choices the page offers.
    public static let intervalChoices = [30, 60, 120, 300]
    public static let spaceChoices: [Int64] = [5_000_000_000, 10_000_000_000, 20_000_000_000, 50_000_000_000]

    /// Changes take effect with the next session; the running one keeps the settings it started with.
    private func editSettings(_ change: @escaping (inout LabSettings) -> Void) async {
        do {
            try await editor.edit(reloadNetd: false) { change(&$0.lab) }
        } catch {
            message = UserMessage(error: error, action: "Save the lab settings")
        }
    }

    // MARK: Automatic checkpoints

    /// Runs while a session exists; stops with `shutDown` or the end of the session.
    func updateAutopilot() {
        guard let session else {
            autopilotTask?.cancel()
            autopilotTask = nil
            return
        }
        guard autopilotTask == nil else { return }
        let settings = session.settings
        autopilotTask = Task { [weak self] in
            var autopilot = LabAutopilot(settings: settings, now: Date())
            while !Task.isCancelled {
                guard let self else { return }
                let processes = try? await self.processes.snapshot().processes
                for request in autopilot.tick(now: self.clock.now(), processes: processes) {
                    await self.autoCheckpoint(request)
                }
                try? await self.clock.sleep(LabAutopilot.pollSeconds)
            }
        }
    }

    /// Automatic checkpoints wait for what the user started and report failures quietly in the status line.
    func autoCheckpoint(_ request: LabRequest) async {
        guard !isBusy, session != nil else { return }
        do {
            let response = try await service.send(request)
            guard response.checkpoint != nil else { return }
            try load(response)
            await refreshOverall()
        } catch {
            autoFailure = UserMessage.describe(error)
        }
    }

    /// Why the last automatic checkpoint failed (no space, helper missing), cleared by the next success.
    public private(set) var autoFailure: String?

    public func shutDown() {
        autopilotTask?.cancel()
        autopilotTask = nil
    }

    public var isWatching: Bool { autopilotTask != nil }

    // MARK: Display

    /// Newest first, as the page lists them.
    public var checkpoints: [LabCheckpoint] { (session?.checkpoints ?? []).reversed() }

    public var findings: [LabFinding] { overall.map { LabFindings.findings(in: $0.changes) } ?? [] }

    public var statusLine: String {
        guard let session else { return "No lab session. Start one, then run the software you want to watch in the sandbox." }
        let count = Format.count(session.checkpoints.count, "checkpoint")
        let changes = overall.map { " · " + Format.count($0.total, "change") + " since the start" } ?? ""
        return "Recording since \(Self.time(session.startedAt)) · \(count)\(changes)"
    }

    public var storageLine: String {
        guard let session else { return freeBytes.map { "\(Format.bytes($0)) free on the disk" } ?? "" }
        var text = "Checkpoints hold about \(Format.bytes(session.estimatedBytes)) of \(Format.bytes(session.settings.maxStoreBytes))"
        if let freeBytes { text += " · \(Format.bytes(freeBytes)) free" }
        if session.pruned > 0 { text += " · \(Format.count(session.pruned, "older checkpoint")) removed to make room" }
        return text
    }

    public func summary(_ checkpoint: LabCheckpoint) -> String {
        guard checkpoint.reason != .start else { return "The files when the session started" }
        guard checkpoint.changeCount > 0 else { return "No file changes" }
        var parts: [String] = []
        if checkpoint.created > 0 { parts.append("\(checkpoint.created) new") }
        if checkpoint.changed > 0 { parts.append("\(checkpoint.changed) changed") }
        if checkpoint.deleted > 0 { parts.append("\(checkpoint.deleted) deleted") }
        if checkpoint.findings > 0 { parts.append(Format.count(checkpoint.findings, "finding")) }
        return parts.joined(separator: " · ")
    }

    /// Servers contacted between the checkpoint before `checkpoint` and it.
    public func servers(for checkpoint: LabCheckpoint) -> [LabServer] {
        guard let session, let parent = checkpoint.parent.flatMap(session.checkpoint) else { return [] }
        return LabServer.summarize(serverRecords, from: parent.takenAt, to: checkpoint.takenAt)
    }

    public func isHead(_ checkpoint: LabCheckpoint) -> Bool { session?.head == checkpoint.id }

    public static func time(_ date: Date) -> String {
        date.formatted(date: .omitted, time: .shortened)
    }

    // MARK: Internals

    @ObservationIgnored private var serverRecords: [ConnectionRecord] = []

    private func refreshServers() async {
        guard let session else {
            servers = []
            serverRecords = []
            return
        }
        serverRecords = await service.connections(since: session.startedAt)
        servers = LabServer.summarize(serverRecords, from: session.startedAt)
    }

    private func refreshOverall() async {
        guard let start = session?.start else { return }
        overall = try? await service.send(.compare(from: start.id, to: nil)).comparison
        await refreshServers()
    }

    private func load(_ response: LabResponse) throws {
        session = response.session
        if let free = response.freeBytes { freeBytes = free }
        autoFailure = nil
    }

    private func perform(_ action: String, busy: String?, _ body: () async throws -> Void) async {
        if busy != nil, isBusy { return }
        if let busy { activity = busy }
        defer { if busy != nil { activity = nil } }
        switch await WorkflowCall.run(action, body) {
        case .value: availability = .available
        case .notAvailable(let note): availability = .notAvailableYet(note)
        case .failed(let failure): message = failure
        }
    }
}

/// A text file before and after, line by line.
public struct LabFileDiff: Sendable, Equatable, Identifiable {
    public var change: LabChange
    public var before: LabFileContent?
    public var after: LabFileContent?
    /// `nil` when one side is binary or too large to show.
    public var lines: [DiffLine]?

    public var id: String { change.id }

    public init(change: LabChange, before: LabFileContent?, after: LabFileContent?) {
        self.change = change
        self.before = before
        self.after = after
        let old = before?.exists == true ? before?.text : ""
        let new = after?.exists == true ? after?.text : ""
        if let old, let new, before?.truncated != true, after?.truncated != true {
            lines = LineDiff.lines(old: old, new: new)
        } else {
            lines = nil
        }
    }

    public var note: String? {
        guard lines == nil else { return nil }
        if before?.truncated == true || after?.truncated == true { return "Too large to compare here." }
        return "Not a text file."
    }
}
