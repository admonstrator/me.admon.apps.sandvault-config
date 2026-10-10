import Foundation
import Observation
import SandvaultCore

/// Activity > Files & programs (D44, D45): runs the recorder while recording is switched on, keeps the stored events
/// and summarises them. Recording starts at launch when `AppConfig.activity.enabled` is set; after a failure it
/// starts again only when the user asks.
@MainActor @Observable
public final class FileActivityModel {
    public enum State: Equatable, Sendable {
        case off
        case recording(since: Date)
        case needsFullDiskAccess
        case needsHelper
        case failed(String)
    }

    public enum Mode: String, CaseIterable, Identifiable, Sendable {
        case changes, everything

        public var id: String { rawValue }
        public var title: String { self == .changes ? "Changes" : "Everything" }
    }

    public private(set) var state: State = .off
    /// Stored and new events, oldest first, about `eventLimit` at most.
    public private(set) var events: [FileActivityEvent] = []
    public var mode: Mode = .changes
    public var message: UserMessage?

    public static let eventLimit = 50_000
    /// Rows Everything shows per program.
    public static let everythingLimit = 300

    @ObservationIgnored private let recorder: ActivityRecording
    @ObservationIgnored private let editor: ConfigEditor
    @ObservationIgnored private let clock: AppClock
    @ObservationIgnored private let environment: SandvaultEnvironment
    @ObservationIgnored private var task: Task<Void, Never>?
    /// Bumps with every start, so a stopped run never changes the state of the next one.
    @ObservationIgnored private var generation = 0
    @ObservationIgnored private var reportCache: (key: ReportKey, report: ActivityReport)?

    private struct ReportKey: Equatable {
        var count: Int
        var first: UUID?
        var last: UUID?
    }

    public init(recorder: ActivityRecording, editor: ConfigEditor, clock: AppClock, environment: SandvaultEnvironment) {
        self.recorder = recorder
        self.editor = editor
        self.clock = clock
        self.environment = environment
    }

    public var settings: ActivityRecordingSettings { editor.config.activity }
    public var isRecording: Bool { if case .recording = state { true } else { false } }

    /// At app launch: records when the user switched it on earlier, else shows what was stored.
    public func launch() async {
        if settings.enabled {
            await begin()
        } else {
            await loadStored()
        }
    }

    /// Start or Try Again: saves `enabled` and starts the recorder.
    public func start() async {
        guard await saveEnabled(true) else { return }
        await begin()
    }

    /// Stop: ends the recorder and saves `enabled = false`; the stored events stay.
    public func stop() async {
        end()
        state = .off
        _ = await saveEnabled(false)
    }

    /// The recorder reads the settings when it starts, so a change restarts a running one.
    public func settingsChanged() async {
        guard isRecording else { return }
        end()
        await begin()
    }

    public func clear() async {
        do {
            try await recorder.clear()
            events = []
        } catch {
            message = UserMessage(error: error, action: "Clear the recorded files and programs")
        }
    }

    public func storageBytes() async -> Int64 {
        await recorder.storageBytes()
    }

    /// Ends the recorder without changing the setting (app quits).
    public func shutDown() {
        end()
    }

    // MARK: What the page shows

    public var report: ActivityReport {
        let key = ReportKey(count: events.count, first: events.first?.id, last: events.last?.id)
        if let cache = reportCache, cache.key == key { return cache.report }
        let report = ActivityReport.make(events, environment: environment)
        reportCache = (key, report)
        return report
    }

    /// Everything: raw events newest first, per program in the order of Changes.
    public var everything: [ProcessEvents] {
        var byProcess: [String: [FileActivityEvent]] = [:]
        for event in events { byProcess[event.process, default: []].append(event) }
        return report.groups.map { group in
            let all = byProcess[group.process] ?? []
            let shown = all.suffix(Self.everythingLimit).reversed().map { ActivityEventLine($0, environment: environment) }
            return ProcessEvents(process: group.process, lines: shown, more: max(0, all.count - Self.everythingLimit))
        }
    }

    /// The banner's title.
    public var bannerTitle: String {
        switch state {
        case .off: "Not recording"
        case .recording(let since): "Recording since \(Format.time(since))"
        case .needsFullDiskAccess: "Full Disk Access needed"
        case .needsHelper: "Helper needed"
        case .failed: "Recording stopped"
        }
    }

    public var bannerText: String {
        switch state {
        case .off:
            "Sandvault can note every file and program the sandbox touches. It records while this app runs; everything stays on this Mac."
        case .recording:
            settings.hideSystemFiles
                ? "Sandvault notes every file and program the sandbox touches. Reading system files is left out."
                : "Sandvault notes every file and program the sandbox touches."
        case .needsFullDiskAccess:
            "macOS lets the event recorder run only with Full Disk Access for Sandvault Config. Turn it on in System Settings, then try again."
        case .needsHelper:
            "Recording runs through the privileged helper. Install it, or reinstall it if it predates recording."
        case .failed(let reason):
            reason
        }
    }

    // MARK: -

    private func begin() async {
        end()
        generation += 1
        let run = generation
        await loadStored()
        guard run == generation else { return }
        let stream = recorder.record(settings: settings)
        state = .recording(since: clock.now())
        task = Task { [weak self] in
            do {
                for try await event in stream {
                    guard let self, run == self.generation else { return }
                    self.append(event)
                }
                self?.ended(run, nil)
            } catch {
                self?.ended(run, error)
            }
        }
    }

    private func end() {
        generation += 1
        task?.cancel()
        task = nil
    }

    private func ended(_ run: Int, _ error: Error?) {
        guard run == generation else { return }
        task = nil
        if error is CancellationError { return }
        state = Self.state(after: error)
    }

    /// What the banner shows after the recorder ended with `error` (`nil`: it ended on its own).
    static func state(after error: Error?) -> State {
        guard let error else { return .failed("The recorder stopped.") }
        switch error as? ActivityRecorderFailure {
        case .needsFullDiskAccess?: return .needsFullDiskAccess
        case .needsHelper?: return .needsHelper
        case .unavailable(let detail)?: return .failed("Recording is unavailable: \(detail)")
        case nil: return .failed(UserMessage.describe(error))
        }
    }

    private func loadStored() async {
        do {
            let stored = try await recorder.stored(since: nil, retentionDays: settings.retentionDays)
            events = Array(stored.suffix(Self.eventLimit))
        } catch {
            message = UserMessage(error: error, action: "Read the recorded files and programs")
        }
    }

    func append(_ event: FileActivityEvent) {
        events.append(event)
        // Trimmed in steps, so a busy recorder does not shift the whole array for every event.
        if events.count > Self.eventLimit + Self.eventLimit / 10 { events.removeFirst(events.count - Self.eventLimit) }
    }

    private func saveEnabled(_ on: Bool) async -> Bool {
        do {
            try await editor.edit(reloadNetd: false) { $0.activity.enabled = on }
            return true
        } catch {
            message = UserMessage(error: error, action: on ? "Start recording" : "Stop recording")
            return false
        }
    }
}

/// One program's raw events under Everything, newest first.
public struct ProcessEvents: Identifiable, Sendable, Equatable {
    public var process: String
    public var lines: [ActivityEventLine]
    /// Older events not shown.
    public var more: Int

    public var id: String { process }
}
