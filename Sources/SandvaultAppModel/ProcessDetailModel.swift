import Foundation
import Observation
import SandvaultCore
import SandvaultNet
import SandvaultObserve

/// Process details (D51): what one sandbox process and the programs it started did. Reads what the other models
/// already hold (recorded files and programs, netd's records and asks, the process list) and puts it together per
/// process; nothing is recorded for it alone. The view keeps its own filter and history, so several detail windows
/// can show different processes.
@MainActor @Observable
public final class ProcessDetailModel {
    /// The process a window or sheet should show; set by `show(_:)`, cleared by the view that presents it.
    public var presented: ProcessReference?

    @ObservationIgnored private let processes: ProcessesModel
    @ObservationIgnored private let files: FileActivityModel
    @ObservationIgnored private let netd: NetdLink
    @ObservationIgnored private let editor: ConfigEditor
    @ObservationIgnored private let environment: SandvaultEnvironment
    @ObservationIgnored private let clock: AppClock
    @ObservationIgnored private var cache: (key: TracerKey, tracer: ProcessTracer)?

    /// The inputs themselves: an unchanged array compares by its storage at once, a changed one was copied on write.
    private struct TracerKey: Equatable {
        var events: [FileActivityEvent]
        var records: [ConnectionRecord]
        var asks: [AskRequest]
        var snapshot: Date?
    }

    public init(processes: ProcessesModel, files: FileActivityModel, netd: NetdLink, editor: ConfigEditor, environment: SandvaultEnvironment, clock: AppClock) {
        self.processes = processes
        self.files = files
        self.netd = netd
        self.editor = editor
        self.environment = environment
        self.clock = clock
    }

    /// Asks the surface that hosts the details to show `reference`.
    public func show(_ reference: ProcessReference) {
        presented = reference
    }

    /// A fresh process list; the view calls it on appear and while it is visible.
    public func refresh() async {
        await processes.refresh()
    }

    public var now: Date { clock.now() }

    /// The details of the process `reference` names; `nil` when nothing mentions its pid.
    public func detail(for reference: ProcessReference, includeChildren: Bool = true, grouped: Bool = true) -> ProcessDetail? {
        guard let trace = tracer.trace(reference, includeChildren: includeChildren) else { return nil }
        return ProcessDetail.make(trace, environment: environment, grouped: grouped)
    }

    /// The newest process that ran the program `name` (Activity > Files & programs groups by program name).
    public func reference(forProgram name: String) -> ProcessReference? {
        files.reference(forProgram: name)
    }

    /// Why parts may be missing from `detail`, in the order they matter.
    public func hints(for detail: ProcessDetail) -> [String] {
        var hints: [String] = []
        if !files.isRecording {
            hints.append(detail.recordedFileEvents == 0
                ? "Files and the programs it started appear when Activity > Files & programs records."
                : "Files & programs is not recording: files and programs after it stopped are missing.")
        }
        if detail.encryptedConnections > 0, !editor.config.network.inspection.enabled {
            hints.append("Turn on Look inside HTTPS to see the address, status and headers of each HTTPS request.")
        }
        switch editor.config.network.mode {
        case .off, .open:
            hints.append("Web traffic and DNS go through netd only in Watch and Ask; until then connections are missing.")
        case .watch, .proxyOnly, .blocked:
            if !netd.isConnected { hints.append("sandvault-netd is not running: connections are not recorded.") }
        }
        return hints
    }

    private var tracer: ProcessTracer {
        let key = TracerKey(events: files.events, records: netd.records, asks: netd.pendingAsks, snapshot: processes.snapshot?.takenAt)
        if let cache, cache.key == key { return cache.tracer }
        let tracer = ProcessTracer(snapshot: processes.snapshot, events: files.events, connections: netd.records, asks: netd.pendingAsks)
        cache = (key, tracer)
        return tracer
    }
}
