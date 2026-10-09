import Foundation
import Observation
import SandvaultCore
import SandvaultObserve

/// Processes screen: polled snapshots, tree and per-session grouping, terminate and throttle.
@MainActor @Observable
public final class ProcessesModel {
    public enum Grouping: String, CaseIterable, Sendable {
        case tree, sessions

        public var displayName: String { self == .tree ? "Tree" : "Sessions" }
    }

    public private(set) var snapshot: ProcessSnapshot?
    /// The last snapshot failed (shown once, not as a popup on every poll).
    public private(set) var refreshError: UserMessage?
    public private(set) var lastReport: ControlReport?
    public private(set) var isBusy = false
    public var grouping: Grouping = .tree
    public var message: UserMessage?

    @ObservationIgnored private let source: ProcessSource
    @ObservationIgnored private let control: ProcessControlling

    public init(source: ProcessSource, control: ProcessControlling) {
        self.source = source
        self.control = control
    }

    public func refresh() async {
        do {
            snapshot = try await source.snapshot()
            refreshError = nil
        } catch {
            refreshError = UserMessage(error: error, action: "Read processes")
        }
    }

    public var processCount: Int { snapshot?.processes.count ?? 0 }
    public var sessionCount: Int { snapshot?.sessions.count ?? 0 }

    /// Depth-first tree order.
    public var rows: [ProcessRow] {
        guard let snapshot else { return [] }
        return snapshot.tree().map { ProcessRow($0.process, depth: $0.depth) }
    }

    /// Sessions longest-running first, then processes without a session.
    public var sessionGroups: [SessionGroup] {
        guard let snapshot else { return [] }
        let ordered = rows
        var groups = snapshot.sessions.map { session in
            SessionGroup(id: session.id, session: session, rows: ordered.filter { $0.sessionID == session.id })
        }
        let known = Set(snapshot.sessions.map(\.id))
        let other = ordered.filter { $0.sessionID.map { !known.contains($0) } ?? true }
        if !other.isEmpty { groups.append(SessionGroup(id: SessionGroup.unassignedID, session: nil, rows: other)) }
        return groups
    }

    public func row(_ pid: Int32) -> ProcessRow? {
        rows.first { $0.pid == pid }
    }

    public func terminate(_ pid: Int32, force: Bool = false) async {
        await perform(force ? "Kill pid \(pid)" : "Terminate pid \(pid)") { try await self.control.terminate(pid: pid, force: force) }
    }

    public func terminateSession(_ id: String, force: Bool = false) async {
        await perform("End session \(Format.shortSession(id))") { try await self.control.terminateSession(id, force: force) }
    }

    /// sv's way: `launchctl bootout`, then `pkill -9` for survivors.
    public func terminateAll() async {
        await perform("End all sandbox processes") { try await self.control.terminateAll() }
    }

    public func throttle(_ pid: Int32, nice: Int? = 10, background: Bool = false) async {
        await perform("Throttle pid \(pid)") { try await self.control.throttle(pid: pid, nice: nice, background: background) }
    }

    private func perform(_ action: String, _ body: () async throws -> ControlReport) async {
        guard !isBusy else { return }
        isBusy = true
        defer { isBusy = false }
        do {
            let report = try await body()
            lastReport = report
            message = UserMessage(report: Self.summary(of: report, action: action))
        } catch {
            message = UserMessage(error: error, action: action)
        }
        await refresh()
    }

    static func summary(of report: ControlReport, action: String) -> ControlReportSummary {
        let title: String
        switch report.action {
        case "terminate": title = "Sent SIGTERM to \(pids(report.targets))"
        case "kill": title = "Sent SIGKILL to \(pids(report.targets))"
        case "terminate-session", "kill-session": title = "Ended session (\(report.targets.count) processes)"
        case "terminate-all": title = report.targets.isEmpty ? "No sandbox processes were running" : "Ended \(report.targets.count) sandbox processes"
        case "throttle": title = "Throttled \(pids(report.targets))"
        default: title = action
        }
        let failures = report.steps.filter { !$0.ok }.map { $0.detail.isEmpty ? $0.command : "\($0.command): \($0.detail)" }
        return ControlReportSummary(title: title, succeeded: report.succeeded, failures: failures, remaining: report.remaining)
    }

    private static func pids(_ targets: [Int32]) -> String {
        targets.count == 1 ? "pid \(targets[0])" : "\(targets.count) processes"
    }
}

public struct ProcessRow: Identifiable, Sendable, Equatable {
    public var pid: Int32
    public var ppid: Int32
    public var depth: Int
    /// Short name (`claude`, `node`), from `CommandName.display`.
    public var name: String
    public var command: String
    public var cpuPercent: Double
    public var memPercent: Double
    public var rssKiB: Int
    public var elapsedSeconds: Int
    public var state: String
    public var sessionID: String?

    public var id: Int32 { pid }

    public init(_ process: SandboxProcess, depth: Int) {
        pid = process.pid
        ppid = process.ppid
        self.depth = depth
        name = CommandName.display(process.command)
        command = process.command
        cpuPercent = process.cpuPercent
        memPercent = process.memPercent
        rssKiB = process.rssKiB
        elapsedSeconds = process.elapsedSeconds
        state = process.state
        sessionID = process.sessionID
    }

    /// The name indented by tree depth (two spaces per level).
    public var indentedName: String { String(repeating: "  ", count: depth) + name }
}

public struct SessionGroup: Identifiable, Sendable, Equatable {
    public static let unassignedID = "unassigned"

    public var id: String
    /// `nil` for processes without a session id.
    public var session: SandboxSession?
    public var rows: [ProcessRow]

    public var title: String {
        guard let session else { return "Without session" }
        return "\(session.command) · \(Format.shortSession(session.id)) · \(Format.duration(session.elapsedSeconds))"
    }
}
