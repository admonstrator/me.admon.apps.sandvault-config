import Foundation
import SandvaultCore

// Process details (D51): what one sandbox process and the programs it started did, put together from the file and
// program recording (eslogger, by pid, parent and start time), netd's connection records (by pid) and the process
// list (running processes, their parent and session). Nothing here runs a command; callers pass what they have.

/// Names one process. Pids are reused, so a pid plus a moment the process existed.
public struct ProcessReference: Codable, Sendable, Hashable {
    public var pid: Int32
    /// A moment the process existed (a request, a file event); `nil` for the running or newest process with the pid.
    public var at: Date?

    public init(pid: Int32, at: Date? = nil) {
        self.pid = pid
        self.at = at
    }
}

/// One process as the recordings and the process list know it.
public struct TracedProcess: Codable, Sendable, Equatable, Identifiable {
    /// `<pid>@<start in ms>`, or `<pid>` when the start is unknown.
    public var id: String
    public var pid: Int32
    public var ppid: Int32?
    /// When it was created: eslogger's `start_time`, else estimated from `ps` (to the second).
    public var start: Date?
    /// The program it runs now (`git`): the last started image, else the executable, else `ps`'s command name.
    public var name: String
    public var executable: String?
    /// The command line: argv of the last start, else `ps`'s.
    public var command: String?
    /// Working directory at the last start.
    public var cwd: String?
    public var signature: AskProgram.Signature?
    public var signingID: String?
    public var sessionID: String?
    /// In the latest process list.
    public var running: Bool
    /// Earliest and latest moment anything of it was seen (start included).
    public var firstSeen: Date?
    public var lastSeen: Date?
    /// The parent among the known processes; `ppid` alone when the parent is not known.
    public var parentID: String?
    /// Direct children, oldest first.
    public var childIDs: [String]

    public init(
        id: String, pid: Int32, ppid: Int32? = nil, start: Date? = nil, name: String, executable: String? = nil, command: String? = nil,
        cwd: String? = nil, signature: AskProgram.Signature? = nil, signingID: String? = nil, sessionID: String? = nil, running: Bool = false,
        firstSeen: Date? = nil, lastSeen: Date? = nil, parentID: String? = nil, childIDs: [String] = []
    ) {
        self.id = id
        self.pid = pid
        self.ppid = ppid
        self.start = start
        self.name = name
        self.executable = executable
        self.command = command
        self.cwd = cwd
        self.signature = signature
        self.signingID = signingID
        self.sessionID = sessionID
        self.running = running
        self.firstSeen = firstSeen
        self.lastSeen = lastSeen
        self.parentID = parentID
        self.childIDs = childIDs
    }

    public var reference: ProcessReference { ProcessReference(pid: pid, at: start ?? firstSeen) }
}

/// One thing a process did.
public struct ProcessTraceItem: Codable, Sendable, Equatable, Identifiable {
    public enum Content: Codable, Sendable, Equatable {
        /// The process started a program (eslogger `exec`; the pid stays, the image changes).
        case started(FileActivityEvent)
        case file(FileActivityEvent)
        /// A connection or DNS query netd decided on; `record.kind` tells which.
        case connection(ConnectionRecord)
        /// A connection that waits for the user's answer.
        case ask(AskRequest)
    }

    public var id: String
    public var time: Date
    /// The `TracedProcess.id` that did it.
    public var processID: String
    public var pid: Int32
    public var content: Content

    public init(id: String, time: Date, processID: String, pid: Int32, content: Content) {
        self.id = id
        self.time = time
        self.processID = processID
        self.pid = pid
        self.content = content
    }
}

/// Everything known about one process, for the detail view and `svctl activity process`.
public struct ProcessTrace: Codable, Sendable, Equatable {
    public var process: TracedProcess
    /// From the oldest known ancestor down to the parent.
    public var ancestors: [TracedProcess]
    /// Every process below it, depth first, oldest child first.
    public var descendants: [TracedProcess]
    /// Oldest first: the process's own items and, with `includesChildren`, those of its descendants.
    public var items: [ProcessTraceItem]
    public var includesChildren: Bool

    public init(process: TracedProcess, ancestors: [TracedProcess], descendants: [TracedProcess], items: [ProcessTraceItem], includesChildren: Bool) {
        self.process = process
        self.ancestors = ancestors
        self.descendants = descendants
        self.items = items
        self.includesChildren = includesChildren
    }

    public var children: [TracedProcess] { descendants.filter { $0.parentID == process.id } }

    /// The process with `id` among this trace's own, its ancestors and its descendants.
    public func process(_ id: String) -> TracedProcess? {
        if id == process.id { return process }
        return descendants.first { $0.id == id } ?? ancestors.first { $0.id == id }
    }
}

/// The index behind process details: every process the inputs mention, with parents, children and items.
public struct ProcessTracer: Sendable {
    /// `ps` gives elapsed time in whole seconds; a start within this of a recorded one is the same process.
    public static let startTolerance: TimeInterval = 2

    public private(set) var processes: [String: TracedProcess] = [:]
    private var itemsByProcess: [String: [ProcessTraceItem]] = [:]
    private var idsByPID: [Int32: [String]] = [:]

    /// `events` and `connections` in any order; `snapshot` is the latest process list, if any.
    public init(snapshot: ProcessSnapshot?, events: [FileActivityEvent], connections: [ConnectionRecord], asks: [AskRequest] = []) {
        for event in events.sorted(by: { $0.timestamp < $1.timestamp }) { add(event) }
        if let snapshot {
            for process in snapshot.processes { add(process, takenAt: snapshot.takenAt) }
        }
        for record in connections {
            guard let pid = record.pid else { continue }
            let id = instance(pid: pid, at: record.timestamp, name: record.process)
            append(ProcessTraceItem(id: record.id.uuidString, time: record.timestamp, processID: id, pid: pid, content: .connection(record)))
        }
        for ask in asks {
            guard let pid = ask.pid else { continue }
            let id = instance(pid: pid, at: ask.createdAt, name: ask.process)
            append(ProcessTraceItem(id: "ask-" + ask.id.uuidString, time: ask.createdAt, processID: id, pid: pid, content: .ask(ask)))
        }
        link()
    }

    /// The process `reference` names: with `at`, the one with that pid alive then (the latest started before it);
    /// without, the running one, else the newest.
    public func find(_ reference: ProcessReference) -> TracedProcess? {
        let candidates = (idsByPID[reference.pid] ?? []).compactMap { processes[$0] }
        if let at = reference.at {
            let before = candidates.filter { ($0.start ?? .distantPast) <= at.addingTimeInterval(Self.startTolerance) }
            if let best = before.max(by: { Self.order($0, $1) }) { return best }
        }
        if let running = candidates.filter(\.running).max(by: { Self.order($0, $1) }) { return running }
        return candidates.max(by: { Self.order($0, $1) })
    }

    /// The trace of the process `reference` names, `nil` when no input mentions the pid.
    public func trace(_ reference: ProcessReference, includeChildren: Bool = true) -> ProcessTrace? {
        guard let process = find(reference) else { return nil }
        return trace(id: process.id, includeChildren: includeChildren)
    }

    public func trace(id: String, includeChildren: Bool = true) -> ProcessTrace? {
        guard let process = processes[id] else { return nil }
        var ancestors: [TracedProcess] = []
        var seen: Set<String> = [id]
        var parent = process.parentID
        while let parentID = parent, seen.insert(parentID).inserted, let found = processes[parentID] {
            ancestors.insert(found, at: 0)
            parent = found.parentID
        }
        var descendants: [TracedProcess] = []
        func walk(_ node: TracedProcess) {
            for childID in node.childIDs where seen.insert(childID).inserted {
                guard let child = processes[childID] else { continue }
                descendants.append(child)
                walk(child)
            }
        }
        walk(process)
        let ids = [id] + (includeChildren ? descendants.map(\.id) : [])
        let items = ids.flatMap { itemsByProcess[$0] ?? [] }.sorted { ($0.time, $0.id) < ($1.time, $1.id) }
        return ProcessTrace(process: process, ancestors: ancestors, descendants: descendants, items: items, includesChildren: includeChildren)
    }

    // MARK: - Building

    static func order(_ a: TracedProcess, _ b: TracedProcess) -> Bool {
        let left = a.start ?? a.firstSeen ?? .distantPast, right = b.start ?? b.firstSeen ?? .distantPast
        return (left, a.id) < (right, b.id)
    }

    static func id(pid: Int32, start: Date?) -> String {
        guard let start else { return String(pid) }
        return "\(pid)@\(Int64((start.timeIntervalSince1970 * 1000).rounded()))"
    }

    private mutating func add(_ event: FileActivityEvent) {
        let id: String
        if let start = event.processStart {
            id = Self.id(pid: event.pid, start: start)
            if processes[id] == nil { create(id, pid: event.pid, start: start, name: event.process) }
        } else {
            // Stored before D51: no start, so the newest process with the pid that started before the event.
            id = instance(pid: event.pid, at: event.timestamp, name: event.process)
        }
        var process = processes[id]!
        if let ppid = event.ppid, ppid > 0 { process.ppid = ppid }
        if event.kind == .exec {
            process.name = Self.basename(event.path)
            process.executable = event.path
            process.command = event.arguments.isEmpty ? event.path : event.arguments.joined(separator: " ")
            process.cwd = event.cwd ?? process.cwd
            process.signature = event.signature ?? process.signature
            process.signingID = event.signingID ?? process.signingID
        } else {
            if process.executable == nil { process.executable = event.executable }
            if process.signature == nil { process.signature = event.signature }
            if process.signingID == nil { process.signingID = event.signingID }
        }
        processes[id] = process
        let content: ProcessTraceItem.Content = event.kind == .exec ? .started(event) : .file(event)
        append(ProcessTraceItem(id: event.id.uuidString, time: event.timestamp, processID: id, pid: event.pid, content: content))
    }

    private mutating func add(_ running: SandboxProcess, takenAt: Date) {
        let start = takenAt.addingTimeInterval(-Double(running.elapsedSeconds))
        let known = (idsByPID[running.pid] ?? []).compactMap { processes[$0] }
        let match = known.filter { process in
            guard let recorded = process.start else { return true }
            return abs(recorded.timeIntervalSince(start)) <= Self.startTolerance
        }.max(by: { Self.order($0, $1) })
        let id = match?.id ?? Self.id(pid: running.pid, start: start)
        if processes[id] == nil { create(id, pid: running.pid, start: start, name: CommandName.display(running.command)) }
        var process = processes[id]!
        process.running = true
        if process.start == nil { process.start = start }
        if process.ppid == nil, running.ppid > 0 { process.ppid = running.ppid }
        process.sessionID = running.sessionID ?? process.sessionID
        if process.command == nil { process.command = running.command }
        processes[id] = process
        touch(id, start)
    }

    /// The process with `pid` alive at `time`, created (start unknown) when no input mentioned the pid yet.
    private mutating func instance(pid: Int32, at time: Date, name: String?) -> String {
        if let found = find(ProcessReference(pid: pid, at: time)) { return found.id }
        let id = Self.id(pid: pid, start: nil)
        if processes[id] == nil { create(id, pid: pid, start: nil, name: name ?? "pid \(pid)") }
        return id
    }

    private mutating func create(_ id: String, pid: Int32, start: Date?, name: String) {
        processes[id] = TracedProcess(id: id, pid: pid, start: start, name: name, firstSeen: start, lastSeen: start)
        idsByPID[pid, default: []].append(id)
    }

    private mutating func append(_ item: ProcessTraceItem) {
        itemsByProcess[item.processID, default: []].append(item)
        touch(item.processID, item.time)
    }

    private mutating func touch(_ id: String, _ time: Date) {
        guard var process = processes[id] else { return }
        process.firstSeen = min(process.firstSeen ?? time, time)
        process.lastSeen = max(process.lastSeen ?? time, time)
        processes[id] = process
    }

    /// Parent: the process with the parent pid that started last before the child (any of them when starts are
    /// unknown). A pid that points to itself or into a loop is left without a parent.
    private mutating func link() {
        for id in processes.keys.sorted() {
            guard let child = processes[id], let ppid = child.ppid, ppid != child.pid else { continue }
            let at = child.start ?? child.firstSeen
            let candidates = (idsByPID[ppid] ?? []).compactMap { processes[$0] }
            let before = at.map { at in candidates.filter { ($0.start ?? .distantPast) <= at.addingTimeInterval(Self.startTolerance) } } ?? candidates
            guard let parent = (before.isEmpty ? candidates : before).max(by: { Self.order($0, $1) }), parent.id != id else { continue }
            if createsLoop(child: id, parent: parent.id) { continue }
            processes[id]?.parentID = parent.id
        }
        for (id, process) in processes {
            guard let parentID = process.parentID else { continue }
            processes[parentID]?.childIDs.append(id)
        }
        let all = processes
        for id in all.keys {
            processes[id]?.childIDs.sort { left, right in
                guard let a = all[left], let b = all[right] else { return left < right }
                return Self.order(a, b)
            }
        }
    }

    private func createsLoop(child: String, parent: String) -> Bool {
        var seen: Set<String> = [child]
        var next: String? = parent
        while let id = next {
            if !seen.insert(id).inserted { return true }
            next = processes[id]?.parentID
        }
        return false
    }

    static func basename(_ path: String) -> String {
        path.split(separator: "/").last.map(String.init) ?? path
    }
}
