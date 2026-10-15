import Foundation
import SandvaultCore
import SandvaultObserve

/// The five tiles of a process's details, each also a filter of the timeline (D51).
public enum ProcessDetailFilter: String, CaseIterable, Identifiable, Sendable {
    case all, web, network, files, programs

    public var id: String { rawValue }

    public var title: String {
        switch self {
        case .all: "All events"
        case .web: "Web requests"
        case .network: "Sites and lookups"
        case .files: "Files"
        case .programs: "Programs started"
        }
    }

    /// Heading of the list under the tiles.
    public var heading: String {
        switch self {
        case .all: "Everything, in order"
        case .web: "Web requests"
        case .network: "Connections and DNS"
        case .files: "Files"
        case .programs: "Programs"
        }
    }

    public var symbolName: String {
        switch self {
        case .all: "list.bullet"
        case .web: "globe"
        case .network: "network"
        case .files: "doc"
        case .programs: "play"
        }
    }
}

/// One line of the timeline: one event, or with grouping several alike (`312 requests`, `Read 63 files in src`).
public struct ProcessDetailRow: Identifiable, Sendable, Equatable {
    public enum Kind: String, Sendable {
        /// The process itself started (or switched to another program).
        case started
        /// It started another program; `opens` names that program's process.
        case launched
        /// A web connection: requests when netd saw them, else the encrypted connection.
        case web
        /// Another TCP connection through netd.
        case connection
        case dns
        case blocked
        /// Waits for the user's answer.
        case asking
        case file
    }

    public var id: String
    /// The first event of the row.
    public var time: Date
    public var kind: Kind
    /// Files only.
    public var action: ActivityAction?
    /// `Read your SSH keys and settings`, `POST api.anthropic.com/v1/messages`.
    public var title: String
    /// The second line: paths, command line, sizes, addresses.
    public var detail: String
    /// The pill on the right: a status code, Encrypted, Blocked, Waiting.
    public var status: String?
    public var statusTint: Tint
    public var sensitive: SensitivePlace?
    /// Events in the row.
    public var count: Int
    /// The process that did it: the shown process or one of the programs it started.
    public var processID: String
    public var pid: Int32
    public var processName: String
    /// `launched`: the started program, for Open.
    public var opens: ProcessReference?
    public var host: String?
    /// Files: the paths behind the row, oldest first.
    public var files: [String] = []

    public var symbolName: String {
        switch kind {
        case .started, .launched: "play.fill"
        case .web: "globe"
        case .connection: "network"
        case .dns: "magnifyingglass"
        case .blocked: "hand.raised.fill"
        case .asking: "questionmark.circle"
        case .file: action?.symbolName ?? "doc"
        }
    }

    public var tint: Tint {
        switch kind {
        case .started, .launched: .gray
        case .web, .connection, .dns: .blue
        case .blocked: .red
        case .asking: .orange
        case .file:
            switch action {
            case .read?: .blue
            case .change?, .move?: .orange
            case .create?: .green
            case .delete?: .red
            case .run?, nil: .gray
            }
        }
    }

    public func matches(_ filter: ProcessDetailFilter) -> Bool {
        switch filter {
        case .all: true
        case .web: kind == .web
        case .network: [.web, .connection, .dns, .blocked, .asking].contains(kind)
        case .files: kind == .file
        case .programs: kind == .started || kind == .launched
        }
    }
}

public struct ProcessDetailTile: Identifiable, Sendable, Equatable {
    public var filter: ProcessDetailFilter
    public var count: Int

    public var id: ProcessDetailFilter { filter }
}

/// Everything the detail view shows for one process (D51), computed from a `ProcessTrace`.
public struct ProcessDetail: Sendable, Equatable {
    public var process: TracedProcess
    /// Ancestors, then the process: `claude > node > sh`.
    public var chain: [TracedProcess]
    /// Direct children, oldest first.
    public var children: [TracedProcess]
    /// Every process below it.
    public var descendantCount: Int
    public var includesChildren: Bool
    /// Oldest first.
    public var rows: [ProcessDetailRow]
    public var tiles: [ProcessDetailTile]
    /// Rows that touched keys, logins, keychains, login items and the like.
    public var warnings: [ProcessDetailRow]
    /// Encrypted web connections whose requests netd did not see.
    public var encryptedConnections: Int
    /// Rows from the files and programs recording.
    public var recordedFileEvents: Int

    /// Newest first, as the list shows them.
    public func rows(_ filter: ProcessDetailFilter, matching search: String = "") -> [ProcessDetailRow] {
        let wanted = search.trimmingCharacters(in: .whitespaces).lowercased()
        return rows.reversed().filter { row in
            guard row.matches(filter) else { return false }
            guard !wanted.isEmpty else { return true }
            return [row.title, row.detail, row.processName, row.host ?? ""].contains { $0.lowercased().contains(wanted) }
        }
    }

    /// `claude`, or `node /opt/homebrew/bin/npm install` under it.
    public var title: String { process.name }

    /// `Running · 42:10`, `Ended · last seen 10:04:37`.
    public func state(now: Date) -> String {
        if process.running {
            guard let start = process.start else { return "Running" }
            return "Running · \(Format.duration(max(0, Int(now.timeIntervalSince(start)))))"
        }
        guard let last = process.lastSeen else { return "Ended" }
        return "Ended · last seen \(Format.time(last))"
    }

    /// `Started by claude`, `Started by pid 812`, `Started at 10:02:11`.
    public var startedBy: String? {
        if chain.count > 1 { return "Started by \(chain[chain.count - 2].name)" }
        if let ppid = process.ppid, ppid > 1 { return "Started by pid \(ppid)" }
        return process.start.map { "Started at \(Format.time($0))" }
    }

    public var signatureText: String {
        switch process.signature {
        case .apple?: "Apple system program"
        case .developer(let team)?: team.map { "Signed by developer team \($0)" } ?? "Signed by its developer"
        case .adHoc?: "Signed ad hoc, no developer identity"
        case .unsigned?: "Not signed"
        case .unknown?, nil: "Signature unknown"
        }
    }

    public var signatureTint: Tint {
        switch process.signature {
        case .apple?, .developer?: .green
        case .adHoc?: .orange
        case .unsigned?: .red
        case .unknown?, nil: .gray
        }
    }

    /// `2 things need a look`.
    public var warningTitle: String? {
        guard !warnings.isEmpty else { return nil }
        return warnings.count == 1 ? "1 thing needs a look" : "\(warnings.count) things need a look"
    }

    // MARK: - Building

    /// `grouped`: alike events of one process in one row (requests to one address, files in one folder).
    public static func make(_ trace: ProcessTrace, environment: SandvaultEnvironment, grouped: Bool = true) -> ProcessDetail {
        var builder = Builder(trace: trace, environment: environment, grouped: grouped)
        builder.build()
        let rows = builder.rows.sorted { ($0.time, $0.id) < ($1.time, $1.id) }
        let descendants = trace.includesChildren ? trace.descendants.count : trace.children.count
        let tiles = [
            ProcessDetailTile(filter: .all, count: trace.items.count + builder.launches),
            ProcessDetailTile(filter: .web, count: builder.webRequests),
            ProcessDetailTile(filter: .network, count: builder.hosts.count),
            ProcessDetailTile(filter: .files, count: builder.paths.count),
            ProcessDetailTile(filter: .programs, count: descendants),
        ]
        return ProcessDetail(
            process: trace.process, chain: trace.ancestors + [trace.process], children: trace.children,
            descendantCount: trace.descendants.count, includesChildren: trace.includesChildren, rows: rows, tiles: tiles,
            warnings: rows.filter { $0.sensitive != nil }, encryptedConnections: builder.encrypted, recordedFileEvents: builder.fileEvents
        )
    }

    struct Builder {
        let trace: ProcessTrace
        let environment: SandvaultEnvironment
        let grouped: Bool
        var rows: [ProcessDetailRow] = []
        var index: [String: Int] = [:]
        var webRequests = 0
        var launches = 0
        var encrypted = 0
        var fileEvents = 0
        var hosts: Set<String> = []
        var paths: Set<String> = []
        /// Paths a process created: its later writes count as part of creating them, as in Changes (D45).
        var created: Set<String> = []

        init(trace: ProcessTrace, environment: SandvaultEnvironment, grouped: Bool) {
            self.trace = trace
            self.environment = environment
            self.grouped = grouped
        }

        mutating func build() {
            for item in trace.items {
                guard case .file(let event) = item.content, event.kind == .create else { continue }
                created.insert(item.processID + "\u{0}" + event.path)
            }
            startRows()
            for item in trace.items { add(item) }
        }

        func name(_ id: String) -> String {
            trace.process(id)?.name ?? "unknown"
        }

        /// One row per key; a repeated key adds to the row (grouped) or gets its own (not grouped).
        mutating func put(_ key: String, _ row: ProcessDetailRow, merge: (inout ProcessDetailRow) -> Void) {
            guard grouped, let at = index[key] else {
                index[key] = rows.count
                rows.append(row)
                return
            }
            rows[at].count += 1
            merge(&rows[at])
        }

        /// The process's own start, and every program it (or, with children, they) started.
        mutating func startRows() {
            let root = trace.process
            let ownStarts = trace.items.filter { $0.processID == root.id && Self.isStart($0) }
            if ownStarts.isEmpty, let start = root.start {
                rows.append(started(root, at: start, path: root.executable, command: root.command, cwd: root.cwd, id: "start-" + root.id))
            }
            let launched = trace.includesChildren ? trace.descendants : trace.children
            for child in launched {
                guard let parentID = child.parentID, let time = child.start ?? child.firstSeen else { continue }
                launches += 1
                let command = child.command ?? child.executable ?? child.name
                let sensitive = Self.sensitiveProgram(child)
                let key = "launch \(parentID) \(child.name)"
                var row = ProcessDetailRow(
                    id: "launch-" + child.id, time: time, kind: .launched, title: "Started \(child.name)", detail: command,
                    status: child.running ? "Running" : nil, statusTint: .green, sensitive: sensitive, count: 1, processID: parentID,
                    pid: trace.process(parentID)?.pid ?? child.ppid ?? 0, processName: name(parentID), opens: child.reference
                )
                if sensitive != nil { row.status = "Keychain" }
                put(key, row) { row in
                    row.title = "Started \(child.name) \(row.count == 2 ? "twice" : "\(row.count) times")"
                    if !row.detail.contains(command), row.detail.count < 160 { row.detail += ", " + command }
                    // Open shows the newest one.
                    row.opens = child.reference
                    if child.running { row.status = "Running" }
                    if sensitive != nil { row.sensitive = sensitive }
                }
            }
        }

        func started(_ process: TracedProcess, at time: Date, path: String?, command: String?, cwd: String?, id: String) -> ProcessDetailRow {
            let place = cwd.map { " in " + PathDisplay.short($0, environment) } ?? ""
            let program = path.map { PathDisplay.name($0) } ?? process.name
            return ProcessDetailRow(
                id: id, time: time, kind: .started, title: "Started \(program)\(place)", detail: command ?? path ?? program,
                status: nil, statusTint: .gray, sensitive: nil, count: 1, processID: process.id, pid: process.pid, processName: process.name
            )
        }

        static func isStart(_ item: ProcessTraceItem) -> Bool {
            if case .started = item.content { return true }
            return false
        }

        mutating func add(_ item: ProcessTraceItem) {
            switch item.content {
            case .started(let event):
                // A started program's own start is its parent's Started row; only the shown process lists its own.
                guard item.processID == trace.process.id else { return }
                let command = event.arguments.isEmpty ? event.path : event.arguments.joined(separator: " ")
                guard let process = trace.process(item.processID) else { return }
                rows.append(started(process, at: item.time, path: event.path, command: command, cwd: event.cwd, id: item.id))
            case .file(let event):
                fileEvents += 1
                file(item, event)
            case .connection(let record):
                connection(item, record)
            case .ask(let ask):
                hosts.insert(ask.host)
                let target = Format.endpoint(ask.host, ask.port)
                put("ask \(item.processID) \(target)", ProcessDetailRow(
                    id: item.id, time: item.time, kind: .asking, title: "Asks to connect to \(target)", detail: "Waits for your answer",
                    status: "Waiting", statusTint: .orange, sensitive: nil, count: 1, processID: item.processID, pid: item.pid,
                    processName: name(item.processID), host: ask.host
                )) { _ in }
            }
        }

        mutating func file(_ item: ProcessTraceItem, _ event: FileActivityEvent) {
            guard let action = ActivityReport.action(event), action != .run else { return }
            if action == .change, created.contains(item.processID + "\u{0}" + event.path) { return }
            paths.insert(event.path)
            let sensitive = SensitivePlace.classify(event.path, environment: environment)
            let anchor = ActivityReport.anchor(of: event.path)
            let key = "file \(item.processID) \(action.rawValue) \(sensitive?.kind.rawValue ?? "") \(anchor)"
            let short = PathDisplay.short(event.path, environment)
            var detail = short
            if action == .move, let destination = event.destination { detail += " → " + PathDisplay.short(destination, environment) }
            let object = sensitive?.title ?? PathDisplay.name(event.path)
            let row = ProcessDetailRow(
                id: item.id, time: item.time, kind: .file, action: action, title: "\(action.verb) \(object)", detail: detail,
                status: sensitive == nil ? nil : "Sensitive", statusTint: .red, sensitive: sensitive, count: 1, processID: item.processID,
                pid: item.pid, processName: name(item.processID), files: [event.path]
            )
            guard grouped, let at = index[key] else {
                index[key] = rows.count
                rows.append(row)
                return
            }
            // Count files, not events: a file read twice in a folder stays one.
            var files = rows[at].files
            guard !files.contains(event.path) else { return }
            files.append(event.path)
            rows[at].files = files
            rows[at].count = files.count
            if sensitive == nil {
                rows[at].title = "\(action.verb) \(Format.grouped(files.count)) files in \(PathDisplay.name(anchor))"
            }
            let names = files.map { ActivityReport.relative($0, to: anchor) }
            rows[at].detail = files.count > ActivityReport.foldAbove ? PathDisplay.short(anchor, environment) : ActivityReport.names(names)
        }

        mutating func connection(_ item: ProcessTraceItem, _ record: ConnectionRecord) {
            hosts.insert(record.host)
            let target = Format.endpoint(record.host, record.port)
            let process = name(item.processID)
            func row(_ kind: ProcessDetailRow.Kind, _ title: String, _ detail: String, _ status: String?, _ tint: Tint, id: String? = nil,
                     time: Date? = nil) -> ProcessDetailRow {
                ProcessDetailRow(
                    id: id ?? item.id, time: time ?? item.time, kind: kind, title: title, detail: detail, status: status, statusTint: tint,
                    sensitive: nil, count: 1, processID: item.processID, pid: item.pid, processName: process, host: record.host
                )
            }
            if record.decision.blocked {
                let why: String
                switch record.decision {
                case .askedDenied: why = "You denied it when asked"
                case .timedOut: why = "Nobody answered in time"
                default: why = "Blocked by a rule or the default for unknown hosts"
                }
                put("blocked \(item.processID) \(target)", row(.blocked, "Blocked \(target)", why, "Blocked", .red)) { row in
                    row.detail = "\(why) · \(row.count) times"
                }
                return
            }
            if record.kind == .dns {
                let answers = record.dnsAnswers.isEmpty ? "No answer" : record.dnsAnswers.joined(separator: ", ")
                put("dns \(item.processID) \(record.host)", row(.dns, "Looked up \(record.host)", answers, nil, .gray)) { row in
                    row.title = "Looked up \(record.host) \(row.count) times"
                }
                return
            }
            if record.kind == .transparentTCP {
                let detail = "TCP · \(Format.bytes(record.bytesIn)) in, \(Format.bytes(record.bytesOut)) out"
                let status = record.error == nil ? nil : "Failed"
                put("tcp \(item.processID) \(target)", row(.connection, "Connected to \(target)", record.error ?? detail, status, .orange)) { row in
                    row.title = "Connected to \(target) \(row.count) times"
                }
                return
            }
            guard !record.http.isEmpty else {
                webRequests += 1
                let tls = record.kind == .transparentTLS || (record.kind == .explicitProxy && record.port != 80)
                if tls, !record.inspected { encrypted += 1 }
                let status: String? = record.error != nil ? "Failed" : tls ? "Encrypted" : nil
                let sizes = "\(Format.bytes(record.bytesIn)) in, \(Format.bytes(record.bytesOut)) out"
                let detail = record.error ?? (tls ? "Encrypted · \(sizes)" : sizes)
                put("web \(item.processID) \(target)", row(.web, "Connected to \(record.host)", detail, status, record.error == nil ? .gray : .orange)) { row in
                    row.title = "\(row.count) connections to \(record.host)"
                }
                return
            }
            for (number, summary) in record.http.enumerated() {
                webRequests += 1
                let path = WebRequestRow.path(of: summary.url)
                let plain = path.split(separator: "?", maxSplits: 1).first.map(String.init) ?? path
                let status = summary.status.map(String.init) ?? (record.error == nil ? nil : "Failed")
                let tint: Tint = summary.status.map { $0 >= 500 ? .red : $0 >= 400 ? .orange : .green } ?? .orange
                var parts: [String] = []
                if let size = summary.responseBytes { parts.append(Format.bytes(size)) }
                if let duration = summary.durationMs { parts.append("\(duration) ms") }
                let time = summary.startedAt ?? item.time.addingTimeInterval(Double(number) / 1000)
                let new = row(.web, "\(summary.method) \(record.host)\(plain)", parts.joined(separator: " · "), status, tint,
                              id: "\(item.id)/\(number)", time: time)
                put("request \(item.processID) \(summary.method) \(record.host) \(plain)", new) { row in
                    row.detail = "\(row.count) requests" + (parts.isEmpty ? "" : " · newest " + parts.joined(separator: " · "))
                    row.status = status
                    row.statusTint = tint
                }
            }
        }

        /// `security` reads and changes keychains; starting it counts as touching one.
        static func sensitiveProgram(_ process: TracedProcess) -> SensitivePlace? {
            guard process.name == "security" || process.executable == "/usr/bin/security" else { return nil }
            return SensitivePlace(.keychain, "the keychain tool", "security reads and changes keychains: passwords, keys and certificates.")
        }
    }
}

