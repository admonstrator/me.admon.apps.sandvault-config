import ArgumentParser
import Foundation
import SandvaultCore
import SandvaultNet
import SandvaultObserve

extension ActivityCommand {
    /// `svctl activity process <pid>`: what one process and the programs it started did (D51).
    struct Trace: AsyncParsableCommand {
        static let configuration = CommandConfiguration(
            commandName: "process",
            abstract: "Show what one sandbox process and the programs it started did: web, connections, DNS, files and programs.",
            discussion: """
                Puts together the recorded files and programs (svctl activity record), netd's connection log and, \
                when netd runs, its open connections and waiting asks, and the running processes. Files and programs \
                need the recording; web requests show their address only for plain HTTP and inspected HTTPS.
                  svctl activity process 4121
                  svctl activity process 4195 --no-children --json
                """
        )

        @OptionGroup var global: GlobalOptions

        @Argument(help: "The process id.") var pid: Int32

        @Option(name: .long, help: "A moment the process existed (ISO 8601), for a pid used by several processes.")
        var at: String?

        @Flag(name: .customLong("no-children"), help: "Leave out the programs it started.")
        var noChildren = false

        @Option(name: .long, help: "Connection log records to read, newest first.")
        var limit = 20_000

        func validate() throws {
            if let at, ISO8601DateFormatter().date(from: at) == nil {
                throw ValidationError("--at expects an ISO 8601 time such as 2026-10-15T14:02:11Z, not '\(at)'")
            }
        }

        func run() async throws {
            let settings = try global.configStore.load().activity
            let events = try await LiveActivityRecorder(paths: global.paths, runner: global.runner)
                .stored(since: nil, retentionDays: settings.retentionDays)
            var records = try ConnectionLog.read(path: global.paths.connectionLog, limit: max(0, limit))
            var asks: [AskRequest] = []
            if let client = try? await ControlClient.connect(socketPath: NetCLI.socketPath(global)) {
                defer { client.close() }
                let logged = Set(records.map(\.id))
                records += ((try? await client.openConnections()) ?? []).filter { !logged.contains($0.id) }
                asks = (try? await client.pendingAsks()) ?? []
            }
            #if os(macOS)
            let snapshot = try? await ProcessMonitor(environment: global.environment, runner: global.runner).snapshot()
            #else
            let snapshot: ProcessSnapshot? = nil
            #endif

            let tracer = ProcessTracer(snapshot: snapshot, events: events, connections: records, asks: asks)
            let reference = ProcessReference(pid: pid, at: at.flatMap { ISO8601DateFormatter().date(from: $0) })
            guard let trace = tracer.trace(reference, includeChildren: !noChildren) else {
                throw SandvaultError.invalidInput("nothing recorded or running for pid \(pid)")
            }
            if global.json { return try Output.json(trace) }
            Self.header(trace).forEach(Output.line)
            if trace.items.isEmpty {
                Output.line("nothing recorded for it yet")
                return
            }
            Output.line("")
            for item in trace.items {
                let name = trace.process(item.processID).map { "\($0.name)(\($0.pid))" } ?? "pid \(item.pid)"
                for line in Self.lines(item) {
                    Output.line(Format.command(([Format.time(item.time), name] + line).joined(separator: "  ")))
                }
            }
        }

        /// Name, state, command, chain, signature, children.
        static func header(_ trace: ProcessTrace) -> [String] {
            let process = trace.process
            var state = process.running ? "running" : "not running"
            if let start = process.start { state += ", started \(Format.time(start))" }
            if let session = process.sessionID { state += ", session \(Format.shortSession(session))" }
            var lines = ["\(process.name) (pid \(process.pid)) \(state)"]
            if let command = process.command { lines.append("command    " + Format.command(command)) }
            if let cwd = process.cwd { lines.append("in         " + cwd) }
            let chain = (trace.ancestors + [process]).map { "\($0.name)(\($0.pid))" }
            var parent = chain.joined(separator: " > ")
            if trace.ancestors.isEmpty, let ppid = process.ppid { parent = "pid \(ppid) > " + parent }
            lines.append("chain      " + parent)
            lines.append("signature  " + signature(process))
            if !trace.descendants.isEmpty {
                let children = trace.children.map { "\($0.name)(\($0.pid))" }.joined(separator: ", ")
                let more = trace.descendants.count - trace.children.count
                lines.append("started    " + children + (more > 0 ? " and \(more) below them" : ""))
            }
            return lines
        }

        static func signature(_ process: TracedProcess) -> String {
            let id = process.signingID.map { " (\($0))" } ?? ""
            switch process.signature {
            case .apple?: return "Apple" + id
            case .developer(let team)?: return (team.map { "developer, team \($0)" } ?? "developer") + id
            case .adHoc?: return "ad hoc, no developer" + id
            case .unsigned?: return "not signed"
            case .unknown?, nil: return "unknown (recorded with Files & programs)"
            }
        }

        /// The columns after time and process: what, then details.
        static func lines(_ item: ProcessTraceItem) -> [[String]] {
            switch item.content {
            case .started(let event), .file(let event):
                return [[ActivityCommand.verb(event), ActivityCommand.target(event)]]
            case .ask(let ask):
                return [["asks", target(ask.host, ask.port), "waiting for an answer"]]
            case .connection(let record):
                let where_ = target(record.host, record.port)
                if record.decision.blocked { return [["blocked", where_, record.decision.rawValue]] }
                if record.kind == .dns {
                    return [["dns", record.host, record.dnsAnswers.isEmpty ? "no answer" : "-> " + record.dnsAnswers.joined(separator: ",")]]
                }
                if !record.http.isEmpty {
                    return record.http.map { summary in
                        var parts = ["request", summary.method, summary.url, summary.status.map(String.init) ?? "-"]
                        if let size = summary.responseBytes { parts.append(Format.bytes(size)) }
                        return parts
                    }
                }
                var parts = ["connect", where_, record.kind == .transparentTCP ? "tcp" : record.inspected ? "inspected" : "encrypted"]
                parts.append("\(Format.bytes(record.bytesIn)) in, \(Format.bytes(record.bytesOut)) out")
                if let error = record.error { parts.append("failed: \(error)") }
                return [parts]
            }
        }

        static func target(_ host: String, _ port: UInt16?) -> String {
            port.map { "\(host):\($0)" } ?? host
        }
    }
}
