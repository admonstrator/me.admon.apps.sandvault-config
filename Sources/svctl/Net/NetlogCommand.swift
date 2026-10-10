import ArgumentParser
import Foundation
import SandvaultCore
import SandvaultNet

struct NetLogCommand: AsyncParsableCommand {
    static let configuration = CommandConfiguration(
        commandName: "netlog",
        abstract: "Connections and DNS queries netd decided on.",
        discussion: """
            Reads the connection log file; --follow then streams new records from netd's control socket.
              svctl netlog --requests
              svctl netlog content 1a2b3c4d > body.json
            """,
        subcommands: [Content.self]
    )

    @OptionGroup var global: GlobalOptions
    @Flag(help: "Keep printing new records as netd decides them.") var follow = false
    @Option(help: "Number of records to show from the log.") var limit = 50
    @Flag(help: "Only blocked connections (denied, denied on ask, ask timed out).") var denied = false
    @Option(help: "Only hosts containing this text.") var host: String?
    @Flag(help: "One line per web request (time, process, method, URL, status, size) instead of per connection.") var requests = false

    func run() async throws {
        let filter = ConnectionFilter(deniedOnly: denied, host: host)
        let records = try ConnectionLog.read(path: global.paths.connectionLog, limit: max(0, limit), filter: filter)
        if !follow {
            if requests {
                let lines = records.flatMap(RequestLine.lines)
                if global.json { return try Output.json(lines) }
                if lines.isEmpty { Output.line("no recorded web requests in \(global.paths.connectionLog)") }
                lines.forEach { Output.line($0.text) }
                return
            }
            if global.json { return try Output.json(records) }
            if records.isEmpty { Output.line("no matching records in \(global.paths.connectionLog)") }
            records.forEach { Output.line(NetCLI.describe($0)) }
            return
        }

        let client = try await ControlClient.connect(socketPath: NetCLI.socketPath(global))
        defer { client.close() }
        try await client.subscribe([.connections])
        for record in records { try emit(record) }
        for await event in client.events {
            guard case .connection(let record) = event, filter.matches(record) else { continue }
            try emit(record)
        }
        throw SandvaultError.io("netd closed the control connection")
    }

    /// JSON Lines with --json, one text line otherwise; with --requests one per web request.
    private func emit(_ record: ConnectionRecord) throws {
        if requests {
            for line in RequestLine.lines(record) {
                if global.json { FileHandle.standardOutput.write(try ControlCodec.encode(line)) } else { Output.line(line.text) }
            }
        } else if global.json {
            FileHandle.standardOutput.write(try ControlCodec.encode(record))
        } else {
            Output.line(NetCLI.describe(record))
        }
    }

    /// One web request with the program that made it.
    struct RequestLine: Encodable {
        var process: String?
        var pid: Int32?
        var request: HTTPSummary
        var timestamp: Date

        static func lines(_ record: ConnectionRecord) -> [RequestLine] {
            record.http.map { RequestLine(process: record.process, pid: record.pid, request: $0, timestamp: $0.startedAt ?? record.timestamp) }
        }

        /// `time  process(pid)  METHOD  URL  status  size  duration  [req <id>] [res <id>]`.
        var text: String {
            var parts = [NetCLI.timestamp(timestamp), process.map { "\($0)(\(pid.map(String.init) ?? "?"))" } ?? "-"]
            parts += [request.method, request.url, request.status.map(String.init) ?? "-"]
            parts.append(request.responseBytes.map(NetCLI.bytes) ?? "-")
            if let duration = request.durationMs { parts.append("\(duration) ms") }
            if let content = request.requestContent { parts.append("req \(NetCLI.shortID(content.id))") }
            if let content = request.responseContent { parts.append("res \(NetCLI.shortID(content.id))") }
            return parts.joined(separator: "  ")
        }
    }

    struct Content: AsyncParsableCommand {
        static let configuration = CommandConfiguration(
            abstract: "Print one stored request or response body as raw bytes.",
            discussion: "The id is a StoredContent id from `svctl netlog --requests` (a prefix is enough when the log names it)."
        )

        @OptionGroup var global: GlobalOptions
        @Argument(help: "The content id or the start of it.") var id: String

        func run() async throws {
            let contentID = try resolve(id)
            let client = try await ControlClient.connect(socketPath: NetCLI.socketPath(global))
            defer { client.close() }
            let (meta, data) = try await client.content(id: contentID)
            if global.json { return try Output.json(meta) }
            FileHandle.standardOutput.write(data)
            if meta.truncated {
                let size = meta.size.map { "of \(NetCLI.bytes($0))" } ?? "of an incomplete body"
                FileHandle.standardError.write(Data("note: kept \(NetCLI.bytes(Int64(meta.storedBytes))) \(size)\n".utf8))
            }
        }

        /// A full UUID, or the one stored content in the connection log whose id starts with `text`.
        private func resolve(_ text: String) throws -> UUID {
            if let uuid = UUID(uuidString: text) { return uuid }
            let prefix = text.lowercased()
            let records = try ConnectionLog.read(path: global.paths.connectionLog, limit: Int.max)
            let ids = Set(records.flatMap(\.http).flatMap { [$0.requestContent?.id, $0.responseContent?.id] }.compactMap { $0 })
            let matches = ids.filter { $0.uuidString.lowercased().hasPrefix(prefix) }
            guard matches.count == 1, let match = matches.first else {
                throw SandvaultError.invalidInput(matches.isEmpty ? "no stored content matches '\(text)'" : "'\(text)' matches several contents")
            }
            return match
        }
    }
}
