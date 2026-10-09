import ArgumentParser
import Foundation
import SandvaultCore
import SandvaultNet

struct NetLogCommand: AsyncParsableCommand {
    static let configuration = CommandConfiguration(
        commandName: "netlog",
        abstract: "Connections and DNS queries netd decided on.",
        discussion: "Reads the connection log file; --follow then streams new records from netd's control socket."
    )

    @OptionGroup var global: GlobalOptions
    @Flag(help: "Keep printing new records as netd decides them.") var follow = false
    @Option(help: "Number of records to show from the log.") var limit = 50
    @Flag(help: "Only blocked connections (denied, denied on ask, ask timed out).") var denied = false
    @Option(help: "Only hosts containing this text.") var host: String?

    func run() async throws {
        let filter = ConnectionFilter(deniedOnly: denied, host: host)
        let records = try ConnectionLog.read(path: global.paths.connectionLog, limit: max(0, limit), filter: filter)
        if !follow {
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

    /// JSON Lines with --json, one text line otherwise.
    private func emit(_ record: ConnectionRecord) throws {
        if global.json {
            FileHandle.standardOutput.write(try ControlCodec.encode(record))
        } else {
            Output.line(NetCLI.describe(record))
        }
    }
}
