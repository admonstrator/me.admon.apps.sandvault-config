import ArgumentParser
import Foundation
import SandvaultCore
import SandvaultNet

struct NetDatabaseCommand: AsyncParsableCommand {
    static let configuration = CommandConfiguration(
        commandName: "database",
        abstract: "The offline network table for ask details (owner and country of an address).",
        discussion: """
            The table is iptoasn.com's ip2asn-v4.tsv (public domain), downloaded only on request and kept on this Mac.
              svctl net database status
              svctl net database update
            """,
        subcommands: [Status.self, Update.self],
        defaultSubcommand: Status.self
    )

    static func describe(_ status: NetworkDatabaseStatus, path: String) -> String {
        guard status.installed else { return "not installed (\(path)); run: svctl net database update" }
        let date = status.updatedAt.map(NetCLI.timestamp) ?? "unknown date"
        return "\(status.ranges) ranges, updated \(date) (\(path))"
    }

    struct Status: AsyncParsableCommand {
        static let configuration = CommandConfiguration(abstract: "Whether the table is installed, its date and size.")
        @OptionGroup var global: GlobalOptions

        func run() async throws {
            let path = global.paths.networkDatabase
            let status = await NetworkDatabaseStore(path: path, runner: global.runner).status()
            if global.json { return try Output.json(status) }
            Output.line(NetDatabaseCommand.describe(status, path: path))
        }
    }

    struct Update: AsyncParsableCommand {
        static let configuration = CommandConfiguration(abstract: "Download the current table from iptoasn.com.")
        @OptionGroup var global: GlobalOptions

        func run() async throws {
            let path = global.paths.networkDatabase
            let status = try await NetworkDatabaseStore(path: path, runner: global.runner).update()
            if global.json { return try Output.json(status) }
            Output.line(NetDatabaseCommand.describe(status, path: path))
        }
    }
}
