import ArgumentParser
import Foundation
import SandvaultCore
import SandvaultNet

struct NetDnsCommand: AsyncParsableCommand {
    static let configuration = CommandConfiguration(
        commandName: "dns",
        abstract: "Fixed answers of the netd DNS forwarder (also used by the proxy).",
        subcommands: [List.self, Override.self, Remove.self]
    )

    struct List: AsyncParsableCommand {
        static let configuration = CommandConfiguration(abstract: "List the DNS overrides.")
        @OptionGroup var global: GlobalOptions

        func run() async throws {
            let overrides = try global.configStore.load().network.dnsOverrides
            if global.json { return try Output.json(overrides) }
            guard !overrides.isEmpty else { return Output.line("no DNS overrides") }
            Output.table(["ID", "PATTERN", "ADDRESS", "NOTE"], overrides.map {
                [NetCLI.shortID($0.id), $0.pattern, $0.address, $0.note ?? ""]
            })
        }
    }

    struct Override: AsyncParsableCommand {
        static let configuration = CommandConfiguration(
            abstract: "Answer queries for a host or `*.domain` with a fixed address.",
            discussion: "An override is exempt from the private-destination guard: it is how the sandbox reaches a chosen LAN host through the proxy."
        )
        @OptionGroup var global: GlobalOptions
        @Argument(help: "db.example.com or *.example.com.") var pattern: String
        @Argument(help: "IPv4 or IPv6 address.") var address: String

        func run() async throws {
            let (entry, reloaded) = try await NetCLI.edit(global) { try $0.network.upsertDnsOverride(pattern: pattern, address: address) }
            if global.json { return try Output.json(entry) }
            Output.line("\(entry.pattern) -> \(entry.address) [\(NetCLI.shortID(entry.id))]; \(NetCLI.reloadNote(reloaded))")
        }
    }

    struct Remove: AsyncParsableCommand {
        static let configuration = CommandConfiguration(abstract: "Remove an override by id prefix or pattern.")
        @OptionGroup var global: GlobalOptions
        @Argument(help: "The start of the override id (see `svctl dns list`) or its pattern.") var selector: String

        func run() async throws {
            let (entry, reloaded) = try await NetCLI.edit(global) { try $0.network.removeDnsOverride(selector: selector) }
            if global.json { return try Output.json(entry) }
            Output.line("removed \(entry.pattern) -> \(entry.address); \(NetCLI.reloadNote(reloaded))")
        }
    }
}
