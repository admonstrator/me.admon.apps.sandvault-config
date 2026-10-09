import ArgumentParser
import SandvaultCore

@main
struct Svctl: AsyncParsableCommand {
    static let configuration = CommandConfiguration(
        commandName: "svctl",
        abstract: "Overview, control and permissions for the sandvault sandbox.",
        version: BundleIdentity.version,
        subcommands: allSubcommands
    )
}
