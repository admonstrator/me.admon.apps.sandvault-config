import ArgumentParser
import SandvaultCore

/// Root helper entry point (agent B). Runs only through `sudo -n`; see HelperProtocol.swift for the rules.
@main
struct Helper: AsyncParsableCommand {
    static let configuration = CommandConfiguration(
        commandName: "svctl-helper",
        abstract: "Privileged helper for Sandvault Config (run through sudo).",
        version: BundleIdentity.version
    )

    func run() async throws {
        throw SandvaultError.notImplemented("svctl-helper")
    }
}
