import ArgumentParser
import SandvaultCore

/// LaunchAgent entry point (agent C).
@main
struct Netd: AsyncParsableCommand {
    static let configuration = CommandConfiguration(
        commandName: "sandvault-netd",
        abstract: "Proxy, DNS forwarder and connection log for the sandvault sandbox.",
        version: BundleIdentity.version
    )

    func run() async throws {
        throw SandvaultError.notImplemented("sandvault-netd")
    }
}
