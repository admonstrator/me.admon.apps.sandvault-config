import ArgumentParser
import Foundation
import SandvaultCore
import SandvaultNet

struct NetCACommand: AsyncParsableCommand {
    static let configuration = CommandConfiguration(
        commandName: "ca",
        abstract: "The local CA for TLS inspection (key stays in the host home, mode 0600).",
        subcommands: [Create.self, Show.self, Publish.self, Remove.self]
    )

    struct Info: Codable {
        var subject: String
        var fingerprint: String
        var notValidAfter: Date
        var keyPath: String
        var certificatePath: String
        var published: CAPublisher.State?
        var publicCertificate: String
        var publicBundle: String
    }

    static func info(_ ca: InspectionCA, global: GlobalOptions) throws -> Info {
        let store = CAStore(paths: global.paths)
        let shared = try? NetCLI.requireSharedWorkspace(global)
        let published = shared.flatMap { try? CAPublisher(paths: global.paths, runner: global.runner, shared: $0).state(of: ca) }
        return Info(
            subject: ca.subject, fingerprint: try ca.fingerprint, notValidAfter: ca.notValidAfter, keyPath: store.keyPath,
            certificatePath: store.certificatePath, published: published, publicCertificate: global.paths.publicCACertificate,
            publicBundle: global.paths.publicCABundle
        )
    }

    static func print(_ info: Info) {
        Output.line("subject:     \(info.subject)")
        Output.line("fingerprint: SHA-256 \(info.fingerprint)")
        Output.line("valid until: \(NetCLI.timestamp(info.notValidAfter))")
        Output.line("key:         \(info.keyPath)")
        Output.line("certificate: \(info.certificatePath)")
        Output.line("published:   \(info.published?.rawValue ?? "unknown (no shared workspace)") (\(info.publicCertificate))")
    }

    struct Create: AsyncParsableCommand {
        static let configuration = CommandConfiguration(abstract: "Create the CA (keeps an existing one).")
        @OptionGroup var global: GlobalOptions

        func run() async throws {
            let (ca, created) = try CAStore(paths: global.paths).loadOrCreate(hostUser: global.environment.hostUser)
            let info = try NetCACommand.info(ca, global: global)
            if global.json { return try Output.json(info) }
            Output.line(created ? "created the inspection CA" : "the inspection CA already exists")
            NetCACommand.print(info)
            if created { Output.line("next: svctl ca publish (or svctl proxy inspection on)") }
        }
    }

    struct Show: AsyncParsableCommand {
        static let configuration = CommandConfiguration(abstract: "Show the CA and whether the sandbox copy is current.")
        @OptionGroup var global: GlobalOptions

        func run() async throws {
            guard let ca = try CAStore(paths: global.paths).load() else {
                throw SandvaultError.notInstalled("inspection CA (run `svctl ca create`)")
            }
            let info = try NetCACommand.info(ca, global: global)
            if global.json { return try Output.json(info) }
            NetCACommand.print(info)
        }
    }

    struct Publish: AsyncParsableCommand {
        static let configuration = CommandConfiguration(abstract: "Copy the CA and a CA bundle (system roots + CA) into the shared workspace.")
        @OptionGroup var global: GlobalOptions

        func run() async throws {
            guard let ca = try CAStore(paths: global.paths).load() else {
                throw SandvaultError.notInstalled("inspection CA (run `svctl ca create`)")
            }
            let shared = try NetCLI.requireSharedWorkspace(global)
            let result = try await CAPublisher(paths: global.paths, runner: global.runner, shared: shared).publish(ca)
            if global.json { return try Output.json(result) }
            Output.line("published \(result.certificatePath)")
            Output.line("published \(result.bundlePath) (\(result.systemRootCount) system roots + CA)")
        }
    }

    struct Remove: AsyncParsableCommand {
        static let configuration = CommandConfiguration(abstract: "Delete the CA and its published copies; turns inspection off.")
        @OptionGroup var global: GlobalOptions

        func run() async throws {
            let store = CAStore(paths: global.paths)
            let shared = try? NetCLI.requireSharedWorkspace(global)
            if let shared { try CAPublisher(paths: global.paths, runner: global.runner, shared: shared).unpublish() }
            try store.remove()
            var reloaded = false
            let config = try global.configStore.load()
            if config.network.inspection.enabled {
                reloaded = try await NetCLI.edit(global) { $0.network.inspection.enabled = false }.reloaded
                // Without this the sandbox's SSL_CERT_FILE would point at the removed bundle.
                var policy = config.network
                policy.inspection.enabled = false
                if let shared { try SandboxEnvironmentBlock.apply(policy: policy, paths: global.paths, shared: shared) }
            } else {
                reloaded = await NetCLI.reload(global)
            }
            if global.json { return try Output.json(["removed": store.directory]) }
            Output.line("removed the inspection CA\(config.network.inspection.enabled ? " and turned inspection off" : ""); \(NetCLI.reloadNote(reloaded))")
        }
    }
}
