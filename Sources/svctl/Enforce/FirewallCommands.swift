import ArgumentParser
import Foundation
import SandvaultCore
import SandvaultEnforce

struct FirewallCommand: AsyncParsableCommand {
    static let configuration = CommandConfiguration(
        commandName: "firewall",
        abstract: "Per-user pf firewall for the sandbox (anchor \(AppPaths.pfAnchor)).",
        discussion: """
        mode, lan, localhost and except change config.json only; `apply` loads the anchor through the root helper. \
        `off` flushes the anchor and is the way back from any mode.
        """,
        subcommands: [Status.self, Mode.self, LAN.self, Localhost.self, Except.self, Preview.self, Apply.self, Off.self]
    )
}

extension FirewallCommand {
    struct Status: AsyncParsableCommand {
        static let configuration = CommandConfiguration(abstract: "Configured policy and, on macOS, what the helper has loaded.")
        @OptionGroup var global: GlobalOptions

        struct Report: Encodable {
            var config: NetworkPolicy
            var loaded: HelperStatus?
            var loadedError: String?
        }

        func run() async throws {
            let network = try global.configStore.load().network
            var report = Report(config: network)
            if EnforcePlatform.isMacOS {
                do { report.loaded = try await EnforceCLI.applier(global).status() } catch { report.loadedError = "\(error)" }
            } else {
                report.loadedError = SandvaultError.unsupportedPlatform("pf").description
            }
            if global.json { return try Output.json(report) }

            Output.line("mode: \(network.mode.cliName)   lan guard: \(network.blockLAN ? "on" : "off")   localhost: \(network.localhost.cliName)")
            Output.line("netd ports: proxy \(network.ports.explicitProxy), http \(network.ports.transparentHTTP), tls \(network.ports.transparentTLS), dns \(network.ports.dns)")
            if network.portExceptions.isEmpty {
                Output.line("exceptions: none")
            } else {
                Output.table(["ID", "PROTO", "DESTINATION", "PORT", "NOTE"], network.portExceptions.map {
                    [EnforceCLI.shortID($0.id), $0.proto.rawValue, $0.destination, $0.port.map(String.init) ?? "any", $0.note ?? ""]
                })
            }
            if let loaded = report.loaded {
                let pf = loaded.pfEnabled.map { $0 ? "enabled" : "disabled" } ?? "unknown"
                Output.line("loaded: \((loaded.firewallMode ?? .off).cliName), pf \(pf)" + (loaded.panicActive ? ", PANIC ACTIVE" : "")
                    + (loaded.anchorChanged ? ", anchor differs from the last apply" : ""))
            } else if let error = report.loadedError {
                Output.line("loaded: unknown (\(error))")
            }
        }
    }

    struct Mode: AsyncParsableCommand {
        static let configuration = CommandConfiguration(abstract: "Set the mode: off, open, proxy-only or blocked.")
        @OptionGroup var global: GlobalOptions
        @Argument(help: "off, open, proxy-only or blocked.") var mode: EnforceCLI.ModeArgument

        func run() async throws {
            try FirewallCommand.edit(global, "mode \(mode.rawValue)") { $0.mode = mode.mode }
        }
    }

    struct LAN: AsyncParsableCommand {
        static let configuration = CommandConfiguration(commandName: "lan", abstract: "Block direct traffic to private networks (on) or not (off).")
        @OptionGroup var global: GlobalOptions
        @Argument(help: "on or off.") var state: EnforceCLI.SwitchArgument

        func run() async throws {
            try FirewallCommand.edit(global, "lan guard \(state.rawValue)") { $0.blockLAN = state == .on }
        }
    }

    struct Localhost: AsyncParsableCommand {
        static let configuration = CommandConfiguration(abstract: "Which loopback ports the sandbox may reach.")
        @OptionGroup var global: GlobalOptions
        @Argument(help: "sandbox-and-helpers, allow-all or block-all.") var policy: EnforceCLI.LocalhostArgument

        func run() async throws {
            try FirewallCommand.edit(global, "localhost \(policy.rawValue)") { $0.localhost = policy.policy }
        }
    }

    struct Except: AsyncParsableCommand {
        static let configuration = CommandConfiguration(
            commandName: "except", abstract: "Direct traffic allowed past the guards (e.g. SSH to a host).",
            subcommands: [Add.self, Remove.self]
        )

        struct Add: AsyncParsableCommand {
            static let configuration = CommandConfiguration(abstract: "Add an exception: <tcp|udp> <address, CIDR or any> [port].")
            @OptionGroup var global: GlobalOptions
            @Argument(help: "tcp or udp.") var proto: EnforceCLI.ProtoArgument
            @Argument(help: "Address, CIDR (140.82.112.0/20) or any.") var destination: String
            @Argument(help: "Port (default: every port).") var port: UInt16?
            @Option(name: .long, help: "Free-text note.") var note: String?

            func run() async throws {
                var id = UUID()
                try FirewallCommand.edit(global, nil) {
                    id = try $0.add(PortException(proto: proto.proto, destination: destination, port: port, note: note))
                }
                if global.json { return try Output.json(["id": id.uuidString.lowercased()]) }
                Output.line("exception \(EnforceCLI.shortID(id)) in config; run svctl firewall apply")
            }
        }

        struct Remove: AsyncParsableCommand {
            static let configuration = CommandConfiguration(abstract: "Remove an exception by id prefix.")
            @OptionGroup var global: GlobalOptions
            @Argument(help: "First characters of the exception id (at least 4).") var idPrefix: String

            func run() async throws {
                var removed: PortException?
                try FirewallCommand.edit(global, nil) { removed = try $0.removeException(idPrefix: idPrefix) }
                guard let removed else { return }
                if global.json { return try Output.json(["removed": removed.id.uuidString.lowercased()]) }
                Output.line("removed exception \(EnforceCLI.shortID(removed.id)); run svctl firewall apply")
            }
        }
    }

    struct Preview: AsyncParsableCommand {
        static let configuration = CommandConfiguration(abstract: "Print the pf rules apply would load.")
        @OptionGroup var global: GlobalOptions
        @Option(name: .long, help: "Sandbox uid to use instead of looking it up (dscl, id).") var uid: UInt32?

        func run() async throws {
            let (_, rules) = try await FirewallCommand.generate(global, uid: uid)
            if global.json { return try Output.json(["rules": rules]) }
            print(rules ?? "# mode off: no anchor (apply flushes \(AppPaths.pfAnchor))\n", terminator: "")
        }
    }

    struct Apply: AsyncParsableCommand {
        static let configuration = CommandConfiguration(abstract: "Load the anchor for the configured mode (root helper); also ends a panic.")
        @OptionGroup var global: GlobalOptions
        @Flag(name: .long, help: "Do not ask for confirmation.") var yes = false

        func run() async throws {
            try EnforceCLI.requireMacOS("firewall apply")
            let (state, rules) = try await FirewallCommand.generate(global, uid: nil)
            if !global.json { print(rules ?? "# mode off: the anchor will be flushed\n", terminator: "") }
            guard try EnforceCLI.confirm("Load these rules for \(global.environment.sandvaultUser)?", yes: yes, json: global.json) else {
                throw ExitCode.failure
            }
            let result = try await EnforceCLI.applier(global).applyFirewall(state, releasingPanic: true)
            _ = await NetCLI.reload(global)
            try EnforceCLI.report(result, json: global.json)
        }
    }

    struct Off: AsyncParsableCommand {
        static let configuration = CommandConfiguration(abstract: "Set mode off and flush the anchor (rollback from any mode, also after a panic).")
        @OptionGroup var global: GlobalOptions

        func run() async throws {
            try EnforceCLI.requireMacOS("firewall off")
            var config = try global.configStore.load()
            config.network.mode = .off
            try global.configStore.save(config)
            let result = try await EnforceCLI.applier(global).disableFirewall()
            _ = await NetCLI.reload(global)
            try EnforceCLI.report(result, json: global.json)
        }
    }

    /// Load, change, save. `what` (when given) is echoed with a reminder to apply.
    static func edit(_ global: GlobalOptions, _ what: String?, _ change: (inout NetworkPolicy) throws -> Void) throws {
        var config = try global.configStore.load()
        try change(&config.network)
        try global.configStore.save(config)
        guard let what else { return }
        if global.json { return try Output.json(config.network) }
        Output.line("\(what) in config; run svctl firewall apply")
    }

    /// The state apply sends (config plus the sandbox's current loopback ports) and the rules it generates.
    static func generate(_ global: GlobalOptions, uid override: UInt32?) async throws -> (AppliedState, String?) {
        let config = try global.configStore.load()
        let needsPorts = config.network.mode != .off && config.network.localhost == .sandboxAndHelpers
        let ports = needsPorts ? await EnforceCLI.dynamicLocalPorts(global) : []
        let state = AppliedState(config: config, dynamicLocalPorts: ports)
        guard config.network.mode != .off else { return (state, nil) }
        let uid = try await EnforceCLI.uid(override, global)
        return (state, try PFAnchorGenerator.rules(for: state, uid: uid))
    }
}
