import ArgumentParser
import Foundation
import SandvaultCore
import SandvaultNet

struct NetProxyCommand: AsyncParsableCommand {
    static let configuration = CommandConfiguration(
        commandName: "proxy",
        abstract: "Domain rules, default action, TLS inspection and the sandbox proxy variables.",
        subcommands: [Status.self, Rules.self, Allow.self, Deny.self, Ask.self, Remove.self, Default.self, Inspection.self, Env.self]
    )

    struct Report: Codable {
        var netd: NetdStatus?
        var mode: FirewallMode
        var defaultAction: DomainAction
        var askTimeoutSeconds: Int
        var askFallback: DomainAction
        var ports: ProxyPorts
        var rules: Int
        var overrides: Int
        var inspectionEnabled: Bool
        var blockPrivateDestinations: Bool
    }

    struct Status: AsyncParsableCommand {
        static let configuration = CommandConfiguration(abstract: "Show netd and the network policy.")
        @OptionGroup var global: GlobalOptions

        func run() async throws {
            let policy = try global.configStore.load().network
            let netd: NetdStatus?
            if let client = try? await ControlClient.connect(socketPath: NetCLI.socketPath(global)) {
                netd = try? await client.status()
                client.close()
            } else {
                netd = nil
            }
            let report = Report(
                netd: netd, mode: policy.mode, defaultAction: policy.defaultAction, askTimeoutSeconds: policy.askTimeoutSeconds,
                askFallback: policy.askFallback, ports: policy.ports, rules: policy.domainRules.count, overrides: policy.dnsOverrides.count,
                inspectionEnabled: policy.inspection.enabled, blockPrivateDestinations: policy.blockPrivateDestinations
            )
            if global.json { return try Output.json(report) }
            if let netd {
                Output.line("netd: running since \(NetCLI.timestamp(netd.startedAt)), version \(netd.version)")
                Output.line("  ports: proxy \(netd.ports.explicitProxy), http \(netd.ports.transparentHTTP), tls \(netd.ports.transparentTLS), dns \(netd.ports.dns)")
                Output.line("  \(netd.activeConnections) active, \(netd.allowedCount) allowed, \(netd.deniedCount) denied, \(netd.pendingAsks) pending asks")
                if let fingerprint = netd.caFingerprint { Output.line("  CA: \(fingerprint)") }
            } else {
                Output.line("netd: not running (\(NetCLI.socketPath(global)))")
            }
            Output.line("mode: \(policy.mode.rawValue)  default: \(policy.defaultAction.rawValue)  asks: \(policy.askTimeoutSeconds)s, then \(policy.askFallback.rawValue)")
            Output.line("rules: \(policy.domainRules.count)  dns overrides: \(policy.dnsOverrides.count)  inspection: \(policy.inspection.enabled ? "on" : "off")  private destinations: \(policy.blockPrivateDestinations ? "blocked" : "allowed")")
        }
    }

    struct Rules: AsyncParsableCommand {
        static let configuration = CommandConfiguration(abstract: "List the domain rules.")
        @OptionGroup var global: GlobalOptions

        struct Listing: Codable {
            var defaultAction: DomainAction
            var rules: [DomainRule]
        }

        func run() async throws {
            let policy = try global.configStore.load().network
            if global.json { return try Output.json(Listing(defaultAction: policy.defaultAction, rules: policy.domainRules)) }
            if policy.domainRules.isEmpty {
                Output.line("no rules")
            } else {
                Output.table(["ID", "PATTERN", "ACTION", "INSPECT", "NOTE"], policy.domainRules.map {
                    [NetCLI.shortID($0.id), $0.pattern, $0.action.rawValue, $0.inspect ? "yes" : "", $0.note ?? ""]
                })
            }
            Output.line("default: \(policy.defaultAction.rawValue)")
        }
    }

    static func setRule(_ global: GlobalOptions, pattern: String, action: DomainAction, inspect: Bool?) async throws {
        let (rule, reloaded) = try await NetCLI.edit(global) { config in
            try config.network.upsertDomainRule(pattern: pattern, action: action, inspect: inspect)
        }
        if global.json { return try Output.json(rule) }
        Output.line("\(action.rawValue) \(rule.pattern)\(rule.inspect ? " (inspect)" : "") [\(NetCLI.shortID(rule.id))]; \(NetCLI.reloadNote(reloaded))")
        if rule.inspect, try !global.configStore.load().network.inspection.enabled {
            Output.line("note: inspection is off; turn it on with `svctl proxy inspection on`")
        }
    }

    struct Allow: AsyncParsableCommand {
        static let configuration = CommandConfiguration(abstract: "Allow a host, `*.domain` or `*`.")
        @OptionGroup var global: GlobalOptions
        @Argument(help: "example.com, *.example.com (subdomains and the apex) or *.") var pattern: String
        @Flag(help: "Decrypt and log HTTP details for matching hosts (needs `svctl proxy inspection on`).") var inspect = false

        func run() async throws {
            try await NetProxyCommand.setRule(global, pattern: pattern, action: .allow, inspect: inspect)
        }
    }

    struct Deny: AsyncParsableCommand {
        static let configuration = CommandConfiguration(abstract: "Deny a host, `*.domain` or `*`.")
        @OptionGroup var global: GlobalOptions
        @Argument(help: "example.com, *.example.com or *.") var pattern: String

        func run() async throws {
            try await NetProxyCommand.setRule(global, pattern: pattern, action: .deny, inspect: false)
        }
    }

    struct Ask: AsyncParsableCommand {
        static let configuration = CommandConfiguration(abstract: "Ask before connecting to a host, `*.domain` or `*`.")
        @OptionGroup var global: GlobalOptions
        @Argument(help: "example.com, *.example.com or *.") var pattern: String

        func run() async throws {
            try await NetProxyCommand.setRule(global, pattern: pattern, action: .ask, inspect: nil)
        }
    }

    struct Remove: AsyncParsableCommand {
        static let configuration = CommandConfiguration(abstract: "Remove a rule by id prefix or pattern.")
        @OptionGroup var global: GlobalOptions
        @Argument(help: "The start of the rule id (see `svctl proxy rules`) or its pattern.") var selector: String

        func run() async throws {
            let (rule, reloaded) = try await NetCLI.edit(global) { try $0.network.removeDomainRule(selector: selector) }
            if global.json { return try Output.json(rule) }
            Output.line("removed \(rule.action.rawValue) \(rule.pattern) [\(NetCLI.shortID(rule.id))]; \(NetCLI.reloadNote(reloaded))")
        }
    }

    struct Default: AsyncParsableCommand {
        static let configuration = CommandConfiguration(abstract: "Set the action for hosts no rule matches.")
        @OptionGroup var global: GlobalOptions
        @Argument(help: "allow, deny or ask.") var action: String

        func validate() throws {
            _ = try NetCLI.parseAction(action)
        }

        func run() async throws {
            let action = try NetCLI.parseAction(self.action)
            let (_, reloaded) = try await NetCLI.edit(global) { $0.network.defaultAction = action }
            if global.json { return try Output.json(["defaultAction": action.rawValue]) }
            Output.line("default action: \(action.rawValue); \(NetCLI.reloadNote(reloaded))")
        }
    }

    struct Inspection: AsyncParsableCommand {
        static let configuration = CommandConfiguration(
            abstract: "Turn TLS inspection on or off.",
            discussion: "`on` creates the CA when needed and publishes it with a CA bundle into the shared workspace. Only hosts whose allow rule has --inspect are decrypted."
        )
        @OptionGroup var global: GlobalOptions
        @Argument(help: "on or off.") var state: String

        func validate() throws {
            guard ["on", "off"].contains(state.lowercased()) else { throw ValidationError("expected on or off, not '\(state)'") }
        }

        func run() async throws {
            let enable = state.lowercased() == "on"
            var notes: [String] = []
            if enable {
                let (ca, created) = try CAStore(paths: global.paths).loadOrCreate(hostUser: global.environment.hostUser)
                if created { notes.append("created CA \(try ca.fingerprint)") }
                let shared = try NetCLI.requireSharedWorkspace(global)
                let published = try await CAPublisher(paths: global.paths, runner: global.runner, shared: shared).publish(ca)
                notes.append("published \(published.certificatePath) and \(published.bundlePath)")
            }
            let (config, reloaded) = try await NetCLI.edit(global) { config -> AppConfig in
                config.network.inspection.enabled = enable
                return config
            }
            if let shared = try? NetCLI.requireSharedWorkspace(global) {
                let change = try SandboxEnvironmentBlock.apply(policy: config.network, paths: global.paths, shared: shared)
                if change != .unchanged { notes.append("sandbox .zshenv block \(change.rawValue)") }
            }
            if global.json { return try Output.json(["inspection": enable ? "on" : "off"]) }
            Output.line("inspection \(enable ? "on" : "off"); \(NetCLI.reloadNote(reloaded))")
            for note in notes { Output.line("  \(note)") }
        }
    }

    struct Env: AsyncParsableCommand {
        static let configuration = CommandConfiguration(
            abstract: "Manage the proxy and CA variables in the sandbox's .zshenv.",
            subcommands: [Apply.self, Remove.self]
        )

        struct Apply: AsyncParsableCommand {
            static let configuration = CommandConfiguration(abstract: "Write the block for the current config (removes it when the firewall is off).")
            @OptionGroup var global: GlobalOptions

            func run() async throws {
                let shared = try NetCLI.requireSharedWorkspace(global)
                let policy = try global.configStore.load().network
                let change = try SandboxEnvironmentBlock.apply(policy: policy, paths: global.paths, shared: shared)
                if global.json { return try Output.json(["change": change.rawValue, "path": global.paths.sharedZshenv]) }
                Output.line("\(global.paths.sharedZshenv): block \(change.rawValue)")
                for variable in SandboxEnvironmentBlock.variables(policy: policy, paths: global.paths) {
                    Output.line("  \(variable.name)=\(variable.value)")
                }
            }
        }

        struct Remove: AsyncParsableCommand {
            static let configuration = CommandConfiguration(abstract: "Remove the block (netd writes it again on its next reload unless the firewall is off).")
            @OptionGroup var global: GlobalOptions

            func run() async throws {
                let shared = try NetCLI.requireSharedWorkspace(global)
                var policy = try global.configStore.load().network
                policy.mode = .off
                let change = try SandboxEnvironmentBlock.apply(policy: policy, paths: global.paths, shared: shared)
                if global.json { return try Output.json(["change": change.rawValue, "path": global.paths.sharedZshenv]) }
                Output.line("\(global.paths.sharedZshenv): block \(change.rawValue)")
            }
        }
    }
}
