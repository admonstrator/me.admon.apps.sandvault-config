import ArgumentParser
import Foundation
import SandvaultCore
import SandvaultEnforce

struct PanicCommand: AsyncParsableCommand {
    static let configuration = CommandConfiguration(
        commandName: "panic",
        abstract: "Block all network access of the sandbox user and terminate all its processes.",
        discussion: "Sets the firewall mode to blocked in config.json. To end it, choose a mode and apply (`svctl firewall mode open && svctl firewall apply`), or run `svctl firewall off`."
    )

    @OptionGroup var global: GlobalOptions
    @Flag(name: .long, help: "Do not ask for confirmation.") var yes = false

    func run() async throws {
        try EnforceCLI.requireMacOS("panic")
        let user = global.environment.sandvaultUser
        guard try EnforceCLI.confirm("Block the network of \(user) and kill all its processes?", yes: yes, json: global.json) else {
            throw ExitCode.failure
        }
        // Persist first, so netd's next apply keeps the block instead of undoing it.
        var config = try global.configStore.load()
        config.network.mode = .blocked
        try global.configStore.save(config)
        let result = try await EnforceCLI.applier(global).panic(AppliedState(config: config))
        _ = await NetCLI.reload(global)
        try EnforceCLI.report(result, json: global.json)
    }
}

struct HelperCommand: AsyncParsableCommand {
    static let configuration = CommandConfiguration(
        commandName: "helper",
        abstract: "Install, remove or inspect the privileged helper.",
        subcommands: [Install.self, Uninstall.self, Status.self]
    )
}

extension HelperCommand {
    struct Install: AsyncParsableCommand {
        static let configuration = CommandConfiguration(abstract: "Install the helper, its sudoers rule and the boot LaunchDaemon (asks for your password).")
        @OptionGroup var global: GlobalOptions
        @Option(name: .long, help: "svctl-helper binary to install (default: next to svctl).") var source: String?

        func run() async throws {
            try EnforceCLI.requireMacOS("helper install")
            let binary = try source ?? HelperCommand.bundledHelper()
            if !global.json { Output.line("Installing \(AppPaths.helperPath) with sudo; enter your administrator password if asked.") }
            let result = try await HelperCommand.sudo(global, binary, ["install", "--user", global.environment.hostUser, "--source", binary])
            try EnforceCLI.report(result, json: global.json)
        }
    }

    struct Uninstall: AsyncParsableCommand {
        static let configuration = CommandConfiguration(abstract: "Firewall off, profile block removed, helper files deleted (asks for your password).")
        @OptionGroup var global: GlobalOptions

        func run() async throws {
            try EnforceCLI.requireMacOS("helper uninstall")
            let binary = FileManager.default.isExecutableFile(atPath: AppPaths.helperPath) ? AppPaths.helperPath : try HelperCommand.bundledHelper()
            let result = try await HelperCommand.sudo(global, binary, ["uninstall", "--user", global.environment.hostUser])
            try EnforceCLI.report(result, json: global.json)
        }
    }

    struct Status: AsyncParsableCommand {
        static let configuration = CommandConfiguration(abstract: "Installed, sudoers rule, integrity hashes.")
        @OptionGroup var global: GlobalOptions

        struct Report: Encodable {
            var installed: Bool
            var status: HelperStatus?
            var error: String?
        }

        func run() async throws {
            try EnforceCLI.requireMacOS("helper status")
            var report = Report(installed: FileManager.default.isExecutableFile(atPath: AppPaths.helperPath))
            if report.installed {
                do { report.status = try await EnforceCLI.applier(global).status() } catch { report.error = "\(error)" }
            }
            if global.json { return try Output.json(report) }
            guard report.installed else { return Output.line("not installed at \(AppPaths.helperPath); run svctl helper install") }
            guard let status = report.status else { return Output.line("installed; status failed: \(report.error ?? "")") }
            Output.line("installed at \(AppPaths.helperPath), \(status.summary)")
            let rows: [(String, String?, Bool)] = [
                ("helper", status.helperSHA256, status.helperChanged),
                ("sudoers rule", status.sudoersSHA256, status.sudoersChanged),
                ("sv sudoers", status.svSudoersSHA256, status.svSudoersChanged),
                ("profile block", status.profileBlockSHA256, status.profileBlockChanged || status.profileBlockMissing),
                ("sv profile part", status.svPartSHA256, status.svPartChanged),
                ("pf anchor", status.anchorSHA256, status.anchorChanged),
            ]
            Output.table(["ITEM", "SHA-256", "CHANGED"], rows.map { [$0.0, $0.1.map { String($0.prefix(16)) } ?? "missing", $0.2 ? "yes" : "no"] })
        }
    }

    /// `svctl-helper` in the same directory as the running svctl.
    static func bundledHelper() throws -> String {
        guard let svctl = Bundle.main.executableURL?.resolvingSymlinksInPath() else {
            throw SandvaultError.notInstalled("cannot locate the running svctl")
        }
        let helper = svctl.deletingLastPathComponent().appendingPathComponent("svctl-helper").path
        guard FileManager.default.isExecutableFile(atPath: helper) else {
            throw SandvaultError.notInstalled("svctl-helper next to svctl (\(helper)); pass --source")
        }
        return helper
    }

    /// Plain sudo: it prompts for the password on the terminal (/dev/tty), not through our pipes.
    static func sudo(_ global: GlobalOptions, _ binary: String, _ arguments: [String]) async throws -> HelperResult {
        let result = try await global.runner.run(CommandInvocation("/usr/bin/sudo", [binary] + arguments + ["--json"], timeout: 300))
        if let decoded = try? JSONCoding.decoder.decode(HelperResult.self, from: result.stdout) { return decoded }
        throw SandvaultError.commandFailed("sudo \(binary) \(arguments.first ?? "")", result.exitCode, result.stderrString)
    }
}
