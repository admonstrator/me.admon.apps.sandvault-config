import ArgumentParser
import Foundation
import SandvaultCore
import SandvaultNet

struct NetdCommand: AsyncParsableCommand {
    static let configuration = CommandConfiguration(
        commandName: "netd",
        abstract: "The sandvault-netd LaunchAgent (macOS).",
        subcommands: [Install.self, Uninstall.self, Status.self, Restart.self]
    )

    static func agent(_ global: GlobalOptions) -> NetdLaunchAgent {
        NetdLaunchAgent(paths: global.paths, runner: global.runner)
    }

    struct Install: AsyncParsableCommand {
        static let configuration = CommandConfiguration(abstract: "Install and start the LaunchAgent (RunAtLoad, KeepAlive).")
        @OptionGroup var global: GlobalOptions
        @Option(help: "Path of sandvault-netd (default: next to svctl).") var executable: String?

        func run() async throws {
            let agent = NetdCommand.agent(global)
            let path = executable ?? Self.siblingExecutable()
            try await agent.install(executable: path)
            if global.json { return try Output.json(["plist": agent.plistPath, "executable": path]) }
            Output.line("installed \(agent.plistPath)")
            Output.line("started \(path) run (log: \(agent.logPath))")
        }

        static func siblingExecutable() -> String {
            let me = URL(fileURLWithPath: CommandLine.arguments[0]).resolvingSymlinksInPath()
            return me.deletingLastPathComponent().appendingPathComponent("sandvault-netd").path
        }
    }

    struct Uninstall: AsyncParsableCommand {
        static let configuration = CommandConfiguration(abstract: "Stop netd and remove the LaunchAgent.")
        @OptionGroup var global: GlobalOptions

        func run() async throws {
            let agent = NetdCommand.agent(global)
            try await agent.uninstall()
            if global.json { return try Output.json(["removed": agent.plistPath]) }
            Output.line("stopped netd and removed \(agent.plistPath)")
        }
    }

    struct Status: AsyncParsableCommand {
        static let configuration = CommandConfiguration(abstract: "LaunchAgent state and whether netd answers on its control socket.")
        @OptionGroup var global: GlobalOptions

        struct Report: Codable {
            var agent: NetdLaunchAgent.Status
            var reachable: Bool
            var socket: String
        }

        func run() async throws {
            let status = try await NetdCommand.agent(global).status()
            let socket = NetCLI.socketPath(global)
            let report = Report(agent: status, reachable: await ControlClient.isReachable(socketPath: socket), socket: socket)
            if global.json { return try Output.json(report) }
            Output.line("LaunchAgent: \(status.installed ? status.plistPath : "not installed")")
            Output.line("launchd:     \(status.loaded ? "loaded, \(status.state ?? "unknown")" : "not loaded")\(status.pid.map { ", pid \($0)" } ?? "")")
            if let code = status.lastExitCode { Output.line("last exit:   \(code)") }
            Output.line("control:     \(report.reachable ? "answering" : "not reachable") (\(socket))")
        }
    }

    struct Restart: AsyncParsableCommand {
        static let configuration = CommandConfiguration(abstract: "Restart netd through launchd.")
        @OptionGroup var global: GlobalOptions

        func run() async throws {
            try await NetdCommand.agent(global).restart()
            if global.json { return try Output.json(["restarted": AppPaths.netdLabel]) }
            Output.line("restarted \(AppPaths.netdLabel)")
        }
    }
}
