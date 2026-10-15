import ArgumentParser
import Foundation
import SandvaultCore
import SandvaultWorkflow

/// Docker Sandboxes VMs (D47). Hand-offs go through `svctl handoff --target docker`.
struct SbxCommand: AsyncParsableCommand {
    static let configuration = CommandConfiguration(
        commandName: "sbx",
        abstract: "Docker Sandboxes Linux VMs: list, open, stop and delete.",
        subcommands: [List.self, Open.self, Stop.self, Remove.self],
        defaultSubcommand: List.self
    )

    static func service(_ global: GlobalOptions) -> DockerSandboxes {
        DockerSandboxes(runner: global.runner)
    }

    struct List: AsyncParsableCommand {
        static let configuration = CommandConfiguration(commandName: "list", abstract: "The VMs sbx ls reports, with the repository each came from.")
        @OptionGroup var global: GlobalOptions

        func run() async throws {
            let state = await SbxCommand.service(global).state()
            if global.json { return try Output.json(state) }
            guard let executable = state.executable else {
                return Output.line("Docker Sandboxes are not installed (brew install docker/tap/sbx, then sbx login)")
            }
            Output.line("sbx: \(executable)")
            if state.sshAgentForwarding == true {
                Output.line("WARN your SSH agent reaches every VM; sbx settings set ssh.agentForwardingEnabled false turns it off")
            }
            if let problem = state.problem { return Output.line(problem) }
            guard !state.sandboxes.isEmpty else { return Output.line("no sandboxes") }
            let repos = try global.configStore.load().repos
            Output.table(["NAME", "STATUS", "AGENT", "FOLDER", "HANDED OFF"], state.sandboxes.map { sandbox in
                [
                    sandbox.name, sandbox.status, sandbox.agent ?? "-", sandbox.workspaces.first ?? "-",
                    repos.last { $0.dockerSandbox == sandbox.name }.map { WorkflowCLI.date($0.createdAt) } ?? "-",
                ]
            })
        }
    }

    struct Open: AsyncParsableCommand {
        static let configuration = CommandConfiguration(abstract: "Attach to a VM in a new terminal window (sbx run --name).")
        @OptionGroup var global: GlobalOptions
        @Argument(help: "Sandbox name.") var name: String
        @Option(help: "terminal, iterm2 or ghostty.") var terminal: String?

        func run() async throws {
            let chosen: TerminalApp = try terminal.map { try WorkflowCLI.parse($0, as: "terminal") } ?? global.configStore.load().handoff.terminal
            let launch = try await SbxCommand.service(global).open(name, terminal: chosen)
            Output.line(launch.launched ? "opened \(name) in \(chosen.rawValue)" : "run in a terminal: \(launch.command)")
        }
    }

    struct Stop: AsyncParsableCommand {
        static let configuration = CommandConfiguration(abstract: "Stop a VM; its files and packages stay.")
        @OptionGroup var global: GlobalOptions
        @Argument(help: "Sandbox name.") var name: String

        func run() async throws {
            try await SbxCommand.service(global).stop(name)
            Output.line("stopped \(name)")
        }
    }

    struct Remove: AsyncParsableCommand {
        static let configuration = CommandConfiguration(
            commandName: "rm", abstract: "Delete a VM and forget its hand-off. Fetch its commits first (svctl repos fetch <name>)."
        )
        @OptionGroup var global: GlobalOptions
        @Argument(help: "Sandbox name.") var name: String

        func run() async throws {
            try await SbxCommand.service(global).remove(name)
            var config = try global.configStore.load()
            config.repos.removeAll { $0.dockerSandbox == name }
            try global.configStore.save(config)
            Output.line("deleted \(name)")
        }
    }
}
