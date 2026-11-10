import ArgumentParser
import Foundation
import SandvaultCore
import SandvaultWorkflow

/// Custom programs (D54): `svctl programs suggest|add|list|remove`.
struct ProgramsCommand: AsyncParsableCommand {
    static let configuration = CommandConfiguration(
        commandName: "programs",
        abstract: "Bring a host program (e.g. claude-lm) into the sandbox with its helpers, files and loopback ports.",
        discussion: """
        add grants the program and its helpers like svctl tools grant, copies the files (paths relative to your home) \
        into $SHARED_WORKSPACE/user, and allows TCP to 127.0.0.1 on the ports. A file that looks like a credential is \
        copied only with --allow-secret for that file. Without options add uses svctl programs suggest. Run \
        svctl firewall apply afterwards for the ports. Start it with: svctl handoff <repo> --program <name>, or sv shell -- <name>.
        """,
        subcommands: [Suggest.self, Add.self, List.self, Remove.self]
    )

    static func service(_ global: GlobalOptions) throws -> ProgramMigration {
        try WorkflowCLI.requireMacOS("custom programs run zsh, otool and sudo as the sandbox user on the Mac")
        return ProgramMigration(environment: global.environment, runner: global.runner, configStore: global.configStore)
    }

    static func show(_ program: CustomProgram) {
        Output.line("\(program.name)" + (program.migratedAt.map { " (brought in \(WorkflowCLI.date($0)))" } ?? ""))
        Output.line("  helpers: " + (program.dependencies.isEmpty ? "-" : program.dependencies.joined(separator: " ")))
        Output.line("  ports:   " + (program.hostPorts.isEmpty ? "-" : program.hostPorts.map(String.init).joined(separator: " ")))
        for file in program.files {
            Output.line("  file:    \(file)" + (program.allowedSecrets.contains(file) ? " (credential allowed)" : ""))
        }
        Output.line("  prompt:  " + (program.takesPrompt ? "a hand-off task is its first argument" : "no first prompt"))
    }

    struct Suggest: AsyncParsableCommand {
        static let configuration = CommandConfiguration(abstract: "What the program probably needs; changes nothing.")
        @OptionGroup var global: GlobalOptions
        @Argument(help: "Command name on your PATH.") var name: String

        func run() async throws {
            let program = try await ProgramsCommand.service(global).suggest(name)
            if global.json { return try Output.json(program) }
            ProgramsCommand.show(program)
        }
    }

    struct Add: AsyncParsableCommand {
        static let configuration = CommandConfiguration(abstract: "Bring the program in (again); every step is reported.")
        @OptionGroup var global: GlobalOptions
        @Argument(help: "Command name on your PATH.") var name: String
        @Option(name: .customLong("helper"), help: "A command it calls (repeatable).") var helpers: [String] = []
        @Option(name: .customLong("port"), help: "A TCP port on 127.0.0.1 it talks to (repeatable).") var ports: [UInt16] = []
        @Option(name: .customLong("file"), help: "A file relative to your home it reads (repeatable).") var files: [String] = []
        @Option(name: .customLong("allow-secret"), help: "Copy this file although it looks like a credential (repeatable, also adds it as --file).")
        var secrets: [String] = []
        @Flag(name: .customLong("prompt"), inversion: .prefixedNo, help: "Pass a hand-off task as its first argument.") var prompt: Bool?

        func run() async throws {
            let service = try ProgramsCommand.service(global)
            var program = try await service.suggest(name)
            if !helpers.isEmpty { program.dependencies = helpers }
            if !ports.isEmpty { program.hostPorts = ports }
            if !files.isEmpty { program.files = files }
            program.files += secrets.filter { !program.files.contains($0) }
            program.allowedSecrets = Array(Set(program.allowedSecrets + secrets)).sorted()
            if let prompt { program.takesPrompt = prompt }
            let report = try await service.migrate(program)
            if global.json { return try Output.json(report) }
            ProgramsCommand.show(report.program)
            for step in report.steps {
                Output.line("  \(step.done ? "ok  " : "FAIL") \(step.kind.rawValue) \(step.subject): \(step.detail)")
            }
            if report.firewallChanged { Output.line("run svctl firewall apply to open the new ports") }
            if !report.succeeded { throw ExitCode.failure }
        }
    }

    struct List: AsyncParsableCommand {
        static let configuration = CommandConfiguration(abstract: "Programs brought in so far.")
        @OptionGroup var global: GlobalOptions

        func run() async throws {
            let programs = try global.configStore.load().programs
            if global.json { return try Output.json(programs) }
            guard !programs.isEmpty else { return Output.line("no custom programs") }
            programs.forEach(ProgramsCommand.show)
        }
    }

    struct Remove: AsyncParsableCommand {
        static let configuration = CommandConfiguration(
            abstract: "Remove its files, port exceptions and own copy from the shared workspace and config (helpers stay)."
        )
        @OptionGroup var global: GlobalOptions
        @Argument(help: "Command name.") var name: String

        func run() async throws {
            try await ProgramsCommand.service(global).remove(name)
            Output.line("removed \(name); copies already in the sandbox home stay until you delete them there")
            Output.line("run svctl firewall apply to close its ports")
        }
    }
}
