import ArgumentParser
import Foundation
import SandvaultCore
import SandvaultWorkflow

struct MigrateCommand: AsyncParsableCommand {
    static let configuration = CommandConfiguration(
        commandName: "migrate",
        abstract: "Copy Claude, git and zsh configuration into $SHARED_WORKSPACE/user without credentials.",
        discussion: """
        Items: all, claude-settings, claude-memory, claude-commands, claude-agents, claude-skills, git-identity, zshrc, \
        zprofile, zshenv. Credential files, symlinks, files over 1 MB and anything that looks like a token are blocked \
        with a reason. sv copies the result into the sandbox home on its next run.
        """,
        subcommands: [Plan.self, Apply.self]
    )

    static func service(_ global: GlobalOptions) -> ConfigMigration {
        ConfigMigration(environment: global.environment, runner: global.runner)
    }

    static func show(_ plan: MigrationPlan) {
        Output.table(["ITEM", "STATUS", "BYTES", "DESTINATION", "SOURCE / REASON"], plan.entries.map {
            [
                WorkflowCLI.migrationName($0.item), $0.blockedReason == nil ? ($0.overwrites ? "replace" : "copy") : "BLOCKED",
                String($0.bytes), "user/\($0.destination)", $0.blockedReason ?? $0.source,
            ]
        })
    }

    struct Plan: AsyncParsableCommand {
        static let configuration = CommandConfiguration(abstract: "Show what would be copied and what is blocked.")
        @OptionGroup var global: GlobalOptions
        @Argument(help: "Items (see svctl migrate --help).") var items: [String]

        func run() async throws {
            let plan = try await MigrateCommand.service(global).plan(try WorkflowCLI.migrationItems(items))
            if global.json { return try Output.json(plan) }
            MigrateCommand.show(plan)
        }
    }

    struct Apply: AsyncParsableCommand {
        static let configuration = CommandConfiguration(abstract: "Copy the copyable entries (each is checked again before it is written).")
        @OptionGroup var global: GlobalOptions
        @Argument(help: "Items (see svctl migrate --help).") var items: [String]
        @Flag(name: .long, help: "Do not ask for confirmation.") var yes = false

        func run() async throws {
            let service = MigrateCommand.service(global)
            try service.layout.requireWorkspace()
            let plan = try await service.plan(try WorkflowCLI.migrationItems(items))
            if !global.json { MigrateCommand.show(plan) }
            guard !plan.copyable.isEmpty else {
                if global.json { try Output.json([MigrationEntry]()) } else { Output.line("nothing to copy") }
                return
            }
            guard try EnforceCLI.confirm("Copy \(plan.copyable.count) file(s) into \(global.environment.sharedUserDir)?", yes: yes, json: global.json) else {
                throw ExitCode.failure
            }
            let written = try await service.apply(plan)
            if global.json { return try Output.json(written) }
            Output.line("copied \(written.count) file(s); sv copies them into the sandbox home on its next run")
        }
    }
}

struct KeysCommand: AsyncParsableCommand {
    static let configuration = CommandConfiguration(
        commandName: "keys",
        abstract: "Public keys that may log in to the sandbox user (sv's authorized_keys.d).",
        discussion: AuthorizedKeyStore.appliedNote + ".",
        subcommands: [List.self, Add.self, Remove.self]
    )

    static func service(_ global: GlobalOptions) -> AuthorizedKeyStore {
        AuthorizedKeyStore(environment: global.environment, runner: global.runner)
    }

    struct List: AsyncParsableCommand {
        static let configuration = CommandConfiguration(abstract: "List the keys with type, fingerprint and comment.")
        @OptionGroup var global: GlobalOptions

        func run() async throws {
            let keys = try await KeysCommand.service(global).keys()
            if global.json { return try Output.json(keys) }
            guard !keys.isEmpty else { return Output.line("no keys in \(global.environment.authorizedKeysDir)") }
            Output.table(["NAME", "TYPE", "FINGERPRINT", "COMMENT"], keys.map { [$0.name, $0.type, $0.fingerprint, $0.comment ?? ""] })
        }
    }

    struct Add: AsyncParsableCommand {
        static let configuration = CommandConfiguration(abstract: "Add one public key (a .pub file, or - for stdin).")
        @OptionGroup var global: GlobalOptions
        @Argument(help: "File name in authorized_keys.d ([A-Za-z0-9._-], at most 64).") var name: String
        @Argument(help: "Public key file, or - for stdin.") var file: String

        func run() async throws {
            let key = try await KeysCommand.service(global).add(name: name, publicKey: try WorkflowCLI.readInput(file, limit: 64 * 1024))
            if global.json { return try Output.json(key) }
            Output.line("added \(key.name): \(key.type) \(key.fingerprint) \(key.comment ?? "")")
            Output.line(AuthorizedKeyStore.appliedNote)
        }
    }

    struct Remove: AsyncParsableCommand {
        static let configuration = CommandConfiguration(abstract: "Remove a key; sv revokes it on its next run.")
        @OptionGroup var global: GlobalOptions
        @Argument(help: "Key name.") var name: String

        func run() async throws {
            try await KeysCommand.service(global).remove(name: name)
            if global.json { return try Output.json(["removed": name]) }
            Output.line("removed \(name); \(AuthorizedKeyStore.appliedNote)")
        }
    }
}

struct DefaultsCommand: AsyncParsableCommand {
    static let configuration = CommandConfiguration(
        commandName: "defaults",
        abstract: "Default sv options: SANDVAULT_ARGS in a managed block of your ~/.zshenv.",
        subcommands: [Show.self, Assign.self, Clear.self]
    )

    static func show(_ state: SandvaultDefaults.State) {
        Output.line("\(state.file): " + (state.arguments.map { $0.isEmpty ? "empty block" : "SANDVAULT_ARGS=\($0.joined(separator: " "))" } ?? "no managed block"))
        if state.assignedOutsideBlock { Output.line("note: SANDVAULT_ARGS is also set outside the block; the later assignment wins") }
        if state.arguments != nil { Output.line("new shells pick it up (or: source ~/.zshenv)") }
    }

    struct Show: AsyncParsableCommand {
        static let configuration = CommandConfiguration(abstract: "Show the managed SANDVAULT_ARGS.")
        @OptionGroup var global: GlobalOptions

        func run() async throws {
            let state = try SandvaultDefaults(environment: global.environment).read()
            if global.json { return try Output.json(state) }
            DefaultsCommand.show(state)
        }
    }

    struct Assign: AsyncParsableCommand {
        static let configuration = CommandConfiguration(commandName: "set", abstract: "Set the default sv options: svctl defaults set -- --ssh --browser")
        @OptionGroup var global: GlobalOptions
        @Argument(help: "sv options after --.") var options: [String] = []

        func run() async throws {
            let state = try SandvaultDefaults(environment: global.environment).set(options)
            if global.json { return try Output.json(state) }
            DefaultsCommand.show(state)
        }
    }

    struct Clear: AsyncParsableCommand {
        static let configuration = CommandConfiguration(abstract: "Remove the managed block.")
        @OptionGroup var global: GlobalOptions

        func run() async throws {
            let defaults = SandvaultDefaults(environment: global.environment)
            let removed = try defaults.clear()
            if global.json { return try Output.json(try defaults.read()) }
            Output.line(removed ? "removed the managed block from \(defaults.file)" : "no managed block in \(defaults.file)")
        }
    }
}
