import ArgumentParser
import Foundation
import SandvaultCore
import SandvaultWorkflow

struct ReposCommand: AsyncParsableCommand {
    static let configuration = CommandConfiguration(
        commandName: "repos",
        abstract: "Clones in the shared workspace and the way back to the host repository.",
        subcommands: [List.self, Fetch.self],
        defaultSubcommand: List.self
    )

    static func service(_ global: GlobalOptions) -> SandboxRepositories {
        SandboxRepositories(environment: global.environment, runner: global.runner, configStore: global.configStore)
    }

    struct List: AsyncParsableCommand {
        static let configuration = CommandConfiguration(abstract: "Branch, head, dirty state, ahead/behind and unfetched commits per clone.")
        @OptionGroup var global: GlobalOptions

        func run() async throws {
            let repos = try await ReposCommand.service(global).repositories()
            if global.json { return try Output.json(repos) }
            guard !repos.isEmpty else { return Output.line("no clones in \(global.environment.sharedReposDir)") }
            Output.table(["NAME", "BRANCH", "HEAD", "LAST COMMIT", "DIRTY", "AHEAD/BEHIND", "UNFETCHED", "DEPLOY KEY", "HOST"], repos.map {
                [
                    $0.name, $0.branch ?? "-", $0.headCommit.map { String($0.prefix(8)) } ?? "-", WorkflowCLI.date($0.lastCommitDate),
                    $0.dirty ? "yes" : "", "\(WorkflowCLI.count($0.aheadOfOrigin))/\(WorkflowCLI.count($0.behindOrigin))",
                    WorkflowCLI.count($0.unfetchedCommits), $0.deployKey == nil ? "" : "yes", $0.record?.hostPath ?? "-",
                ]
            })
        }
    }

    struct Fetch: AsyncParsableCommand {
        static let configuration = CommandConfiguration(abstract: "Run git fetch sandvault in the host repository of a hand-off.")
        @OptionGroup var global: GlobalOptions
        @Argument(help: "Clone name (see svctl repos).") var name: String

        func run() async throws {
            guard let record = try global.configStore.load().repos.last(where: { $0.repoName == name }) else {
                throw SandvaultError.invalidInput("no hand-off of \(name) recorded; run git fetch sandvault in the host repository yourself")
            }
            let status = try await ReposCommand.service(global).fetchBack(record)
            if global.json { return try Output.json(status) }
            Output.line("fetched \(name) into \(record.hostPath) (remote sandvault)")
            if let branch = status.branch {
                Output.line("branch \(branch): \(WorkflowCLI.count(status.unfetchedCommits)) commits not fetched; merge with git merge sandvault/\(branch)")
            }
        }
    }
}

struct ToolsCommand: AsyncParsableCommand {
    static let configuration = CommandConfiguration(
        commandName: "tools",
        abstract: "Check whether a host command works in the sandbox and make it available.",
        subcommands: [Check.self, Grant.self, List.self]
    )

    static func service(_ global: GlobalOptions) throws -> ToolAccess {
        try WorkflowCLI.requireMacOS("checking tools runs zsh, otool and sudo as the sandbox user on the Mac")
        return ToolAccess(environment: global.environment, runner: global.runner, configStore: global.configStore)
    }

    static func show(_ status: ToolStatus) {
        Output.line("\(status.name): " + (status.reachableInSandbox ? "available in the sandbox" : "not available in the sandbox"))
        Output.line("  host: \(status.hostPath ?? "not found") (\(status.location.rawValue))")
        if let kind = status.kind { Output.line("  kind: \(kind)") }
        if let formula = status.formula { Output.line("  formula: \(formula)") }
        Output.line("  \(status.reason)")
        if !status.reachableInSandbox {
            Output.line(status.options.isEmpty ? "  no automatic way; install it inside the sandbox" : "  options: " + status.options.map(\.rawValue).joined(separator: ", "))
        }
    }

    struct Check: AsyncParsableCommand {
        static let configuration = CommandConfiguration(abstract: "Where the host has the command and whether the sandbox can run it.")
        @OptionGroup var global: GlobalOptions
        @Argument(help: "Command name.") var name: String

        func run() async throws {
            let status = try await ToolsCommand.service(global).status(of: name)
            if global.json { return try Output.json(status) }
            ToolsCommand.show(status)
        }
    }

    struct Grant: AsyncParsableCommand {
        static let configuration = CommandConfiguration(abstract: "Install with brew or copy into $SHARED_WORKSPACE/user/bin, then check again.")
        @OptionGroup var global: GlobalOptions
        @Argument(help: "Command name.") var name: String
        @Option(help: "brew or copy (default: the best option of svctl tools check).") var method: String?

        func run() async throws {
            let service = try ToolsCommand.service(global)
            let chosen: ToolGrantMethod
            if let method {
                chosen = try WorkflowCLI.parse(method, as: "method")
            } else {
                let status = try await service.status(of: name)
                guard let best = status.options.first else {
                    if !global.json { ToolsCommand.show(status) }
                    throw SandvaultError.invalidInput("no way to grant \(name) automatically")
                }
                chosen = best
            }
            let grant = try await service.grant(name, method: chosen)
            if global.json { return try Output.json(grant) }
            Output.line("\(name) is available in the sandbox (\(grant.method.rawValue) from \(grant.source))")
        }
    }

    struct List: AsyncParsableCommand {
        static let configuration = CommandConfiguration(abstract: "Commands granted so far.")
        @OptionGroup var global: GlobalOptions

        func run() async throws {
            let tools = try global.configStore.load().tools
            if global.json { return try Output.json(tools) }
            guard !tools.isEmpty else { return Output.line("no grants") }
            Output.table(["NAME", "METHOD", "SOURCE", "GRANTED"], tools.map { [$0.name, $0.method.rawValue, $0.source, WorkflowCLI.date($0.grantedAt)] })
        }
    }
}
