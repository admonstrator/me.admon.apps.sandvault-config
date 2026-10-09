import ArgumentParser
import Foundation
import SandvaultCore
import SandvaultWorkflow

struct HandoffCommand: AsyncParsableCommand {
    static let configuration = CommandConfiguration(
        commandName: "handoff",
        abstract: "Hand a repository to an agent: readiness check, briefing, sv-clone in a new terminal window.",
        discussion: """
        Prints the readiness report first and stops on a blocker. With a task or --include-uncommitted the briefing \
        goes to $SHARED_WORKSPACE/tmp/handoff-<repo>.md and the agent is told to read it. Agent, terminal and sv \
        options default to the hand-off settings in config.json. Pass sv options as --sv-option=--browser.
        """
    )

    @OptionGroup var global: GlobalOptions
    @Argument(help: "Local repository path or remote URL.") var source: String
    @Option(help: "claude, codex, opencode, gemini, pi, muse or shell.") var agent: String?
    @Option(help: "The task for the agent.") var task: String?
    @Option(name: .customLong("task-file"), help: "Read the task from a file (- for stdin).") var taskFile: String?
    @Flag(name: .customLong("include-uncommitted"), help: "Carry uncommitted changes of tracked files as a patch.") var includeUncommitted = false
    @Option(help: "terminal, iterm2 or ghostty.") var terminal: String?
    @Option(name: .customLong("deploy-key"), help: "GitHub deploy key for the clone: none, ro or rw (sv-clone -k / -w).")
    var deployKey: WorkflowCLI.DeployKeyArgument = .none
    @Option(name: .customLong("sv-option"), parsing: .unconditionalSingleValue, help: "An sv option such as --browser (repeatable).")
    var svOptions: [String] = []
    @Flag(name: .customLong("check-only"), help: "Only print the readiness report.") var checkOnly = false
    @Flag(name: .customLong("print"), help: "Write the briefing and print the command instead of opening a terminal.") var printOnly = false

    struct Report: Encodable {
        var readiness: ReadinessReport
        var result: HandoffResult?
    }

    func validate() throws {
        if task != nil && taskFile != nil { throw ValidationError("use --task or --task-file, not both") }
        if checkOnly && printOnly { throw ValidationError("use --check-only or --print, not both") }
    }

    func run() async throws {
        let settings = try global.configStore.load().handoff
        let service = RepositoryHandoff(environment: global.environment, runner: global.runner, configStore: global.configStore)
        let report = try await service.readiness(of: source)
        if checkOnly || !report.canProceed {
            if global.json { try Output.json(Report(readiness: report)) } else { show(report) }
            if !report.canProceed { throw ExitCode.failure }
            return
        }
        if !printOnly {
            try WorkflowCLI.requireMacOS("opening a terminal needs macOS; use --print for the command or --check-only for the report")
        }
        let request = HandoffRequest(
            source: source,
            agent: try agent.map { try WorkflowCLI.parse($0, as: "agent") } ?? settings.defaultAgent,
            task: try taskFile.map { try WorkflowCLI.readInput($0) } ?? task,
            includeUncommitted: includeUncommitted,
            terminal: try terminal.map { try WorkflowCLI.parse($0, as: "terminal") } ?? settings.terminal,
            svOptions: svOptions.isEmpty ? settings.svOptions : svOptions,
            deployKey: deployKey.mode
        )
        let result = try await service.handOff(request, launch: !printOnly)
        if global.json { return try Output.json(Report(readiness: report, result: result)) }
        show(report)
        if let briefing = result.briefingPath { Output.line("briefing: \(briefing)") }
        Output.line("command: \(ShellQuoting.join(result.command))")
        if result.launched {
            Output.line("started in \(request.terminal.rawValue); the clone will be \(result.record.sandboxPath)")
        } else {
            Output.line("not started: run the command above in a terminal")
        }
        if result.briefingPath != nil, HandoffCommandLine.promptArguments(request.agent, "") == nil {
            Output.line("note: \(request.agent.rawValue) takes no first prompt; point it at the briefing yourself")
        }
    }

    private func show(_ report: ReadinessReport) {
        Output.line("\(report.repositoryName): \(report.repositoryPath)")
        for finding in report.findings {
            Output.line("  \(WorkflowCLI.severity(finding.severity).padding(toLength: 5, withPad: " ", startingAt: 0)) \(finding.kind.rawValue): \(finding.message)")
        }
        let warnings = report.findings.filter { $0.severity == .warning }.count
        if !report.canProceed {
            Output.line("blocked: fix the blockers above first")
        } else {
            Output.line(warnings == 0 ? "ready" : "ready with \(warnings) warning\(warnings == 1 ? "" : "s")")
        }
    }
}
