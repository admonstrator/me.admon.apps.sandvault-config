import Foundation
import SandvaultCore

/// Readiness check and hand-off of a repository to an agent: `sv-clone` started in a terminal window (D26).
public struct RepositoryHandoff: HandoffService {
    public let layout: SharedLayout
    public let runner: CommandRunner
    public let configStore: ConfigStore
    /// Opening a terminal needs macOS; elsewhere `handOff` returns the command with `launched: false`.
    public let isMacOS: Bool
    /// The second target (D47).
    public let docker: DockerSandboxes

    public init(
        environment: SandvaultEnvironment, runner: CommandRunner, configStore: ConfigStore,
        shared: SharedFiles? = nil, isMacOS: Bool = WorkflowPlatform.isMacOS, docker: DockerSandboxes? = nil
    ) {
        layout = SharedLayout(environment: environment, shared: shared)
        self.runner = runner
        self.configStore = configStore
        self.isMacOS = isMacOS
        self.docker = docker ?? DockerSandboxes(runner: runner, isMacOS: isMacOS)
    }

    public func readiness(of source: String) async throws -> ReadinessReport {
        try await ReadinessCheck(layout: layout, runner: runner).run(source)
    }

    public func readiness(of source: String, target: HandoffTarget) async throws -> ReadinessReport {
        switch target {
        case .sandvault: try await readiness(of: source)
        case .dockerSandbox: try await dockerReadiness(of: source)
        }
    }

    public func handOff(_ request: HandoffRequest) async throws -> HandoffResult {
        try await handOff(request, launch: true)
    }

    /// `launch: false` writes the briefing, records the hand-off and returns the command without opening a terminal.
    public func handOff(_ request: HandoffRequest, launch: Bool) async throws -> HandoffResult {
        if request.target == .dockerSandbox { return try await handOffToDocker(request, launch: launch) }
        try SvOptions.validate(request.svOptions)
        let report = try await readiness(of: request.source)
        let blockers = report.findings.filter { $0.severity == .blocker }
        guard blockers.isEmpty else {
            throw SandvaultError.invalidInput("cannot hand off \(request.source): " + blockers.map(\.message).joined(separator: "; "))
        }
        let isLocal: Bool
        if case .local = RepositorySource.classify(request.source, home: layout.environment.hostHome) { isLocal = true } else { isLocal = false }
        if request.includeUncommitted && !isLocal {
            throw SandvaultError.invalidInput("uncommitted changes can only be carried from a local repository")
        }
        let name = report.repositoryName
        let clonePath = layout.reposDir + "/" + name
        let task = request.task?.trimmingCharacters(in: .whitespacesAndNewlines)

        var briefingPath: String?
        if (task?.isEmpty == false) || request.includeUncommitted {
            briefingPath = try await writeBriefing(report: report, request: request, task: task, isLocal: isLocal, clonePath: clonePath)
        }
        let command = HandoffCommandLine.arguments(
            source: report.repositoryPath, request: request,
            prompt: briefingPath.map { "Read \($0) and continue the task described there." }
        )
        let launched = launch && isMacOS
        if launched {
            _ = try await runner.checked(TerminalLaunch.invocation(request.terminal, command: ShellQuoting.join(command)))
        }
        let record = HandoffRecord(hostPath: report.repositoryPath, repoName: name, sandboxPath: clonePath, agent: request.agent)
        var config = try configStore.load()
        config.repos.removeAll { $0.dockerSandbox == nil && ($0.repoName == name || $0.sandboxPath == clonePath) }
        config.repos.append(record)
        try configStore.save(config)
        return HandoffResult(record: record, briefingPath: briefingPath, command: command, launched: launched)
    }

    // MARK: - Docker Sandboxes (D47)

    /// Where a URL is cloned on the host: `<cloneDirectory>/<repo>`.
    func cloneDestination(for name: String) throws -> String {
        let directory = try configStore.load().handoff.cloneDirectory.trimmingCharacters(in: .whitespaces)
        guard !directory.isEmpty, !Text.hasControlCharacters(directory) else { throw SandvaultError.invalidInput("the clone folder is not set") }
        var base = HostPath.absolute(directory, home: layout.environment.hostHome)
        while base.count > 1 && base.hasSuffix("/") { base.removeLast() }
        return base + "/" + name
    }

    /// sv's readiness without what only sv-clone needs (`origin`, the shared workspace clone). A URL is checked
    /// against its clone folder: missing means `git clone` first, an existing clone is checked like a local folder.
    func dockerReadiness(of source: String) async throws -> ReadinessReport {
        let missing = docker.executable == nil ? [ReadinessFinding(kind: .targetMissing, severity: .blocker,
            message: "Docker Sandboxes are not installed (brew install docker/tap/sbx, then sbx login)")] : []
        var report: ReadinessReport
        switch RepositorySource.classify(source, home: layout.environment.hostHome) {
        case .remote(let url):
            let name = RepositoryName.derive(from: url)
            guard RepositoryName.isValid(name) else { report = try await readiness(of: source); break }
            let destination = try cloneDestination(for: name)
            switch FileKind.of(destination) {
            case .missing:
                report = ReadinessReport(repositoryPath: destination, repositoryName: name, findings: [ReadinessFinding(
                    kind: .cloneFirst, severity: .info, message: "\(url) is cloned to \(destination) first, in the terminal with your git login"
                )])
            case .directory where FileKind.of(destination + "/.git") != .missing:
                report = try await readiness(of: destination)
                report.findings.insert(ReadinessFinding(kind: .cloneFirst, severity: .info,
                    message: "\(destination) already exists and is handed off as it is (no pull)"), at: 0)
            default:
                report = ReadinessReport(repositoryPath: destination, repositoryName: name, findings: [ReadinessFinding(
                    kind: .cloneFirst, severity: .blocker, message: "\(destination) exists but is not a git repository; choose another clone folder"
                )])
            }
        default:
            report = try await readiness(of: source)
        }
        report.findings = missing + report.findings.compactMap(Self.forDocker)
        return report
    }

    static func forDocker(_ finding: ReadinessFinding) -> ReadinessFinding? {
        switch finding.kind {
        case .noOriginRemote, .alreadyHandedOff:
            return nil
        case .uncommittedChanges:
            var adjusted = finding
            adjusted.message = finding.message.replacingOccurrences(of: " unless they are included", with: "; the Linux VM gets committed history only")
            return adjusted
        default:
            return finding
        }
    }

    func handOffToDocker(_ request: HandoffRequest, launch: Bool) async throws -> HandoffResult {
        guard request.agent.sbxAgent != nil else {
            throw SandvaultError.invalidInput("\(request.agent.rawValue) does not run in Docker Sandboxes (claude, codex, opencode, gemini or shell)")
        }
        if request.includeUncommitted {
            throw SandvaultError.invalidInput("Docker Sandboxes clone committed history only; commit first or leave out uncommitted changes")
        }
        let report = try await dockerReadiness(of: request.source)
        let blockers = report.findings.filter { $0.severity == .blocker }
        guard blockers.isEmpty, let sbx = docker.executable else {
            throw SandvaultError.invalidInput("cannot hand off \(request.source): " + blockers.map(\.message).joined(separator: "; "))
        }
        let folder = report.repositoryPath
        var prepare: [String]?
        if case .remote(let url) = RepositorySource.classify(request.source, home: layout.environment.hostHome), FileKind.of(folder) == .missing {
            prepare = ["git", "clone", "--", url, folder]
        }
        var config = try configStore.load()
        let taken = Set(await docker.state().sandboxes.map(\.name) + config.repos.compactMap(\.dockerSandbox))
        let name = DockerSandboxName.make(for: report.repositoryName, taken: taken)
        let task = request.task?.trimmingCharacters(in: .whitespacesAndNewlines)
        let command = try DockerSandboxes.runArguments(sbx: sbx, name: name, agent: request.agent, folder: folder, prompt: task)
        let result = HandoffResult(
            record: HandoffRecord(hostPath: folder, repoName: report.repositoryName, sandboxPath: "sbx:" + name, agent: request.agent, dockerSandbox: name),
            briefingPath: nil, command: command, prepare: prepare, launched: launch && isMacOS
        )
        if result.launched {
            _ = try await runner.checked(TerminalLaunch.invocation(request.terminal, command: result.shellLine))
        }
        config.repos.removeAll { $0.dockerSandbox == name }
        config.repos.append(result.record)
        try configStore.save(config)
        return result
    }

    /// Writes `tmp/handoff-<repo>.md` (and with uncommitted changes `tmp/handoff-<repo>.patch`) through `SharedFiles`.
    private func writeBriefing(report: ReadinessReport, request: HandoffRequest, task: String?, isLocal: Bool, clonePath: String) async throws -> String {
        try layout.requireWorkspace()
        let name = report.repositoryName
        let markdownRelative = "\(layout.handoffRelative)/handoff-\(name).md"
        let patchRelative = "\(layout.handoffRelative)/handoff-\(name).patch"
        let root = report.repositoryPath

        var branch: String?
        var head: String?
        if isLocal {
            let symbolic = try await git(root, ["symbolic-ref", "--quiet", "--short", "HEAD"])
            head = try await git(root, ["rev-parse", "HEAD"]).trimmedOutput
            branch = symbolic.succeeded ? symbolic.trimmedOutput : head.map { "detached at \($0)" }
        }

        var patch: HandoffBriefing.Patch?
        if request.includeUncommitted {
            let diff = try await runner.checked(CommandInvocation(GitSafe.gitPath, [
                "-C", root, "diff", "--binary", "--no-color", "--no-ext-diff", "--no-textconv",
                "--src-prefix=a/", "--dst-prefix=b/", "HEAD",
            ], timeout: 120))
            if diff.stdout.isEmpty {
                patch = .noChanges
            } else {
                try layout.shared.write(diff.stdout, to: patchRelative, permissions: 0o640)
                patch = .written(path: layout.absolute(patchRelative), base: head ?? "HEAD")
            }
        }
        if case .written = patch {} else {
            try layout.shared.remove(patchRelative)
        }
        let text = HandoffBriefing.markdown(
            name: name, source: root, branch: branch, clonePath: clonePath, task: task, patch: patch, date: Date()
        )
        try layout.shared.write(Data(text.utf8), to: markdownRelative, permissions: 0o640)
        return layout.absolute(markdownRelative)
    }

    private func git(_ root: String, _ arguments: [String]) async throws -> CommandResult {
        try await runner.run(CommandInvocation(GitSafe.gitPath, ["-C", root] + arguments, timeout: 30))
    }
}

extension HandoffResult {
    /// What the terminal runs: `prepare && command`, every word quoted for a POSIX shell.
    public var shellLine: String {
        ((prepare.map { [$0] } ?? []) + [command]).map(ShellQuoting.join).joined(separator: " && ")
    }
}

/// `sv-clone [-k|-w] <source> -- <sv options…> <agent> [-- <first prompt>]` (D26).
public enum HandoffCommandLine {
    public static func arguments(source: String, request: HandoffRequest, prompt: String?) -> [String] {
        var argv = ["sv-clone"]
        switch request.deployKey {
        case .none: break
        case .readOnly: argv.append("-k")
        case .readWrite: argv.append("-w")
        }
        argv += [source, "--"] + request.svOptions + [request.agent.svCommand]
        if let prompt, let promptArguments = promptArguments(request.agent, prompt) {
            argv += ["--"] + promptArguments
        }
        return argv
    }

    /// How each agent takes a first prompt and stays interactive; `nil` when it has no such argument
    /// (for `shell`, arguments after `--` are a command to run).
    public static func promptArguments(_ agent: AgentKind, _ prompt: String) -> [String]? {
        switch agent {
        case .claude, .codex, .pi: [prompt]
        case .gemini: ["--prompt-interactive", prompt]
        case .opencode: ["--prompt", prompt]
        case .muse, .shell: nil
        }
    }
}

/// The briefing the agent is told to read.
public enum HandoffBriefing {
    public enum Patch: Equatable, Sendable {
        /// Uncommitted changes were requested but there were none in tracked files.
        case noChanges
        case written(path: String, base: String)
    }

    public static func markdown(name: String, source: String, branch: String?, clonePath: String, task: String?, patch: Patch?, date: Date) -> String {
        var lines = ["# Hand-off: \(name)", "", "- Source on the host: \(source)"]
        if let branch { lines.append("- Branch: \(branch)") }
        lines += ["- Clone in the sandbox: \(clonePath)", "- Handed off: \(ISO8601DateFormatter().string(from: date))", ""]
        if let task, !task.isEmpty {
            lines += ["## Task", "", task, ""]
        }
        switch patch {
        case nil:
            break
        case .noChanges?:
            lines += ["## Uncommitted changes", "", "The host had no uncommitted changes in tracked files.", ""]
        case let .written(path, base)?:
            lines += [
                "## Uncommitted changes",
                "",
                "The host had uncommitted changes that are not in the clone. Before anything else, apply them in \(clonePath):",
                "",
                "    git apply \(ShellQuoting.quote(path))",
                "",
                "The patch was made with `git diff --binary HEAD` against commit \(base). If `git rev-parse HEAD` differs or the "
                    + "patch does not apply cleanly, stop and report instead of guessing. Untracked files are not included.",
                "",
            ]
        }
        return lines.joined(separator: "\n")
    }
}

/// Opens a terminal window that runs `command` (already quoted for a POSIX shell).
/// The command reaches AppleScript as an `argv` item, never inside a string literal.
public enum TerminalLaunch {
    public static func invocation(_ terminal: TerminalApp, command: String) -> CommandInvocation {
        switch terminal {
        case .terminal:
            return osascript([
                "on run argv", "tell application \"Terminal\"", "activate", "do script (item 1 of argv)", "end tell", "end run",
            ], command)
        case .iterm2:
            return osascript([
                "on run argv", "tell application \"iTerm\"", "activate",
                "set newWindow to (create window with default profile)",
                "tell current session of newWindow to write text (item 1 of argv)",
                "end tell", "end run",
            ], command)
        case .ghostty:
            // Ghostty 1.3's AppleScript, like Terminal: the user's shell gets the line typed in, so the window stays.
            // `open -na Ghostty --args --command=…` restored saved windows or opened an empty one on macOS 27.
            return osascript([
                "on run argv", "tell application \"Ghostty\"", "activate",
                "set cfg to new surface configuration",
                "set win to new window with configuration cfg",
                "set term to focused terminal of selected tab of win",
                "input text (item 1 of argv) to term",
                "send key \"enter\" to term",
                "end tell", "end run",
            ], command)
        }
    }

    private static func osascript(_ statements: [String], _ command: String) -> CommandInvocation {
        CommandInvocation("/usr/bin/osascript", statements.flatMap { ["-e", $0] } + [command], timeout: 30)
    }
}
