import Foundation
import SandvaultCore

/// Docker Sandboxes through the `sbx` command line (D47). Lists, stops and removes VMs; attaching and hand-offs run
/// in a terminal window because the agents are interactive.
public struct DockerSandboxes: DockerSandboxService {
    public let runner: CommandRunner
    public let isMacOS: Bool
    /// Where Homebrew installs `sbx`; a GUI app does not see the login shell's PATH.
    public let candidates: [String]
    let exists: @Sendable (String) -> Bool

    public static let defaultCandidates = ["/opt/homebrew/bin/sbx", "/usr/local/bin/sbx"]
    static let timeout: Double = 20

    public init(
        runner: CommandRunner, isMacOS: Bool = WorkflowPlatform.isMacOS, candidates: [String] = DockerSandboxes.defaultCandidates,
        exists: @escaping @Sendable (String) -> Bool = { FileManager.default.isExecutableFile(atPath: $0) }
    ) {
        self.runner = runner
        self.isMacOS = isMacOS
        self.candidates = candidates
        self.exists = exists
    }

    public var executable: String? { candidates.first(where: exists) }

    public func state() async -> DockerSandboxesState {
        guard let sbx = executable else { return .notInstalled }
        var state = DockerSandboxesState(executable: sbx)
        do {
            let result = try await runner.run(CommandInvocation(sbx, ["ls", "--json"], timeout: Self.timeout))
            if result.succeeded, let sandboxes = Self.parseList(result.stdout) {
                state.sandboxes = sandboxes
            } else {
                state.problem = result.succeeded ? "sbx ls printed something unexpected" : Self.reason(result, "sbx ls failed")
            }
        } catch {
            state.problem = "sbx ls failed: \(error)"
        }
        if let result = try? await runner.run(CommandInvocation(sbx, ["settings", "get", "ssh.agentForwardingEnabled"], timeout: Self.timeout)),
           result.succeeded {
            state.sshAgentForwarding = Self.parseBool(result.stdoutString)
        }
        return state
    }

    public func open(_ name: String, terminal: TerminalApp) async throws -> SandboxLaunch {
        let line = ShellQuoting.join(try Self.attachArguments(sbx: try require(), name: name))
        guard isMacOS else { return SandboxLaunch(command: line, launched: false) }
        _ = try await runner.checked(TerminalLaunch.invocation(terminal, command: line))
        return SandboxLaunch(command: line, launched: true)
    }

    public func stop(_ name: String) async throws {
        try DockerSandboxName.validateExisting(name)
        _ = try await runner.checked(CommandInvocation(try require(), ["stop", name], timeout: 60))
    }

    public func remove(_ name: String) async throws {
        try DockerSandboxName.validateExisting(name)
        _ = try await runner.checked(CommandInvocation(try require(), ["rm", "--force", name], timeout: 120))
    }

    private func require() throws -> String {
        guard let sbx = executable else {
            throw SandvaultError.invalidInput("Docker Sandboxes are not installed (brew install docker/tap/sbx, then sbx login)")
        }
        return sbx
    }

    // MARK: - Command lines

    /// `sbx run --name <name>`: reattaches from any directory.
    public static func attachArguments(sbx: String, name: String) throws -> [String] {
        try DockerSandboxName.validateExisting(name)
        return [sbx, "run", "--name", name]
    }

    /// `sbx run --name <name> --clone <agent> <folder> [-- <prompt>]`. Clone mode mounts the folder read-only and the
    /// agent works on its own clone; `git fetch sandbox-<name>` in the folder brings its commits back.
    public static func runArguments(sbx: String, name: String, agent: AgentKind, folder: String, prompt: String?) throws -> [String] {
        guard let sbxAgent = agent.sbxAgent else {
            throw SandvaultError.invalidInput("\(agent.rawValue) does not run in Docker Sandboxes (claude, codex, opencode, gemini or shell)")
        }
        var argv = [sbx, "run", "--name", name, "--clone", sbxAgent, folder]
        if let prompt, !prompt.isEmpty, let promptArguments = HandoffCommandLine.promptArguments(agent, prompt) {
            argv += ["--"] + promptArguments
        }
        return argv
    }

    // MARK: - Parsing (sbx output is the user's own tool, but still parsed strictly)

    struct ListOutput: Decodable {
        struct Entry: Decodable {
            var name: String
            var status: String?
            var agent: String?
            var workspaces: [String]?
        }
        var sandboxes: [Entry]
    }

    /// sbx 0.4x on macOS prints a bare array `[{"name":…,"status":…,"agent":…,"workspaces":[…]}]`; older builds wrap
    /// it as `{"sandboxes":[…]}`. Unknown fields are ignored.
    static func parseList(_ data: Data) -> [DockerSandbox]? {
        let decoder = JSONDecoder()
        guard let entries = (try? decoder.decode([ListOutput.Entry].self, from: data)) ?? (try? decoder.decode(ListOutput.self, from: data))?.sandboxes
        else { return nil }
        return entries
            .filter { !Text.hasControlCharacters($0.name) && !$0.name.isEmpty }
            .map { DockerSandbox(name: $0.name, status: $0.status ?? "unknown", agent: $0.agent, workspaces: $0.workspaces ?? []) }
            .sorted { $0.name < $1.name }
    }

    static func parseBool(_ text: String) -> Bool? {
        let word = text.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
        if word.hasSuffix("true") { return true }
        if word.hasSuffix("false") { return false }
        return nil
    }

    static func reason(_ result: CommandResult, _ fallback: String) -> String {
        let text = result.stderrString.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !text.isEmpty, text.count <= 300, !Text.hasControlCharacters(text) else { return fallback }
        return text
    }
}

/// Sandbox names the app creates: `sv-<repo>`, lower case, `-` for anything else, a number when taken.
public enum DockerSandboxName {
    public static func make(for repoName: String, taken: Set<String>) -> String {
        var base = "sv-" + String(repoName.lowercased().unicodeScalars.map { scalar in
            ("a"..."z").contains(scalar) || ("0"..."9").contains(scalar) ? Character(scalar) : "-"
        })
        while base.contains("--") { base = base.replacingOccurrences(of: "--", with: "-") }
        if base.hasSuffix("-") { base.removeLast() }
        base = String(base.prefix(48))
        guard taken.contains(base) else { return base }
        var number = 2
        while taken.contains("\(base)-\(number)") { number += 1 }
        return "\(base)-\(number)"
    }

    /// Names from `sbx ls` or the config, before they become arguments.
    static func validateExisting(_ name: String) throws {
        guard !name.isEmpty, name.count <= 128, !name.hasPrefix("-"), !Text.hasControlCharacters(name), !name.contains(" ") else {
            throw SandvaultError.invalidInput("bad sandbox name '\(name)'")
        }
    }
}
