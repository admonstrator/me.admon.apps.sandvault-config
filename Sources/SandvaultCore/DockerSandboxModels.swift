import Foundation

// Docker Sandboxes (`sbx`) as a second hand-off target next to sv (D47): one Linux microVM per sandbox, driven
// only through the `sbx` command line. pf, the helper and the sandbox profile are not involved.

/// Where a hand-off runs the agent.
public enum HandoffTarget: String, Codable, Sendable, CaseIterable {
    /// sv's sandbox account on this Mac (`sv-clone`).
    case sandvault
    /// A Docker Sandboxes Linux VM (`sbx run --clone`).
    case dockerSandbox
}

extension AgentKind {
    /// The `sbx run` agent name; `nil` for agents Docker Sandboxes has no template for.
    public var sbxAgent: String? {
        switch self {
        case .claude, .codex, .opencode, .gemini, .shell: rawValue
        case .pi, .muse: nil
        }
    }
}

/// One entry of `sbx ls --json`.
public struct DockerSandbox: Codable, Sendable, Equatable, Hashable, Identifiable {
    public var name: String
    /// `running`, `stopped`, ... as sbx reports it.
    public var status: String
    public var agent: String?
    /// Host folders the sandbox mounts (in clone mode read-only).
    public var workspaces: [String]

    public var id: String { name }
    public var isRunning: Bool { status == "running" }

    public init(name: String, status: String, agent: String? = nil, workspaces: [String] = []) {
        self.name = name
        self.status = status
        self.agent = agent
        self.workspaces = workspaces
    }
}

/// What the app knows about Docker Sandboxes on this Mac.
public struct DockerSandboxesState: Codable, Sendable, Equatable {
    /// Absolute path of `sbx`, `nil` when it is not installed.
    public var executable: String?
    public var sandboxes: [DockerSandbox]
    /// `sbx settings get ssh.agentForwardingEnabled`: the host's SSH agent reaches every sandbox. `nil` when unknown.
    public var sshAgentForwarding: Bool?
    /// Why the list is missing (daemon down, not signed in, unreadable output).
    public var problem: String?

    public init(executable: String? = nil, sandboxes: [DockerSandbox] = [], sshAgentForwarding: Bool? = nil, problem: String? = nil) {
        self.executable = executable
        self.sandboxes = sandboxes
        self.sshAgentForwarding = sshAgentForwarding
        self.problem = problem
    }

    public var installed: Bool { executable != nil }
    public static let notInstalled = DockerSandboxesState()
}

public protocol DockerSandboxService: Sendable {
    func state() async -> DockerSandboxesState
    /// Opens a terminal window attached to the sandbox (`sbx run --name <name>`).
    func open(_ name: String, terminal: TerminalApp) async throws -> SandboxLaunch
    func stop(_ name: String) async throws
    /// `sbx rm --force`: the VM, its files and the agent's unfetched commits are gone.
    func remove(_ name: String) async throws
}

/// For builds and tests without Docker Sandboxes.
public struct NoDockerSandboxes: DockerSandboxService {
    public init() {}
    public func state() async -> DockerSandboxesState { .notInstalled }
    public func open(_ name: String, terminal: TerminalApp) async throws -> SandboxLaunch { throw SandvaultError.notImplemented("Docker Sandboxes") }
    public func stop(_ name: String) async throws { throw SandvaultError.notImplemented("Docker Sandboxes") }
    public func remove(_ name: String) async throws { throw SandvaultError.notImplemented("Docker Sandboxes") }
}
