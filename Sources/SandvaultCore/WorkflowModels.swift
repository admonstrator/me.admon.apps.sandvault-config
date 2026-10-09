import Foundation

// Phase 2 contract: shapes for hand-off, repos, tools, migration and keys (agent D implements, agent E consumes).

// MARK: - Hand-off

public enum FindingSeverity: String, Codable, Sendable, CaseIterable, Comparable {
    case info, warning, blocker

    private var rank: Int {
        switch self {
        case .info: 0
        case .warning: 1
        case .blocker: 2
        }
    }

    public static func < (lhs: FindingSeverity, rhs: FindingSeverity) -> Bool { lhs.rank < rhs.rank }
}

public enum ReadinessKind: String, Codable, Sendable, CaseIterable {
    case notGitRepository, noCommits, uncommittedChanges, untrackedFiles
    case symlinkOutside, virtualenvHostInterpreter, envrc, dotenvFile, localSubmodule, gitFileIndirection
    case largeRepository, alreadyHandedOff
    /// sv-clone (v1.32) refuses a local repository without an `origin` remote.
    case noOriginRemote
}

public struct ReadinessFinding: Codable, Sendable, Equatable, Hashable {
    public var kind: ReadinessKind
    public var severity: FindingSeverity
    /// Path relative to the repository root, when the finding is about one file.
    public var path: String?
    public var message: String

    public init(kind: ReadinessKind, severity: FindingSeverity, path: String? = nil, message: String) {
        self.kind = kind
        self.severity = severity
        self.path = path
        self.message = message
    }
}

public struct ReadinessReport: Codable, Sendable, Equatable {
    public var repositoryPath: String
    public var repositoryName: String
    public var findings: [ReadinessFinding]

    public init(repositoryPath: String, repositoryName: String, findings: [ReadinessFinding]) {
        self.repositoryPath = repositoryPath
        self.repositoryName = repositoryName
        self.findings = findings
    }

    public var worst: FindingSeverity? { findings.map(\.severity).max() }
    public var canProceed: Bool { worst != .blocker }
}

public struct HandoffRequest: Codable, Sendable, Equatable {
    /// Local repository path or remote URL (what `sv-clone` accepts).
    public var source: String
    public var agent: AgentKind
    /// Task text; written to `$SHARED_WORKSPACE/tmp/handoff-<repo>.md` and passed to the agent as its first prompt.
    public var task: String?
    /// Carry uncommitted changes into the clone (`git diff --binary` applied there).
    public var includeUncommitted: Bool
    public var terminal: TerminalApp
    /// Extra `sv` options (e.g. `--browser`).
    public var svOptions: [String]
    /// `sv-clone -k` / `-w`.
    public var deployKey: DeployKeyMode

    public enum DeployKeyMode: String, Codable, Sendable, CaseIterable { case none, readOnly, readWrite }

    public init(
        source: String, agent: AgentKind, task: String? = nil, includeUncommitted: Bool = false,
        terminal: TerminalApp = .terminal, svOptions: [String] = [], deployKey: DeployKeyMode = .none
    ) {
        self.source = source
        self.agent = agent
        self.task = task
        self.includeUncommitted = includeUncommitted
        self.terminal = terminal
        self.svOptions = svOptions
        self.deployKey = deployKey
    }
}

public struct HandoffResult: Codable, Sendable, Equatable {
    public var record: HandoffRecord
    public var briefingPath: String?
    /// The exact command line started in the terminal.
    public var command: [String]
    public var launched: Bool

    public init(record: HandoffRecord, briefingPath: String?, command: [String], launched: Bool) {
        self.record = record
        self.briefingPath = briefingPath
        self.command = command
        self.launched = launched
    }
}

// MARK: - Repos (way back)

public struct RepoStatus: Codable, Sendable, Equatable, Identifiable {
    public var record: HandoffRecord?
    public var name: String
    public var sandboxPath: String
    public var branch: String?
    public var headCommit: String?
    public var lastCommitDate: Date?
    /// `nil` when unknown (not on macOS, or the sandboxed status call failed).
    public var dirty: Bool?
    /// Commits in the sandbox clone that the host repository has not fetched yet (`HEAD` of the clone vs `sandvault/<branch>` on the host).
    public var unfetchedCommits: Int?
    public var aheadOfOrigin: Int?
    public var behindOrigin: Int?
    public var deployKey: String?

    public var id: String { sandboxPath }

    public init(
        record: HandoffRecord?, name: String, sandboxPath: String, branch: String? = nil, headCommit: String? = nil,
        lastCommitDate: Date? = nil, dirty: Bool? = nil, unfetchedCommits: Int? = nil, aheadOfOrigin: Int? = nil,
        behindOrigin: Int? = nil, deployKey: String? = nil
    ) {
        self.record = record
        self.name = name
        self.sandboxPath = sandboxPath
        self.branch = branch
        self.headCommit = headCommit
        self.lastCommitDate = lastCommitDate
        self.dirty = dirty
        self.unfetchedCommits = unfetchedCommits
        self.aheadOfOrigin = aheadOfOrigin
        self.behindOrigin = behindOrigin
        self.deployKey = deployKey
    }
}

// MARK: - Tools

public enum ToolLocation: String, Codable, Sendable, CaseIterable { case system, homebrew, hostHome, sharedUser, sandboxHome, missing }

public struct ToolStatus: Codable, Sendable, Equatable {
    public var name: String
    /// Where the host resolves it (`command -v` in a login shell).
    public var hostPath: String?
    public var location: ToolLocation
    /// Mach-O with only system dylibs, script with interpreter, symlink into a toolchain, ...
    public var kind: String?
    public var reachableInSandbox: Bool
    public var reason: String
    /// Ways to make it available, best first.
    public var options: [ToolGrantMethod]
    /// Homebrew formula that provides it, when known.
    public var formula: String?

    public init(
        name: String, hostPath: String?, location: ToolLocation, kind: String? = nil, reachableInSandbox: Bool,
        reason: String, options: [ToolGrantMethod] = [], formula: String? = nil
    ) {
        self.name = name
        self.hostPath = hostPath
        self.location = location
        self.kind = kind
        self.reachableInSandbox = reachableInSandbox
        self.reason = reason
        self.options = options
        self.formula = formula
    }
}

// MARK: - Migration

public enum MigrationItem: String, Codable, Sendable, CaseIterable {
    case claudeSettings, claudeMemory, claudeCommands, claudeAgents, claudeSkills
    case gitIdentity, zshrc, zprofile, zshenv
}

public struct MigrationEntry: Codable, Sendable, Equatable, Hashable {
    public var item: MigrationItem
    public var source: String
    /// Relative to `$SHARED_WORKSPACE/user`.
    public var destination: String
    public var bytes: Int
    /// Why this file will not be copied (credential, token pattern, symlink outside, too large).
    public var blockedReason: String?
    public var overwrites: Bool

    public init(item: MigrationItem, source: String, destination: String, bytes: Int, blockedReason: String? = nil, overwrites: Bool = false) {
        self.item = item
        self.source = source
        self.destination = destination
        self.bytes = bytes
        self.blockedReason = blockedReason
        self.overwrites = overwrites
    }
}

public struct MigrationPlan: Codable, Sendable, Equatable {
    public var entries: [MigrationEntry]

    public init(entries: [MigrationEntry]) {
        self.entries = entries
    }

    public var copyable: [MigrationEntry] { entries.filter { $0.blockedReason == nil } }
}

// MARK: - SSH keys for sv's authorized_keys.d

public struct AuthorizedKey: Codable, Sendable, Equatable, Hashable, Identifiable {
    /// File name in `authorized_keys.d`.
    public var name: String
    public var type: String
    public var fingerprint: String
    public var comment: String?

    public var id: String { name }

    public init(name: String, type: String, fingerprint: String, comment: String? = nil) {
        self.name = name
        self.type = type
        self.fingerprint = fingerprint
        self.comment = comment
    }
}

// MARK: - Services (agent D implements, factories in `Workflow`)

public protocol HandoffService: Sendable {
    func readiness(of source: String) async throws -> ReadinessReport
    func handOff(_ request: HandoffRequest) async throws -> HandoffResult
}

public protocol RepoService: Sendable {
    func repositories() async throws -> [RepoStatus]
    /// `git fetch sandvault` in the host repository of `record`.
    func fetchBack(_ record: HandoffRecord) async throws -> RepoStatus
}

public protocol ToolService: Sendable {
    func status(of name: String) async throws -> ToolStatus
    func grant(_ name: String, method: ToolGrantMethod) async throws -> ToolGrant
}

public protocol MigrationService: Sendable {
    func plan(_ items: [MigrationItem]) async throws -> MigrationPlan
    func apply(_ plan: MigrationPlan) async throws -> [MigrationEntry]
}

public protocol KeyService: Sendable {
    func keys() async throws -> [AuthorizedKey]
    func add(name: String, publicKey: String) async throws -> AuthorizedKey
    func remove(name: String) async throws
}

// MARK: - The sandbox itself (sv build, sv uninstall, sessions)

/// What `sv` is asked to do in a terminal window.
public enum SandboxCommand: Sendable, Equatable {
    /// `sv <agent> [directory]`; `shell` opens a login shell.
    case open(AgentKind, directory: String?)
    /// `sv build`: creates the sandbox account, profile and shared workspace (asks for the password in the terminal).
    case build
    /// `sv --rebuild build`: rewrites sv's configuration and permissions, which drops the managed rules block.
    case rebuild
    /// `sv uninstall`: removes the account and sv's files, keeps `$SHARED_WORKSPACE/user` and the repositories.
    case uninstall
}

/// Whether sv's sandbox exists, from the files sv writes (no sudo, no dscl).
public struct SandboxState: Codable, Sendable, Equatable {
    /// sv's install marker, written last by `sv build` and removed first by `sv uninstall`.
    public var installed: Bool
    /// `/var/sandvault/sandbox-<user>.sb`.
    public var profile: Bool
    /// `/Users/<sandvault user>`.
    public var home: Bool
    /// `/Users/Shared/sv-<user>`.
    public var workspace: Bool

    public init(installed: Bool, profile: Bool, home: Bool, workspace: Bool) {
        self.installed = installed
        self.profile = profile
        self.home = home
        self.workspace = workspace
    }

    /// Something of an earlier sandbox is left, but sv's marker says it is not complete.
    public var incomplete: Bool { !installed && (profile || home) }
}

/// The line a terminal window was asked to run.
public struct SandboxLaunch: Codable, Sendable, Equatable {
    public var command: String
    public var launched: Bool

    public init(command: String, launched: Bool) {
        self.command = command
        self.launched = launched
    }
}

public protocol SandboxService: Sendable {
    func state() async -> SandboxState
    /// Opens a terminal window with `sv`; each `followUp` argv runs after it, only when everything before succeeded.
    func run(_ command: SandboxCommand, terminal: TerminalApp, svOptions: [String], followUp: [[String]]) async throws -> SandboxLaunch
}
