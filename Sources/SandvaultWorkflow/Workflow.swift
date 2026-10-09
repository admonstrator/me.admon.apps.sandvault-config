import SandvaultCore

/// Entry points other modules use. Agent D replaces the stub bodies; the signatures are the contract.
public enum Workflow {
    /// Readiness check and hand-off of a repository to an agent (`sv-clone` in a terminal).
    public static func makeHandoffService(environment: SandvaultEnvironment, runner: CommandRunner, configStore: ConfigStore) -> HandoffService {
        UnimplementedWorkflow()
    }

    /// Repositories in the shared workspace and the way back (`git fetch sandvault`).
    public static func makeRepoService(environment: SandvaultEnvironment, runner: CommandRunner, configStore: ConfigStore) -> RepoService {
        UnimplementedWorkflow()
    }

    /// Whether a host command works inside the sandbox, and making it available.
    public static func makeToolService(environment: SandvaultEnvironment, runner: CommandRunner, configStore: ConfigStore) -> ToolService {
        UnimplementedWorkflow()
    }

    /// Copying host configuration (Claude, git, zsh) into `$SHARED_WORKSPACE/user`.
    public static func makeMigrationService(environment: SandvaultEnvironment, runner: CommandRunner) -> MigrationService {
        UnimplementedWorkflow()
    }

    /// Public keys in sv's `authorized_keys.d`.
    public static func makeKeyService(environment: SandvaultEnvironment, runner: CommandRunner) -> KeyService {
        UnimplementedWorkflow()
    }
}

struct UnimplementedWorkflow: HandoffService, RepoService, ToolService, MigrationService, KeyService {
    func readiness(of source: String) async throws -> ReadinessReport { throw SandvaultError.notImplemented("Workflow.readiness") }
    func handOff(_ request: HandoffRequest) async throws -> HandoffResult { throw SandvaultError.notImplemented("Workflow.handOff") }
    func repositories() async throws -> [RepoStatus] { throw SandvaultError.notImplemented("Workflow.repositories") }
    func fetchBack(_ record: HandoffRecord) async throws -> RepoStatus { throw SandvaultError.notImplemented("Workflow.fetchBack") }
    func status(of name: String) async throws -> ToolStatus { throw SandvaultError.notImplemented("Workflow.toolStatus") }
    func grant(_ name: String, method: ToolGrantMethod) async throws -> ToolGrant { throw SandvaultError.notImplemented("Workflow.grant") }
    func plan(_ items: [MigrationItem]) async throws -> MigrationPlan { throw SandvaultError.notImplemented("Workflow.plan") }
    func apply(_ plan: MigrationPlan) async throws -> [MigrationEntry] { throw SandvaultError.notImplemented("Workflow.apply") }
    func keys() async throws -> [AuthorizedKey] { throw SandvaultError.notImplemented("Workflow.keys") }
    func add(name: String, publicKey: String) async throws -> AuthorizedKey { throw SandvaultError.notImplemented("Workflow.addKey") }
    func remove(name: String) async throws { throw SandvaultError.notImplemented("Workflow.removeKey") }
}
