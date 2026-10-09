import SandvaultCore

/// Entry points other modules use. The concrete types are public too, for callers that need more
/// (`RepositoryHandoff.handOff(_:launch:)`, `SandvaultDefaults`).
public enum Workflow {
    /// Readiness check and hand-off of a repository to an agent (`sv-clone` in a terminal).
    public static func makeHandoffService(environment: SandvaultEnvironment, runner: CommandRunner, configStore: ConfigStore) -> HandoffService {
        RepositoryHandoff(environment: environment, runner: runner, configStore: configStore)
    }

    /// Repositories in the shared workspace and the way back (`git fetch sandvault`).
    public static func makeRepoService(environment: SandvaultEnvironment, runner: CommandRunner, configStore: ConfigStore) -> RepoService {
        SandboxRepositories(environment: environment, runner: runner, configStore: configStore)
    }

    /// Whether a host command works inside the sandbox, and making it available.
    public static func makeToolService(environment: SandvaultEnvironment, runner: CommandRunner, configStore: ConfigStore) -> ToolService {
        ToolAccess(environment: environment, runner: runner, configStore: configStore)
    }

    /// Copying host configuration (Claude, git, zsh) into `$SHARED_WORKSPACE/user`.
    public static func makeMigrationService(environment: SandvaultEnvironment, runner: CommandRunner) -> MigrationService {
        ConfigMigration(environment: environment, runner: runner)
    }

    /// Public keys in sv's `authorized_keys.d`.
    public static func makeKeyService(environment: SandvaultEnvironment, runner: CommandRunner) -> KeyService {
        AuthorizedKeyStore(environment: environment, runner: runner)
    }
}
