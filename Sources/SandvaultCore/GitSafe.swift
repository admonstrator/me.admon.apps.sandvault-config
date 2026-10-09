import Foundation

/// Git invocations against repositories the sandbox can write to (`$SHARED_WORKSPACE/repos/*`).
/// A sandbox that poisons `.git/config` could otherwise run code as the host user through keys git
/// treats as commands. Same hardening as upstream `sv-clone` `git_repo()`; `-c` wins over repo config.
public enum GitSafe {
    public static let hardeningArguments: [String] = [
        "-c", "core.fsmonitor=",
        "-c", "core.sshCommand=",
        "-c", "core.hooksPath=/dev/null",
        "-c", "core.pager=cat",
        "-c", "protocol.ext.allow=never",
    ]

    public static let gitPath = "/usr/bin/git"

    /// `git <hardening> -C <repository> <arguments>` with a scrubbed environment.
    public static func invocation(repository: String, _ arguments: [String], timeout: Double? = 60) -> CommandInvocation {
        CommandInvocation(
            gitPath,
            hardeningArguments + ["-C", repository] + arguments,
            environment: scrubbedEnvironment(),
            timeout: timeout
        )
    }

    /// Keeps only what git needs; drops `GIT_*` overrides a caller might have inherited.
    public static func scrubbedEnvironment(_ base: [String: String] = ProcessInfo.processInfo.environment) -> [String: String] {
        var environment: [String: String] = [:]
        for key in ["HOME", "USER", "LOGNAME", "PATH", "LANG", "LC_ALL", "TMPDIR", "SSH_AUTH_SOCK"] {
            if let value = base[key] { environment[key] = value }
        }
        environment["GIT_TERMINAL_PROMPT"] = "0"
        environment["GIT_CONFIG_NOSYSTEM"] = "1"
        return environment
    }
}
