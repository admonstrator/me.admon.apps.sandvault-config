import Foundation
import SandvaultCore

/// Everything the root helper touches, injectable so tests run the real logic against a temporary root
/// with `FakeCommandRunner`. Paths written into files (sudoers rule, LaunchDaemon) stay the real ones.
public struct HelperContext: Sendable {
    /// Prefix for every root path: `""` in production, a temporary directory in tests.
    public var root: String
    public var runner: CommandRunner
    /// The helper's own process environment (`SUDO_USER`, `SUDO_UID`).
    public var processEnvironment: [String: String]
    /// Write files as root:wheel. Tests that do not run as root turn it off.
    public var setsRootOwnership: Bool
    /// The running helper binary: default `--source` for `install`.
    public var executablePath: String?
    public var now: @Sendable () -> Date

    public init(
        root: String = "",
        runner: CommandRunner,
        processEnvironment: [String: String],
        setsRootOwnership: Bool = true,
        executablePath: String? = nil,
        now: @escaping @Sendable () -> Date = { Date() }
    ) {
        self.root = root
        self.runner = runner
        self.processEnvironment = processEnvironment
        self.setsRootOwnership = setsRootOwnership
        self.executablePath = executablePath
        self.now = now
    }

    func profile(_ environment: SandvaultEnvironment) -> String { root + environment.sandboxProfilePath }
    func svSudoers(_ environment: SandvaultEnvironment) -> String { root + environment.sudoersFile }
    func helperSudoers(_ environment: SandvaultEnvironment) -> String { root + AppPaths(environment: environment).helperSudoersFile }
    var helperBinary: String { root + AppPaths.helperPath }
    var stateDir: String { root + AppPaths.rootStateDir }
    var launchDaemonPlist: String { root + AppPaths.launchDaemonPlist }
    var recordPath: String { RootState.recordPath(in: stateDir) }
    var statePath: String { RootState.statePath(in: stateDir) }
}
