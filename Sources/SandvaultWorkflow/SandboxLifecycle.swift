import Foundation
import SandvaultCore

/// Sessions and the sandbox's life cycle, all through `sv` in a terminal window: `sv build` and `sv uninstall` ask
/// for the administrator password there, and agents need a terminal anyway.
public struct SandboxLifecycle: SandboxService {
    public let environment: SandvaultEnvironment
    public let runner: CommandRunner
    /// Opening a terminal needs macOS; elsewhere `run` returns the line with `launched: false`.
    public let isMacOS: Bool
    let exists: @Sendable (String) -> Bool

    public init(
        environment: SandvaultEnvironment, runner: CommandRunner, isMacOS: Bool = WorkflowPlatform.isMacOS,
        exists: @escaping @Sendable (String) -> Bool = { FileManager.default.fileExists(atPath: $0) }
    ) {
        self.environment = environment
        self.runner = runner
        self.isMacOS = isMacOS
        self.exists = exists
    }

    public func state() async -> SandboxState {
        SandboxState(
            installed: exists(environment.installMarker), profile: exists(environment.sandboxProfilePath),
            home: exists(environment.sandvaultHome), workspace: exists(environment.sharedWorkspace)
        )
    }

    public func run(_ command: SandboxCommand, terminal: TerminalApp, svOptions: [String], followUp: [[String]]) async throws -> SandboxLaunch {
        let line = try Self.commandLine(command, svOptions: svOptions, followUp: followUp)
        guard isMacOS else { return SandboxLaunch(command: line, launched: false) }
        _ = try await runner.checked(TerminalLaunch.invocation(terminal, command: line))
        return SandboxLaunch(command: line, launched: true)
    }

    /// `sv <options> <command>`, then `&& <follow-up>` for each one, every word quoted for a POSIX shell.
    /// The options pass `SvOptions.validate`; `--rebuild` comes only from `.rebuild`, never from the options.
    public static func commandLine(_ command: SandboxCommand, svOptions: [String], followUp: [[String]] = []) throws -> String {
        let argv: [String]
        switch command {
        case let .open(agent, directory):
            try SvOptions.validate(svOptions)
            if let directory, directory.isEmpty || Text.hasControlCharacters(directory) {
                throw SandvaultError.invalidInput("invalid start directory")
            }
            argv = ["sv"] + svOptions + [agent.svCommand] + (directory.map { [$0] } ?? [])
        case .build:
            argv = ["sv", "build"]
        case .rebuild:
            argv = ["sv", "--rebuild", "build"]
        case .uninstall:
            argv = ["sv", "uninstall"]
        }
        return ([argv] + followUp).map(ShellQuoting.join).joined(separator: " && ")
    }
}
