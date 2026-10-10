import Foundation
import Observation
import SandvaultCore
import SandvaultEnforce
import SandvaultNet

/// Settings screen: helper and netd installation with the bundled executables, hand-off defaults, polling.
@MainActor @Observable
public final class SettingsModel {
    public private(set) var helperInstalled = false
    public private(set) var netdAgent: NetdLaunchAgent.Status?
    public private(set) var netdAgentError: String?
    public private(set) var preferences: AppPreferences
    public private(set) var isBusy = false
    public var message: UserMessage?
    /// Called after the helper or netd changed (overview and firewall refresh, netd link retries).
    @ObservationIgnored public var onSetupChanged: (@MainActor () async -> Void)?

    @ObservationIgnored private let editor: ConfigEditor
    @ObservationIgnored private let helperSetup: HelperInstalling
    @ObservationIgnored private let agent: NetdAgentControl
    @ObservationIgnored private let store: PreferencesStore
    @ObservationIgnored public let bundled: BundledTools
    @ObservationIgnored public let environment: SandvaultEnvironment

    public init(
        editor: ConfigEditor, helperSetup: HelperInstalling, agent: NetdAgentControl, preferences: PreferencesStore,
        bundled: BundledTools, environment: SandvaultEnvironment
    ) {
        self.editor = editor
        self.helperSetup = helperSetup
        self.agent = agent
        self.store = preferences
        self.bundled = bundled
        self.environment = environment
        self.preferences = preferences.load()
    }

    public var handoff: HandoffSettings { editor.config.handoff }
    public var netdSupported: Bool { agent.platformSupported }

    public func refresh() async {
        helperInstalled = helperSetup.isInstalled
        guard agent.platformSupported else {
            netdAgent = nil
            netdAgentError = SandvaultError.unsupportedPlatform("LaunchAgents (launchd) exist only on macOS").description
            return
        }
        do {
            netdAgent = try await agent.status()
            netdAgentError = nil
        } catch {
            netdAgent = nil
            netdAgentError = UserMessage.describe(error)
        }
    }

    // MARK: Root helper (administrator password through osascript, D27)

    public func installHelper() async {
        guard let source = bundled.helper else {
            message = UserMessage(error: SandvaultError.notInstalled("svctl-helper inside the app bundle"), action: "Install the helper")
            return
        }
        await runSetup("Install the helper") { try await self.helperSetup.install(source: source, user: self.environment.hostUser) }
    }

    public func uninstallHelper() async {
        let binary = helperSetup.isInstalled ? AppPaths.helperPath : bundled.helper
        guard let binary else {
            message = UserMessage(error: SandvaultError.notInstalled("svctl-helper"), action: "Uninstall the helper")
            return
        }
        await runSetup("Uninstall the helper") { try await self.helperSetup.uninstall(binary: binary, user: self.environment.hostUser) }
    }

    // MARK: netd LaunchAgent

    public func installNetd() async {
        guard let executable = bundled.netd else {
            message = UserMessage(error: SandvaultError.notInstalled("sandvault-netd inside the app bundle"), action: "Install netd")
            return
        }
        await runAgent("Install netd", success: "netd installed and started") { try await self.agent.install(executable: executable) }
    }

    public func uninstallNetd() async {
        await runAgent("Uninstall netd", success: "netd stopped and removed") { try await self.agent.uninstall() }
    }

    public func restartNetd() async {
        await runAgent("Restart netd", success: "netd restarted") { try await self.agent.restart() }
    }

    /// One step for the menu bar: kickstart a loaded agent that runs this app's netd, else install it (which also
    /// replaces an agent pointing at another binary).
    public func startNetd() async {
        await refresh()
        if netdAgent?.loaded == true && !netdExecutableMismatch {
            await restartNetd()
        } else {
            await installNetd()
        }
    }

    public var netdAgentSummary: String {
        guard let agent = netdAgent else { return netdAgentError ?? "unknown" }
        guard agent.installed else { return "not installed" }
        var text = agent.loaded ? "loaded, \(agent.state ?? "state unknown")" : "installed, not loaded"
        if let pid = agent.pid { text += ", pid \(pid)" }
        if let code = agent.lastExitCode, !agent.loaded || agent.pid == nil { text += ", last exit \(code)" }
        return text
    }

    /// The LaunchAgent runs a different binary than the one in this app (e.g. after moving the app).
    public var netdExecutableMismatch: Bool {
        guard let installed = netdAgent?.executable, let bundled = bundled.netd else { return false }
        return netdAgent?.installed == true && installed != bundled
    }

    // MARK: Preferences

    public func setDefaultAgent(_ agent: AgentKind) async {
        await editHandoff("Set the default agent") { $0.defaultAgent = agent }
    }

    public func setTerminal(_ terminal: TerminalApp) async {
        await editHandoff("Set the terminal") { $0.terminal = terminal }
    }

    public func setShowInDock(_ on: Bool) {
        preferences.showInDock = on
        store.save(preferences)
    }

    public func setExpertMode(_ on: Bool) {
        preferences.expertMode = on
        store.save(preferences)
    }

    public func setRefreshInterval(_ seconds: Double) {
        preferences.refreshInterval = min(max(seconds, AppPreferences.refreshRange.lowerBound), AppPreferences.refreshRange.upperBound)
        store.save(preferences)
    }

    /// Puts the bundled svctl on PATH (needs an administrator for /usr/local/bin).
    public var svctlLinkCommand: String? {
        bundled.svctl.map { "sudo ln -sf \(AdministratorScript.shellQuote($0)) /usr/local/bin/svctl" }
    }

    // MARK: -

    private func runSetup(_ action: String, _ body: () async throws -> HelperResult) async {
        guard !isBusy else { return }
        isBusy = true
        defer { isBusy = false }
        do {
            let result = try await body()
            message = result.ok ? .success(result.message) : UserMessage(kind: .error, title: "\(action) failed", detail: result.message)
        } catch AdministratorScript.Cancelled.byUser {
            message = .info("\(action): cancelled")
        } catch {
            message = UserMessage(error: error, action: action)
        }
        await refresh()
        await onSetupChanged?()
    }

    private func runAgent(_ action: String, success: String, _ body: () async throws -> Void) async {
        guard !isBusy else { return }
        isBusy = true
        defer { isBusy = false }
        do {
            try await body()
            message = .success(success)
        } catch {
            message = UserMessage(error: error, action: action)
        }
        await refresh()
        await onSetupChanged?()
    }

    private func editHandoff(_ action: String, _ change: (inout HandoffSettings) -> Void) async {
        do {
            try await editor.edit(reloadNetd: false) { change(&$0.handoff) }
        } catch {
            message = UserMessage(error: error, action: action)
        }
    }
}

// MARK: - Administrator commands

/// `osascript -e 'do shell script "..." with administrator privileges'`: macOS asks for an administrator
/// password and runs the command as root. Arguments are shell-quoted, then the whole command is escaped as an
/// AppleScript string, so no path can break out of either layer. osascript gets the script as one argv
/// element; no shell is involved on our side.
public enum AdministratorScript {
    public enum Cancelled: Error, Equatable { case byUser }

    public static let osascript = "/usr/bin/osascript"

    /// POSIX shell single quotes; `'` becomes `'\''`.
    public static func shellQuote(_ argument: String) -> String {
        "'" + argument.replacingOccurrences(of: "'", with: "'\\''") + "'"
    }

    /// An AppleScript string literal: backslash and double quote escaped.
    public static func appleScriptLiteral(_ text: String) -> String {
        "\"" + text.replacingOccurrences(of: "\\", with: "\\\\").replacingOccurrences(of: "\"", with: "\\\"") + "\""
    }

    public static func script(_ argv: [String]) -> String {
        "do shell script " + appleScriptLiteral(argv.map(shellQuote).joined(separator: " ")) + " with administrator privileges"
    }

    public static func invocation(_ argv: [String]) -> CommandInvocation {
        CommandInvocation(osascript, ["-e", script(argv)], timeout: 300)
    }

    /// osascript reports a cancelled password dialog as error -128.
    public static func isCancelled(_ result: CommandResult) -> Bool {
        result.exitCode != 0 && result.stderrString.contains("-128")
    }

    /// The helper's JSON line from osascript's output (`do shell script` turns line feeds into returns).
    public static func helperResult(_ result: CommandResult) throws -> HelperResult {
        if isCancelled(result) { throw Cancelled.byUser }
        let text = result.stdoutString.trimmingCharacters(in: .whitespacesAndNewlines)
        if let line = text.split(whereSeparator: { $0 == "\n" || $0 == "\r" }).last,
           let decoded = try? JSONCoding.decoder.decode(HelperResult.self, from: Data(line.utf8)) {
            return decoded
        }
        throw SandvaultError.commandFailed("osascript (svctl-helper)", result.exitCode, result.stderrString)
    }
}

/// D27: the bundled `svctl-helper install --source <bundled helper> --user <name>` as root after a password prompt.
public struct AdministratorHelperInstaller: HelperInstalling {
    public var runner: CommandRunner
    public var isMacOS: Bool

    public init(runner: CommandRunner, isMacOS: Bool = EnforcePlatform.isMacOS) {
        self.runner = runner
        self.isMacOS = isMacOS
    }

    public var isInstalled: Bool { FileManager.default.isExecutableFile(atPath: AppPaths.helperPath) }

    public static func installArguments(source: String, user: String) -> [String] {
        [source, "install", "--source", source, "--user", user, "--json"]
    }

    public static func uninstallArguments(binary: String, user: String) -> [String] {
        [binary, "uninstall", "--user", user, "--json"]
    }

    public func install(source: String, user: String) async throws -> HelperResult {
        try requireMacOS()
        let result = try await runner.run(AdministratorScript.invocation(Self.installArguments(source: source, user: user)))
        return try AdministratorScript.helperResult(result)
    }

    public func uninstall(binary: String, user: String) async throws -> HelperResult {
        try requireMacOS()
        let result = try await runner.run(AdministratorScript.invocation(Self.uninstallArguments(binary: binary, user: user)))
        return try AdministratorScript.helperResult(result)
    }

    private func requireMacOS() throws {
        guard isMacOS else { throw SandvaultError.unsupportedPlatform("the root helper exists on macOS only") }
    }
}
