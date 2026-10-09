import Foundation
import Observation
import SandvaultCore

/// Sandbox screen: start a shell or an agent, and create, rebuild or delete the sandbox. Everything runs `sv` in a
/// terminal window, where `sv build` and `sv uninstall` ask for the administrator password themselves.
@MainActor @Observable
public final class SandboxModel {
    public private(set) var state: SandboxState?
    public private(set) var isBusy = false
    public var message: UserMessage?
    /// The preset `create` applies.
    public var setup = SandboxSetup.everyday
    /// Where a session starts; `nil` is the shared workspace.
    public var startDirectory: String?

    @ObservationIgnored private let service: SandboxService
    @ObservationIgnored private let editor: ConfigEditor
    @ObservationIgnored private let helperSetup: HelperInstalling
    @ObservationIgnored private let bundled: BundledTools
    @ObservationIgnored public let environment: SandvaultEnvironment

    public init(service: SandboxService, editor: ConfigEditor, helperSetup: HelperInstalling, bundled: BundledTools, environment: SandvaultEnvironment) {
        self.service = service
        self.editor = editor
        self.helperSetup = helperSetup
        self.bundled = bundled
        self.environment = environment
    }

    public func refresh() async {
        state = await service.state()
    }

    public var installed: Bool { state?.installed == true }

    /// `Installed`, `Not installed`, or what is left of an incomplete one.
    public var summary: String {
        guard let state else { return "Checking…" }
        if state.installed { return "Installed for \(environment.hostUser) (\(environment.sandvaultUser))" }
        if state.incomplete { return "Incomplete: parts of an earlier sandbox are left. Create it again to repair it." }
        return "No sandbox yet"
    }

    // MARK: Sessions

    /// `sv <agent>` in the configured terminal, starting in `startDirectory` or the shared workspace.
    public func open(_ agent: AgentKind) async {
        let directory = startDirectory ?? (state?.workspace == true ? environment.sharedWorkspace : nil)
        let title = agent.displayName
        await launch(.open(agent, directory: directory), action: "Start \(title)", followUp: []) {
            "\(title) opens in \(self.editor.config.handoff.terminal.displayName)"
        }
    }

    // MARK: Life cycle

    /// Saves the preset's rules and protection level, then runs `sv build` and applies both once it succeeded.
    public func create() async {
        let setup = self.setup
        do {
            try await editor.edit {
                $0.sandbox.preset = setup.rules
                setup.protection.apply(to: &$0.network)
            }
        } catch {
            message = UserMessage(error: error, action: "Save the preset")
            return
        }
        await launch(.build, action: "Create the sandbox", followUp: applySteps()) {
            "sv build runs in \(self.editor.config.handoff.terminal.displayName); it asks for your password"
        }
    }

    /// `sv --rebuild build` repairs sv's configuration and permissions; the managed rules block is written again after it.
    public func rebuild() async {
        await launch(.rebuild, action: "Rebuild the sandbox", followUp: applySteps()) {
            "sv rebuilds the sandbox in \(self.editor.config.handoff.terminal.displayName); it asks for your password"
        }
    }

    /// `sv uninstall`: the account and sv's files go, `user/` and the repositories in the shared workspace stay.
    public func delete() async {
        await launch(.uninstall, action: "Delete the sandbox", followUp: []) {
            "sv uninstall runs in \(self.editor.config.handoff.terminal.displayName); it asks for your password"
        }
    }

    /// What the uninstall keeps, for the confirmation.
    public var deleteExplanation: String {
        "Removes \(environment.sandvaultUser), its home folder, sv's profile and SSH key. "
            + "\(environment.sharedWorkspace)/user and the repositories in \(environment.sharedReposDir) stay."
    }

    /// `svctl rules apply` and `svctl firewall apply` after `sv build`, when the helper can do them unattended.
    func applySteps() -> [[String]] {
        guard helperSetup.isInstalled, let svctl = bundled.svctl else { return [] }
        let config = editor.config
        var steps: [[String]] = []
        let sandbox = config.sandbox
        if sandbox.preset != .standard || !sandbox.fileRules.isEmpty || !sandbox.machRules.isEmpty || !sandbox.execRules.isEmpty {
            steps.append([svctl, "rules", "apply", "--yes"])
        }
        if config.network.mode != .off { steps.append([svctl, "firewall", "apply", "--yes"]) }
        return steps
    }

    private func launch(_ command: SandboxCommand, action: String, followUp: [[String]], success: () -> String) async {
        guard !isBusy else { return }
        isBusy = true
        defer { isBusy = false }
        let handoff = editor.config.handoff
        do {
            let result = try await service.run(command, terminal: handoff.terminal, svOptions: handoff.svOptions, followUp: followUp)
            message = result.launched ? .success(success()) : .info("\(action): run this in a terminal", detail: result.command)
        } catch {
            message = UserMessage(error: error, action: action)
        }
        await refresh()
    }
}

/// Starting points for a new sandbox: sandbox rules plus a protection level, both changeable later.
public enum SandboxSetup: String, CaseIterable, Identifiable, Sendable {
    case everyday, careful, offline, unrestricted

    public var id: String { rawValue }

    public var title: String {
        switch self {
        case .everyday: "Everyday"
        case .careful: "Careful"
        case .offline: "Offline"
        case .unrestricted: "Unrestricted"
        }
    }

    public var explanation: String {
        switch self {
        case .everyday: "sv's rules. Network allowed, every website and DNS name shows under Activity."
        case .careful: "Hardened rules (no AppleScript, open, launchctl). Each new website waits for your answer."
        case .offline: "Hardened rules and no network at all."
        case .unrestricted: "sv's rules and a direct network connection. Only addresses are visible."
        }
    }

    public var rules: SandboxPreset {
        switch self {
        case .everyday, .unrestricted: .standard
        case .careful, .offline: .hardened
        }
    }

    public var protection: ProtectionLevel {
        switch self {
        case .everyday: .watch
        case .careful: .ask
        case .offline: .blockAll
        case .unrestricted: .off
        }
    }
}
