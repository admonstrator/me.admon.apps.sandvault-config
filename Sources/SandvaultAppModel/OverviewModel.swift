import Foundation
import Observation
import SandvaultCore
import SandvaultObserve

/// Overview screen: the doctor checks of all three modules, `StatusSummary`, sessions, and the next setup step.
@MainActor @Observable
public final class OverviewModel {
    public private(set) var sections: [CheckSection] = []
    public private(set) var summary: StatusSummary?
    public private(set) var refreshedAt: Date?
    public private(set) var isRefreshing = false

    @ObservationIgnored private let doctor: DoctorSource
    @ObservationIgnored private let status: StatusSource
    @ObservationIgnored private let helperSetup: HelperInstalling
    @ObservationIgnored private let clock: AppClock
    @ObservationIgnored private let editor: ConfigEditor
    @ObservationIgnored private let netd: NetdLink

    /// Checks run dscl, sudo and pfctl; the overview refreshes them at most this often on its own.
    public static let staleAfter: Double = 30

    public init(doctor: DoctorSource, status: StatusSource, helperSetup: HelperInstalling, clock: AppClock, editor: ConfigEditor, netd: NetdLink) {
        self.doctor = doctor
        self.status = status
        self.helperSetup = helperSetup
        self.clock = clock
        self.editor = editor
        self.netd = netd
    }

    public func refresh() async {
        guard !isRefreshing else { return }
        isRefreshing = true
        defer { isRefreshing = false }
        editor.reloadIfChanged()
        let config = editor.config
        let sections = await doctor.sections(config: config)
        summary = await status.summary(firewallMode: config.network.mode, checks: sections.flatMap(\.checks))
        self.sections = sections
        refreshedAt = clock.now()
    }

    public func refreshIfStale() async {
        if let refreshedAt, clock.now().timeIntervalSince(refreshedAt) < Self.staleAfter { return }
        await refresh()
    }

    public var checks: [Check] { sections.flatMap(\.checks) }
    /// Checks in `warning` or `failure`, worst first.
    public var problems: [Check] { checks.filter { $0.state >= .warning }.sorted { $0.state > $1.state } }
    public var sessions: [SandboxSession] { summary?.sessions ?? [] }

    public var setup: SetupState {
        SetupState(checks: checks, helperInstalled: helperSetup.isInstalled, netdRunning: netd.isConnected, firewallMode: editor.config.network.mode)
    }

    public var nextStep: SetupStep { setup.nextStep }
}

/// What is installed and running, derived from the doctor checks and live state.
public struct SetupState: Sendable, Equatable {
    /// `nil` while unknown (no checks yet or the check could not tell).
    public var svInstalled: Bool?
    public var accountReady: Bool?
    public var helperInstalled: Bool
    public var netdRunning: Bool
    public var firewallMode: FirewallMode
    public var panicActive: Bool
    /// The loaded anchor differs from the configured mode (`enforce.firewall`).
    public var firewallOutOfSync: Bool
    public var svFix: String?
    public var accountFix: String?

    public init(
        svInstalled: Bool?, accountReady: Bool?, helperInstalled: Bool, netdRunning: Bool, firewallMode: FirewallMode,
        panicActive: Bool = false, firewallOutOfSync: Bool = false, svFix: String? = nil, accountFix: String? = nil
    ) {
        self.svInstalled = svInstalled
        self.accountReady = accountReady
        self.helperInstalled = helperInstalled
        self.netdRunning = netdRunning
        self.firewallMode = firewallMode
        self.panicActive = panicActive
        self.firewallOutOfSync = firewallOutOfSync
        self.svFix = svFix
        self.accountFix = accountFix
    }

    public init(checks: [Check], helperInstalled: Bool, netdRunning: Bool, firewallMode: FirewallMode) {
        func check(_ id: String) -> Check? { checks.first { $0.id == id } }
        func present(_ id: String) -> Bool? {
            switch check(id)?.state {
            case .ok?, .warning?: true
            case .failure?: false
            default: nil
            }
        }
        self.init(
            svInstalled: present("sv.installed"),
            accountReady: present("account.user"),
            helperInstalled: helperInstalled,
            netdRunning: netdRunning,
            firewallMode: firewallMode,
            panicActive: check("enforce.panic")?.state == .warning,
            firewallOutOfSync: [.warning, .failure].contains(check("enforce.firewall")?.state),
            svFix: check("sv.installed")?.fix,
            accountFix: check("account.user")?.fix
        )
    }

    /// The one thing to do next, in dependency order: sv, its account, the helper, a panic to end, netd, the firewall.
    public var nextStep: SetupStep {
        if svInstalled == false { return .installSandvault(fix: svFix) }
        if svInstalled == nil { return .checking }
        if accountReady == false { return .createSandbox(fix: accountFix) }
        if !helperInstalled { return .installHelper }
        if panicActive { return .endPanic }
        if !netdRunning { return .startNetd }
        if firewallMode == .off { return .enableFirewall }
        if firewallOutOfSync { return .applyFirewall }
        return .ready
    }
}

public enum SetupStep: Sendable, Equatable {
    case checking
    case installSandvault(fix: String?)
    case createSandbox(fix: String?)
    case installHelper
    case endPanic
    case startNetd
    case enableFirewall
    case applyFirewall
    case ready

    public var title: String {
        switch self {
        case .checking: "Checking the installation"
        case .installSandvault: "Install sandvault"
        case .createSandbox: "Create the sandbox account"
        case .installHelper: "Install the privileged helper"
        case .endPanic: "Panic is active"
        case .startNetd: "Start sandvault-netd"
        case .enableFirewall: "Turn on the firewall"
        case .applyFirewall: "Apply the firewall"
        case .ready: "Everything is set up"
        }
    }

    public var detail: String {
        switch self {
        case .checking: "Running the doctor checks."
        case .installSandvault: "Sandvault Config controls an existing sandvault installation (`sv`)."
        case .createSandbox: "Run sv once; it creates the sandbox user, its group and the shared workspace."
        case .installHelper: "Rules and the firewall take effect through a root helper. Installing it asks for your administrator password once."
        case .endPanic: "The sandbox user has no network. Choose a firewall mode and apply it, or turn the firewall off."
        case .startNetd: "netd runs the proxy, DNS forwarder, connection log and the asks. Install its LaunchAgent in Settings."
        case .enableFirewall: "The sandbox reaches the network directly and only addresses are visible. Watch lists every host it contacts."
        case .applyFirewall: "The loaded pf anchor differs from the configured mode."
        case .ready: "sv, the helper, netd and the firewall are in place."
        }
    }

    public var suggestedCommand: String? {
        switch self {
        case .installSandvault(let fix), .createSandbox(let fix): fix
        case .installHelper: "svctl helper install"
        case .endPanic: "svctl firewall off"
        case .startNetd: "svctl netd install"
        case .enableFirewall: "svctl firewall mode watch && svctl firewall apply"
        case .applyFirewall: "svctl firewall apply"
        case .checking, .ready: nil
        }
    }

    /// Where the app does it.
    public var screen: Screen? {
        switch self {
        case .installHelper, .startNetd: .settings
        case .endPanic, .enableFirewall, .applyFirewall: .firewall
        case .checking, .installSandvault, .createSandbox, .ready: nil
        }
    }

    public var isDone: Bool { self == .ready }
}
