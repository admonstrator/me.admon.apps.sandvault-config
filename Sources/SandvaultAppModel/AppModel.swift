import Foundation
import Observation
import SandvaultCore
import SandvaultObserve

/// Pages of the main window, in sidebar order.
public enum Screen: String, CaseIterable, Identifiable, Hashable, Sendable {
    case overview, sandbox, activity, processes, network, firewall, rules, tools, handoff, migration, settings

    /// The window without expert mode.
    public static let simple: [Screen] = [.overview, .sandbox, .activity, .handoff, .settings]

    public var id: String { rawValue }

    public var title: String {
        switch self {
        case .overview: "Overview"
        case .sandbox: "Sandbox"
        case .activity: "Activity"
        case .processes: "Processes"
        case .network: "Network"
        case .firewall: "Firewall & Proxy"
        case .rules: "Sandbox Rules & Learn"
        case .tools: "Tools"
        case .handoff: "Repos & Hand-off"
        case .migration: "Migration"
        case .settings: "Settings"
        }
    }

    public var symbolName: String {
        switch self {
        case .overview: "gauge.with.dots.needle.33percent"
        case .sandbox: "shippingbox"
        case .activity: "dot.radiowaves.left.and.right"
        case .processes: "list.bullet.indent"
        case .network: "network"
        case .firewall: "shield.lefthalf.filled"
        case .rules: "lock.doc"
        case .tools: "wrench.and.screwdriver"
        case .handoff: "arrow.triangle.branch"
        case .migration: "tray.and.arrow.down"
        case .settings: "gearshape"
        }
    }
}

/// Where the app is visible. Polling runs only while at least one surface is.
public enum Surface: Hashable, Sendable {
    case window, menu
}

/// The app's root: one environment, one config editor, one netd link, one model per screen.
@MainActor @Observable
public final class AppModel {
    public let editor: ConfigEditor
    public let netd: NetdLink
    public let overview: OverviewModel
    public let processes: ProcessesModel
    public let network: NetworkModel
    public let activity: ActivityModel
    public let firewall: FirewallModel
    public let rules: RulesModel
    public let asks: AsksModel
    public let handoff: HandoffModel
    public let repos: ReposModel
    public let tools: ToolsModel
    public let migration: MigrationModel
    public let keys: KeysModel
    public let settings: SettingsModel
    public let sandbox: SandboxModel

    public private(set) var selection: Screen = .overview
    public private(set) var visibleSurfaces: Set<Surface> = []

    @ObservationIgnored public let environment: AppEnvironment
    @ObservationIgnored private var pollTask: Task<Void, Never>?
    @ObservationIgnored private var started = false

    public init(environment: AppEnvironment) {
        self.environment = environment
        let editor = ConfigEditor(store: environment.configStore, netd: environment.netd)
        editor.reload()
        let netd = NetdLink(connector: environment.netd, clock: environment.clock)
        self.editor = editor
        self.netd = netd
        overview = OverviewModel(
            doctor: environment.doctor, status: environment.status, helperSetup: environment.helperSetup, clock: environment.clock,
            editor: editor, netd: netd
        )
        processes = ProcessesModel(source: environment.processes, control: environment.processControl)
        network = NetworkModel(connections: environment.connections, netd: netd, editor: editor, clock: environment.clock)
        activity = ActivityModel(network: network, processes: processes, netd: netd, editor: editor)
        firewall = FirewallModel(
            editor: editor, policy: environment.policy, sandboxUID: environment.sandboxUID, localPorts: environment.localPorts,
            ca: environment.ca, clock: environment.clock
        )
        rules = RulesModel(
            editor: editor, profiles: environment.profiles, policy: environment.policy, violations: environment.violations,
            environment: environment.environment
        )
        asks = AsksModel(netd: netd, editor: editor)
        handoff = HandoffModel(service: environment.handoff, editor: editor)
        repos = ReposModel(service: environment.repos)
        tools = ToolsModel(service: environment.tools, editor: editor)
        migration = MigrationModel(service: environment.migration)
        keys = KeysModel(service: environment.keys)
        settings = SettingsModel(
            editor: editor, helperSetup: environment.helperSetup, agent: environment.netdAgent, preferences: environment.preferences,
            bundled: environment.bundled, environment: environment.environment, networkDatabase: environment.networkDatabase
        )

        sandbox = SandboxModel(
            service: environment.sandbox, editor: editor, helperSetup: environment.helperSetup, bundled: environment.bundled,
            environment: environment.environment
        )

        handoff.onHandedOff = { [weak self] in await self?.repos.refresh() }
        settings.onSetupChanged = { [weak self] in await self?.setupChanged() }
    }

    /// Connects to netd (asks need a listener for as long as the app runs) and reads the slow state once.
    public func start() {
        guard !started else { return }
        started = true
        netd.start()
        Task {
            await settings.refresh()
            await firewall.refreshStatus()
            await overview.refresh()
            await sandbox.refresh()
        }
    }

    public func stop() {
        netd.stop()
        rules.stopLearning()
        pollTask?.cancel()
        pollTask = nil
        started = false
    }

    // MARK: Navigation and visibility

    /// Sidebar pages: all of them in expert mode, `Screen.simple` otherwise.
    public var screens: [Screen] {
        settings.preferences.expertMode ? Screen.allCases : Screen.simple
    }

    /// Opens `screen`; a page hidden outside expert mode opens the overview instead, where the simple window
    /// offers the same choice (the protection level for the firewall steps).
    public func select(_ screen: Screen) {
        let target = screens.contains(screen) ? screen : .overview
        selection = target
        Task { await refreshOnShow(target) }
    }

    public func setShowInDock(_ on: Bool) {
        settings.setShowInDock(on)
    }

    public func setExpertMode(_ on: Bool) {
        settings.setExpertMode(on)
        if !screens.contains(selection) { select(.overview) }
    }

    public func setVisible(_ surface: Surface, _ visible: Bool) {
        if visible { visibleSurfaces.insert(surface) } else { visibleSurfaces.remove(surface) }
        updatePolling()
        if visible && surface == .window { Task { await refreshOnShow(selection) } }
    }

    public var isPolling: Bool { pollTask != nil }

    /// Snapshots every `refreshInterval` while the window or the menu is visible; nothing runs otherwise
    /// (the netd subscription is push, not polling, and keeps running for the asks and the menu bar state).
    func updatePolling() {
        if visibleSurfaces.isEmpty {
            pollTask?.cancel()
            pollTask = nil
        } else if pollTask == nil {
            pollTask = Task { [weak self] in
                while !Task.isCancelled {
                    guard let self else { return }
                    await self.tick()
                    let interval = self.settings.preferences.refreshInterval
                    try? await self.environment.clock.sleep(interval)
                }
            }
        }
    }

    func tick() async {
        editor.reloadIfChanged()
        await processes.refresh()
        guard visibleSurfaces.contains(.window) else { return }
        switch selection {
        case .network: await network.refreshSockets()
        case .activity: await activity.refresh()
        case .overview: await overview.refreshIfStale()
        case .sandbox: await sandbox.refresh()
        default: break
        }
    }

    func refreshOnShow(_ screen: Screen) async {
        editor.reloadIfChanged()
        switch screen {
        case .overview: await overview.refreshIfStale()
        case .sandbox:
            await sandbox.refresh()
            await repos.refresh()
        case .activity: await activity.refresh()
        case .processes: await processes.refresh()
        case .network: await network.refreshSockets()
        case .firewall: await firewall.refreshStatus()
        case .rules: rules.refreshPlan()
        case .tools: break
        case .handoff: await repos.refresh()
        case .migration: await keys.refresh()
        case .settings: await settings.refresh()
        }
    }

    func setupChanged() async {
        netd.retryNow()
        await firewall.refreshStatus()
        await overview.refresh()
    }

    // MARK: Hand-off entry points (folder picker, drops on the window and the menu)

    /// Takes the first dropped folder, switches to the hand-off page and checks it. Returns whether one was taken.
    @discardableResult
    public func handOff(paths: [String]) -> Bool {
        guard let folder = paths.first(where: Self.isDirectory) else { return false }
        selection = .handoff
        Task {
            await handoff.select(folder)
            await repos.refresh()
        }
        return true
    }

    static func isDirectory(_ path: String) -> Bool {
        var isDirectory: ObjCBool = false
        return FileManager.default.fileExists(atPath: path, isDirectory: &isDirectory) && isDirectory.boolValue
    }

    // MARK: Menu bar

    /// The status item's symbol; cheap and independent of the connection records, so the icon does not redraw per record.
    public var menuBarSymbol: String {
        MenuBarSummary.state(
            mode: editor.config.network.mode, panicActive: firewall.panicActive, netdRunning: netd.isConnected,
            pendingAsks: asks.pending.count
        ).symbolName
    }

    public var menuBar: MenuBarSummary {
        MenuBarSummary(
            mode: editor.config.network.mode, panicActive: firewall.panicActive, netdRunning: netd.isConnected,
            snapshot: processes.snapshot, records: netd.records, pendingAsks: asks.pending.count, now: environment.clock.now(),
            protection: firewall.protection, pendingHosts: asks.pending.map(\.host)
        )
    }
}

/// What the menu bar icon and its window show.
public struct MenuBarSummary: Sendable, Equatable {
    public var symbolName: String
    public var stateTitle: String
    public var sessions: Int
    public var processes: Int
    public var deniedLastHour: Int
    public var pendingAsks: Int
    /// Hosts of the waiting asks, oldest first, each once.
    public var pendingHosts: [String]
    public var netdRunning: Bool
    public var mode: FirewallMode
    public var panicActive: Bool
    /// The simple window's level, `nil` for a combination only expert mode sets.
    public var protection: ProtectionLevel?
    /// Hosts denied in the last hour, most recent first (at most `recentLimit`).
    public var recentDenied: [DeniedHost]

    public static let recentLimit = 5

    public init(
        mode: FirewallMode, panicActive: Bool, netdRunning: Bool, snapshot: ProcessSnapshot?, records: [ConnectionRecord],
        pendingAsks: Int, now: Date, protection: ProtectionLevel? = nil, pendingHosts: [String] = []
    ) {
        (symbolName, stateTitle) = Self.state(mode: mode, panicActive: panicActive, netdRunning: netdRunning, pendingAsks: pendingAsks)
        sessions = snapshot?.sessions.count ?? 0
        processes = snapshot?.processes.count ?? 0
        self.pendingAsks = pendingAsks
        var seen: Set<String> = []
        self.pendingHosts = pendingHosts.filter { seen.insert($0).inserted }
        self.netdRunning = netdRunning
        self.mode = mode
        self.panicActive = panicActive
        self.protection = protection

        let since = now.addingTimeInterval(-3600)
        let denied = records.filter { $0.decision.blocked && $0.timestamp >= since }
        deniedLastHour = denied.count
        var hosts: [String: DeniedHost] = [:]
        for record in denied {
            var entry = hosts[record.host] ?? DeniedHost(host: record.host, count: 0, lastSeen: record.timestamp)
            entry.count += 1
            entry.lastSeen = max(entry.lastSeen, record.timestamp)
            hosts[record.host] = entry
        }
        recentDenied = Array(hosts.values.sorted { ($0.lastSeen, $1.host) > ($1.lastSeen, $0.host) }.prefix(Self.recentLimit))
    }

    /// netd carries the sandbox's web and DNS in this mode, but it is not running.
    public var netdMissing: Bool { mode.needsNetd && !netdRunning }

    /// The line next to the title of the menu bar window: waiting asks, an emergency stop, else level and sessions.
    public var statusText: String {
        if pendingAsks > 0 { return "\(pendingAsks) waiting" }
        if panicActive { return "Emergency stop" }
        let level = protection?.statusWord ?? mode.displayName
        let count = switch sessions {
        case 0: "no sessions"
        case 1: "1 session"
        default: "\(sessions) sessions"
        }
        return "\(level) · \(count)"
    }

    /// The dot before `statusText`.
    public var statusTint: Tint {
        if panicActive { return .red }
        if pendingAsks > 0 || netdMissing { return .orange }
        return mode == .off ? .gray : .green
    }

    /// The sentence under the level buttons.
    public var explanation: String {
        if panicActive { return "Emergency stop: the sandbox has no network. Choose a level to end it." }
        return protection?.explanation ?? mode.explanation
    }

    /// Symbol and title, in priority order: blocked, waiting asks, netd missing where it carries the web, then the mode.
    public static func state(mode: FirewallMode, panicActive: Bool, netdRunning: Bool, pendingAsks: Int) -> (symbolName: String, title: String) {
        if panicActive || mode == .blocked {
            return ("xmark.shield.fill", panicActive ? "Panic: sandbox blocked" : "Firewall: blocked")
        }
        if pendingAsks > 0 { return ("exclamationmark.shield.fill", "Waiting for your answer") }
        if mode.needsNetd && !netdRunning { return ("exclamationmark.triangle", "\(mode.displayName), but netd is not running") }
        switch mode {
        case .off: return ("shield.slash", "Firewall off")
        case .open: return ("shield.lefthalf.filled", "Firewall: open")
        case .watch: return ("eye", "Firewall: watch")
        case .proxyOnly, .blocked: return ("checkmark.shield.fill", "Firewall: proxy only")
        }
    }
}

public struct DeniedHost: Identifiable, Sendable, Equatable {
    public var host: String
    public var count: Int
    public var lastSeen: Date

    public var id: String { host }
}
