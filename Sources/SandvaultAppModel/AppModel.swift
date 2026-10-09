import Foundation
import Observation
import SandvaultCore
import SandvaultObserve

/// Pages of the main window, in sidebar order.
public enum Screen: String, CaseIterable, Identifiable, Hashable, Sendable {
    case overview, processes, network, firewall, rules, tools, handoff, migration, settings

    public var id: String { rawValue }

    public var title: String {
        switch self {
        case .overview: "Overview"
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
    public let firewall: FirewallModel
    public let rules: RulesModel
    public let asks: AsksModel
    public let handoff: HandoffModel
    public let repos: ReposModel
    public let tools: ToolsModel
    public let migration: MigrationModel
    public let keys: KeysModel
    public let settings: SettingsModel

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
            bundled: environment.bundled, environment: environment.environment
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

    public func select(_ screen: Screen) {
        selection = screen
        Task { await refreshOnShow(screen) }
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
        case .overview: await overview.refreshIfStale()
        default: break
        }
    }

    func refreshOnShow(_ screen: Screen) async {
        editor.reloadIfChanged()
        switch screen {
        case .overview: await overview.refreshIfStale()
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

    public var menuBar: MenuBarSummary {
        MenuBarSummary(
            mode: editor.config.network.mode, panicActive: firewall.panicActive, netdRunning: netd.isConnected,
            snapshot: processes.snapshot, records: netd.records, pendingAsks: asks.pending.count, now: environment.clock.now()
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
    public var netdRunning: Bool
    /// Hosts denied in the last hour, most recent first (at most `recentLimit`).
    public var recentDenied: [DeniedHost]

    public static let recentLimit = 5

    public init(
        mode: FirewallMode, panicActive: Bool, netdRunning: Bool, snapshot: ProcessSnapshot?, records: [ConnectionRecord],
        pendingAsks: Int, now: Date
    ) {
        if panicActive || mode == .blocked {
            (symbolName, stateTitle) = ("xmark.shield.fill", panicActive ? "Panic: sandbox blocked" : "Firewall: blocked")
        } else if pendingAsks > 0 {
            (symbolName, stateTitle) = ("exclamationmark.shield.fill", "Waiting for your answer")
        } else if mode == .proxyOnly && !netdRunning {
            (symbolName, stateTitle) = ("exclamationmark.triangle", "Proxy only, but netd is not running")
        } else if mode == .off {
            (symbolName, stateTitle) = ("shield.slash", "Firewall off")
        } else if mode == .open {
            (symbolName, stateTitle) = ("shield.lefthalf.filled", "Firewall: open")
        } else {
            (symbolName, stateTitle) = ("checkmark.shield.fill", "Firewall: proxy only")
        }
        sessions = snapshot?.sessions.count ?? 0
        processes = snapshot?.processes.count ?? 0
        self.pendingAsks = pendingAsks
        self.netdRunning = netdRunning

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
}

public struct DeniedHost: Identifiable, Sendable, Equatable {
    public var host: String
    public var count: Int
    public var lastSeen: Date

    public var id: String { host }
}
