import Foundation
import SandvaultCore
import SandvaultEnforce
import SandvaultNet
import SandvaultObserve
import SandvaultWorkflow

// Seams the view models depend on. Each has a live adapter over the phase 1/2 modules (below) and a fake in tests,
// so no model ever needs a Mac, sudo or a live netd socket.

public protocol ProcessSource: Sendable {
    func snapshot() async throws -> ProcessSnapshot
}

public protocol ProcessControlling: Sendable {
    func terminate(pid: Int32, force: Bool) async throws -> ControlReport
    func terminateSession(_ idOrPrefix: String, force: Bool) async throws -> ControlReport
    func terminateAll() async throws -> ControlReport
    func throttle(pid: Int32, nice: Int?, background: Bool) async throws -> ControlReport
}

public protocol ConnectionSource: Sendable {
    func connections() async throws -> [SandboxConnection]
    func traffic(pids: Set<Int32>?) async throws -> [ProcessTraffic]
}

public protocol ViolationSource: Sendable {
    func stream() -> AsyncThrowingStream<SandboxViolation, Error>
}

/// The root helper as the app uses it (`HelperPolicyApplier`).
public protocol PolicyControl: Sendable {
    func applyFirewall(_ state: AppliedState, releasingPanic: Bool) async throws -> HelperResult
    func applyProfile(_ state: AppliedState) async throws -> HelperResult
    func resetProfile() async throws -> HelperResult
    func disableFirewall() async throws -> HelperResult
    func panic(_ state: AppliedState?) async throws -> HelperResult
    func status() async throws -> HelperStatus
}

/// Doctor checks of one module, in `svctl doctor` order.
public struct CheckSection: Sendable, Equatable, Identifiable {
    public var id: String
    public var title: String
    public var checks: [Check]

    public init(id: String, title: String, checks: [Check]) {
        self.id = id
        self.title = title
        self.checks = checks
    }
}

/// The three `CheckProvider`s (Observe, Enforce, Net). Enforce and Net read the config, so it is passed per call.
public protocol DoctorSource: Sendable {
    func sections(config: AppConfig) async -> [CheckSection]
}

public protocol StatusSource: Sendable {
    func summary(firewallMode: FirewallMode, checks: [Check]) async -> StatusSummary
}

public protocol ProfileSource: Sendable {
    func plan(for settings: SandboxSettings) throws -> ProfilePlan
}

public protocol SandboxUIDSource: Sendable {
    func sandboxUID() async throws -> UInt32
}

/// One connection to netd's control socket; `ControlClient` in production.
public protocol NetdClient: AnyObject, Sendable {
    var events: AsyncStream<ControlEvent> { get }
    func status() async throws -> NetdStatus
    func subscribe(_ topics: [ControlTopic]) async throws
    func answer(_ answer: AskAnswer) async throws
    func pendingAsks() async throws -> [AskRequest]
    func recent(limit: Int) async throws -> [ConnectionRecord]
    func reloadConfig() async throws
    func close()
}

public protocol NetdConnector: Sendable {
    func connect() async throws -> any NetdClient
}

/// The netd LaunchAgent (`NetdLaunchAgent`).
public protocol NetdAgentControl: Sendable {
    var platformSupported: Bool { get }
    func install(executable: String) async throws
    func uninstall() async throws
    func restart() async throws
    func status() async throws -> NetdLaunchAgent.Status
}

/// Installing the root helper needs an administrator password (D27).
public protocol HelperInstalling: Sendable {
    var isInstalled: Bool { get }
    func install(source: String, user: String) async throws -> HelperResult
    func uninstall(binary: String, user: String) async throws -> HelperResult
}

public struct CAStatus: Sendable, Equatable {
    public var exists: Bool
    public var fingerprint: String?
    public var notValidAfter: Date?
    /// State of the copy in the shared workspace; `nil` when it cannot be read (no workspace).
    public var published: CAPublisher.State?

    public init(exists: Bool, fingerprint: String? = nil, notValidAfter: Date? = nil, published: CAPublisher.State? = nil) {
        self.exists = exists
        self.fingerprint = fingerprint
        self.notValidAfter = notValidAfter
        self.published = published
    }

    public static let none = CAStatus(exists: false)
}

/// The inspection CA and the sandbox's `.zshenv` block, as `svctl proxy inspection on|off` handles them.
public protocol CAControl: Sendable {
    func status() -> CAStatus
    /// Creates the CA when needed and publishes it with a bundle into the shared workspace.
    func prepareInspection() async throws -> CAStatus
    func syncSandboxEnvironment(_ policy: NetworkPolicy) throws
}

/// `svctl`, `svctl-helper` and `sandvault-netd` inside the app bundle (`Contents/MacOS`); `nil` when missing.
public struct BundledTools: Sendable, Equatable {
    public var svctl: String?
    public var helper: String?
    public var netd: String?

    public init(svctl: String? = nil, helper: String? = nil, netd: String? = nil) {
        self.svctl = svctl
        self.helper = helper
        self.netd = netd
    }
}

/// Time as the models see it; tests replace both.
public struct AppClock: Sendable {
    public var now: @Sendable () -> Date
    public var sleep: @Sendable (Double) async throws -> Void

    public init(now: @escaping @Sendable () -> Date, sleep: @escaping @Sendable (Double) async throws -> Void) {
        self.now = now
        self.sleep = sleep
    }

    public static let live = AppClock(now: { Date() }, sleep: { seconds in
        try await Task.sleep(nanoseconds: UInt64(max(0, seconds) * 1_000_000_000))
    })
}

/// App-only settings (everything shared with svctl lives in config.json).
public struct AppPreferences: Codable, Sendable, Equatable {
    /// Seconds between process and socket snapshots while a window or the menu is open.
    public var refreshInterval: Double
    /// Shows every screen; off, the window has only Overview, Sandbox, Activity, Repos & Hand-off and Settings.
    public var expertMode: Bool
    /// An icon in the Dock (with a menu to start sessions) besides the menu bar item.
    public var showInDock: Bool

    public init(refreshInterval: Double = AppModelInfo.refreshInterval, expertMode: Bool = false, showInDock: Bool = true) {
        self.refreshInterval = refreshInterval
        self.expertMode = expertMode
        self.showInDock = showInDock
    }

    /// Missing keys keep their defaults, so preferences saved by an older version survive.
    public init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        refreshInterval = try container.decodeIfPresent(Double.self, forKey: .refreshInterval) ?? AppModelInfo.refreshInterval
        expertMode = try container.decodeIfPresent(Bool.self, forKey: .expertMode) ?? false
        showInDock = try container.decodeIfPresent(Bool.self, forKey: .showInDock) ?? true
    }

    public static let refreshRange: ClosedRange<Double> = 1...30
}

public protocol PreferencesStore: Sendable {
    func load() -> AppPreferences
    func save(_ preferences: AppPreferences)
}

public struct UserDefaultsPreferences: PreferencesStore {
    public var key: String

    public init(key: String = "preferences") {
        self.key = key
    }

    public func load() -> AppPreferences {
        guard let data = UserDefaults.standard.data(forKey: key),
              let preferences = try? JSONDecoder().decode(AppPreferences.self, from: data)
        else { return AppPreferences() }
        return preferences
    }

    public func save(_ preferences: AppPreferences) {
        if let data = try? JSONEncoder().encode(preferences) { UserDefaults.standard.set(data, forKey: key) }
    }
}

// MARK: - Composition root

/// Everything the models need, built once. `live` wires the real factories; tests pass fakes.
public struct AppEnvironment: Sendable {
    public var environment: SandvaultEnvironment
    public var paths: AppPaths
    public var runner: CommandRunner
    public var configStore: ConfigStore
    public var bundled: BundledTools
    public var clock: AppClock
    public var preferences: PreferencesStore

    public var processes: ProcessSource
    public var processControl: ProcessControlling
    public var connections: ConnectionSource
    public var violations: ViolationSource
    public var doctor: DoctorSource
    public var status: StatusSource

    public var policy: PolicyControl
    public var profiles: ProfileSource
    public var sandboxUID: SandboxUIDSource
    public var localPorts: LocalPortSource
    public var helperSetup: HelperInstalling

    public var netd: NetdConnector
    public var netdAgent: NetdAgentControl
    public var ca: CAControl

    public var handoff: HandoffService
    public var repos: RepoService
    public var tools: ToolService
    public var migration: MigrationService
    public var keys: KeyService
    public var sandbox: SandboxService
    /// The offline address-to-network table netd reads for asks (D39).
    public var networkDatabase: NetworkDatabaseService

    public init(
        environment: SandvaultEnvironment, paths: AppPaths, runner: CommandRunner, configStore: ConfigStore,
        bundled: BundledTools, clock: AppClock, preferences: PreferencesStore,
        processes: ProcessSource, processControl: ProcessControlling, connections: ConnectionSource,
        violations: ViolationSource, doctor: DoctorSource, status: StatusSource,
        policy: PolicyControl, profiles: ProfileSource, sandboxUID: SandboxUIDSource, localPorts: LocalPortSource,
        helperSetup: HelperInstalling, netd: NetdConnector, netdAgent: NetdAgentControl, ca: CAControl,
        handoff: HandoffService, repos: RepoService, tools: ToolService, migration: MigrationService, keys: KeyService,
        sandbox: SandboxService, networkDatabase: NetworkDatabaseService
    ) {
        self.environment = environment
        self.paths = paths
        self.runner = runner
        self.configStore = configStore
        self.bundled = bundled
        self.clock = clock
        self.preferences = preferences
        self.processes = processes
        self.processControl = processControl
        self.connections = connections
        self.violations = violations
        self.doctor = doctor
        self.status = status
        self.policy = policy
        self.profiles = profiles
        self.sandboxUID = sandboxUID
        self.localPorts = localPorts
        self.helperSetup = helperSetup
        self.netd = netd
        self.netdAgent = netdAgent
        self.ca = ca
        self.handoff = handoff
        self.repos = repos
        self.tools = tools
        self.migration = migration
        self.keys = keys
        self.sandbox = sandbox
        self.networkDatabase = networkDatabase
    }

    /// The real thing: the factories of Observe, Enforce, Net and Workflow over one `ProcessCommandRunner`.
    public static func live(
        environment: SandvaultEnvironment = .current(),
        bundled: BundledTools = BundledTools(),
        runner: CommandRunner = ProcessCommandRunner(),
        preferences: PreferencesStore = UserDefaultsPreferences()
    ) -> AppEnvironment {
        let paths = AppPaths(environment: environment)
        let store = ConfigStore(paths: paths)
        return AppEnvironment(
            environment: environment, paths: paths, runner: runner, configStore: store, bundled: bundled, clock: .live,
            preferences: preferences,
            processes: ProcessMonitor(environment: environment, runner: runner),
            processControl: ProcessController(environment: environment, runner: runner),
            connections: ConnectionMonitor(environment: environment, runner: runner),
            violations: ViolationMonitor(environment: environment, runner: runner),
            doctor: LiveDoctor(environment: environment, runner: runner),
            status: LiveStatus(environment: environment, runner: runner),
            policy: HelperPolicyApplier(runner: runner),
            profiles: ProfileInspector(environment: environment),
            sandboxUID: LiveSandboxUID(environment: environment, runner: runner),
            localPorts: Observe.makeLocalPortSource(environment: environment, runner: runner),
            helperSetup: AdministratorHelperInstaller(runner: runner),
            netd: SocketNetdConnector(socketPath: paths.effectiveControlSocket),
            netdAgent: NetdLaunchAgent(paths: paths, runner: runner),
            ca: LiveCA(paths: paths, runner: runner),
            handoff: Workflow.makeHandoffService(environment: environment, runner: runner, configStore: store),
            repos: Workflow.makeRepoService(environment: environment, runner: runner, configStore: store),
            tools: Workflow.makeToolService(environment: environment, runner: runner, configStore: store),
            migration: Workflow.makeMigrationService(environment: environment, runner: runner),
            keys: Workflow.makeKeyService(environment: environment, runner: runner),
            sandbox: Workflow.makeSandboxService(environment: environment, runner: runner),
            networkDatabase: NetworkDatabaseStore(path: paths.networkDatabase, runner: runner)
        )
    }
}

// MARK: - Live adapters

extension ProcessMonitor: ProcessSource {}
extension ProcessController: ProcessControlling {}
extension ConnectionMonitor: ConnectionSource {}
extension ViolationMonitor: ViolationSource {}
extension HelperPolicyApplier: PolicyControl {}
extension ProfileInspector: ProfileSource {}
extension NetdLaunchAgent: NetdAgentControl {}
extension ControlClient: NetdClient {}

public struct SocketNetdConnector: NetdConnector {
    public var socketPath: String

    public init(socketPath: String) {
        self.socketPath = socketPath
    }

    public func connect() async throws -> any NetdClient {
        try await ControlClient.connect(socketPath: socketPath)
    }
}

struct LiveDoctor: DoctorSource {
    var environment: SandvaultEnvironment
    var runner: CommandRunner

    func sections(config: AppConfig) async -> [CheckSection] {
        async let observe = Observe.makeCheckProvider(environment: environment, runner: runner).checks()
        async let enforce = Enforce.makeCheckProvider(environment: environment, runner: runner, config: config).checks()
        async let net = Net.makeCheckProvider(environment: environment, runner: runner, config: config).checks()
        return [
            CheckSection(id: "sandvault", title: "Sandvault", checks: await observe),
            CheckSection(id: "enforce", title: "Enforcement", checks: await enforce),
            CheckSection(id: "network", title: "Network", checks: await net),
        ]
    }
}

struct LiveStatus: StatusSource {
    var environment: SandvaultEnvironment
    var runner: CommandRunner

    func summary(firewallMode: FirewallMode, checks: [Check]) async -> StatusSummary {
        await StatusSummary.collect(environment: environment, runner: runner, firewallMode: firewallMode, checks: checks)
    }
}

struct LiveSandboxUID: SandboxUIDSource {
    var environment: SandvaultEnvironment
    var runner: CommandRunner

    func sandboxUID() async throws -> UInt32 {
        try await SandboxAccount.resolveUID(environment: environment, runner: runner)
    }
}

struct LiveCA: CAControl {
    var paths: AppPaths
    var runner: CommandRunner

    func status() -> CAStatus {
        guard let ca = try? CAStore(paths: paths).load() else { return .none }
        let published = workspace().flatMap { try? CAPublisher(paths: paths, runner: runner, shared: $0).state(of: ca) }
        return CAStatus(exists: true, fingerprint: try? ca.fingerprint, notValidAfter: ca.notValidAfter, published: published)
    }

    func prepareInspection() async throws -> CAStatus {
        let (ca, _) = try CAStore(paths: paths).loadOrCreate(hostUser: paths.environment.hostUser)
        guard let shared = workspace() else {
            throw SandvaultError.notInstalled("shared workspace \(paths.environment.sharedWorkspace) (run `sv` once to create it)")
        }
        _ = try await CAPublisher(paths: paths, runner: runner, shared: shared).publish(ca)
        return status()
    }

    func syncSandboxEnvironment(_ policy: NetworkPolicy) throws {
        guard let shared = workspace() else { return }
        _ = try SandboxEnvironmentBlock.apply(policy: policy, paths: paths, shared: shared)
    }

    /// The shared workspace, only when it exists (nothing is written into a missing one).
    private func workspace() -> SharedFiles? {
        var isDirectory: ObjCBool = false
        let root = paths.environment.sharedWorkspace
        guard FileManager.default.fileExists(atPath: root, isDirectory: &isDirectory), isDirectory.boolValue else { return nil }
        return SharedFiles(root: root)
    }
}
