import Foundation
import SandvaultCore
import SandvaultEnforce
import SandvaultNet
import SandvaultObserve
@testable import SandvaultAppModel

/// Thread-safe box for fakes.
final class Locked<Value>: @unchecked Sendable {
    private let lock = NSLock()
    private var value: Value

    init(_ value: Value) {
        self.value = value
    }

    func get() -> Value { lock.withLock { value } }
    func set(_ newValue: Value) { lock.withLock { value = newValue } }
    func mutate<T>(_ body: (inout Value) -> T) -> T { lock.withLock { body(&value) } }
}

/// Manual time: `now` moves only when a test advances it; `sleep` records the delay and returns at once.
final class TestClock: @unchecked Sendable {
    let current = Locked(Date(timeIntervalSince1970: 1_800_000_000))
    let sleeps = Locked<[Double]>([])

    var clock: AppClock {
        AppClock(
            now: { [current] in current.get() },
            sleep: { [sleeps] seconds in
                sleeps.mutate { $0.append(seconds) }
                try await Task.sleep(nanoseconds: 1_000_000)
            }
        )
    }

    func advance(_ seconds: Double) {
        current.mutate { $0 = $0.addingTimeInterval(seconds) }
    }
}

// MARK: - Observe

final class FakeProcesses: ProcessSource, ProcessControlling, @unchecked Sendable {
    let snapshotResult = Locked<Result<ProcessSnapshot, SandvaultError>>(.success(ProcessSnapshot(processes: [], sessions: [], helpers: [], environmentReadable: true)))
    let snapshotCalls = Locked(0)
    let actions = Locked<[String]>([])
    let report = Locked<ControlReport?>(nil)

    func snapshot() async throws -> ProcessSnapshot {
        snapshotCalls.mutate { $0 += 1 }
        return try snapshotResult.get().get()
    }

    func terminate(pid: Int32, force: Bool) async throws -> ControlReport {
        record("terminate \(pid) force=\(force)", default: ControlReport(action: force ? "kill" : "terminate", targets: [pid], steps: []))
    }

    func terminateSession(_ idOrPrefix: String, force: Bool) async throws -> ControlReport {
        record("session \(idOrPrefix)", default: ControlReport(action: "terminate-session", targets: [10, 11], steps: []))
    }

    func terminateAll() async throws -> ControlReport {
        record("all", default: ControlReport(action: "terminate-all", targets: [10, 11, 12], steps: []))
    }

    func throttle(pid: Int32, nice: Int?, background: Bool) async throws -> ControlReport {
        record("throttle \(pid) nice=\(nice.map(String.init) ?? "-") background=\(background)", default: ControlReport(action: "throttle", targets: [pid], steps: []))
    }

    private func record(_ action: String, default fallback: ControlReport) -> ControlReport {
        actions.mutate { $0.append(action) }
        return report.get() ?? fallback
    }
}

final class FakeConnections: ConnectionSource, @unchecked Sendable {
    let sockets = Locked<[SandboxConnection]>([])
    let calls = Locked(0)

    func connections() async throws -> [SandboxConnection] {
        calls.mutate { $0 += 1 }
        return sockets.get()
    }

    func traffic(pids: Set<Int32>?) async throws -> [ProcessTraffic] { [] }
}

final class FakeViolations: ViolationSource, @unchecked Sendable {
    let continuation = Locked<AsyncThrowingStream<SandboxViolation, Error>.Continuation?>(nil)
    let terminated = Locked(false)

    func stream() -> AsyncThrowingStream<SandboxViolation, Error> {
        let (stream, continuation) = AsyncThrowingStream.makeStream(of: SandboxViolation.self)
        continuation.onTermination = { [terminated] _ in terminated.set(true) }
        self.continuation.set(continuation)
        return stream
    }
}

struct FakeDoctor: DoctorSource {
    var checks: [Check]

    func sections(config: AppConfig) async -> [CheckSection] {
        [CheckSection(id: "all", title: "All", checks: checks)]
    }
}

struct FakeStatus: StatusSource {
    func summary(firewallMode: FirewallMode, checks: [Check]) async -> StatusSummary {
        StatusSummary(
            installation: checks.first { $0.id == "sv.installed" }, sessions: [], processCount: 0, listeningPorts: [],
            firewallMode: firewallMode, worstCheck: CheckReport(checks: checks).worst, problems: checks.filter { $0.state >= .warning },
            errors: []
        )
    }
}

struct FakeUID: SandboxUIDSource {
    func sandboxUID() async throws -> UInt32 { 601 }
}

struct FakePorts: LocalPortSource {
    var ports: [UInt16] = [3000]
    func allowedLocalPorts() async throws -> [UInt16] { ports }
}

// MARK: - Enforce

final class FakePolicy: PolicyControl, @unchecked Sendable {
    let calls = Locked<[String]>([])
    let states = Locked<[AppliedState]>([])
    let result = Locked(HelperResult(ok: true, message: "done"))
    let helperStatus = Locked(HelperStatus())

    func applyFirewall(_ state: AppliedState, releasingPanic: Bool) async throws -> HelperResult {
        log("applyFirewall releasingPanic=\(releasingPanic)", state)
    }

    func applyProfile(_ state: AppliedState) async throws -> HelperResult { log("applyProfile", state) }
    func resetProfile() async throws -> HelperResult { log("resetProfile", nil) }
    func disableFirewall() async throws -> HelperResult { log("disableFirewall", nil) }
    func panic(_ state: AppliedState?) async throws -> HelperResult { log("panic", state) }

    func status() async throws -> HelperStatus {
        calls.mutate { $0.append("status") }
        return helperStatus.get()
    }

    private func log(_ call: String, _ state: AppliedState?) -> HelperResult {
        calls.mutate { $0.append(call) }
        if let state { states.mutate { $0.append(state) } }
        return result.get()
    }
}

final class FakeHelperSetup: HelperInstalling, @unchecked Sendable {
    let installed = Locked(false)
    let calls = Locked<[String]>([])

    var isInstalled: Bool { installed.get() }

    func install(source: String, user: String) async throws -> HelperResult {
        calls.mutate { $0.append("install \(source) \(user)") }
        installed.set(true)
        return HelperResult(ok: true, message: "installed")
    }

    func uninstall(binary: String, user: String) async throws -> HelperResult {
        calls.mutate { $0.append("uninstall \(binary) \(user)") }
        installed.set(false)
        return HelperResult(ok: true, message: "uninstalled")
    }
}

// MARK: - Net

final class FakeNetdClient: NetdClient, @unchecked Sendable {
    let events: AsyncStream<ControlEvent>
    let sink: AsyncStream<ControlEvent>.Continuation
    let subscriptions = Locked<[[ControlTopic]]>([])
    let answers = Locked<[AskAnswer]>([])
    let reloads: Locked<Int>
    let closed = Locked(false)
    let pending: [AskRequest]
    let recentRecords: [ConnectionRecord]

    init(pending: [AskRequest] = [], recent: [ConnectionRecord] = [], reloads: Locked<Int> = Locked(0)) {
        (events, sink) = AsyncStream.makeStream(of: ControlEvent.self)
        self.pending = pending
        recentRecords = recent
        self.reloads = reloads
    }

    func status() async throws -> NetdStatus { NetdStatus(startedAt: Date(timeIntervalSince1970: 0), ports: ProxyPorts(), mode: .proxyOnly) }
    func subscribe(_ topics: [ControlTopic]) async throws { subscriptions.mutate { $0.append(topics) } }
    func answer(_ answer: AskAnswer) async throws { answers.mutate { $0.append(answer) } }
    func pendingAsks() async throws -> [AskRequest] { pending }
    func recent(limit: Int) async throws -> [ConnectionRecord] { Array(recentRecords.suffix(limit)) }
    func reloadConfig() async throws { reloads.mutate { $0 += 1 } }

    func close() {
        closed.set(true)
        sink.finish()
    }

    /// netd pushes an event.
    func push(_ event: ControlEvent) { sink.yield(event) }
}

/// Hands out queued outcomes first, then a fresh client per connection, or refuses when `running` is false.
final class FakeNetdConnector: NetdConnector, @unchecked Sendable {
    enum Outcome {
        case refuse
        case client(FakeNetdClient)
    }

    let queue = Locked<[Outcome]>([])
    let running = Locked(true)
    let reloads = Locked(0)
    let connects = Locked(0)
    let clients = Locked<[FakeNetdClient]>([])

    func connect() async throws -> any NetdClient {
        connects.mutate { $0 += 1 }
        let next = queue.mutate { $0.isEmpty ? nil : $0.removeFirst() }
        switch next {
        case .refuse?:
            throw SandvaultError.notInstalled("sandvault-netd is not running (no control socket at /tmp/test.sock)")
        case .client(let client)?:
            clients.mutate { $0.append(client) }
            return client
        case nil:
            guard running.get() else { throw SandvaultError.notInstalled("sandvault-netd is not running (no control socket at /tmp/test.sock)") }
            let client = FakeNetdClient(reloads: reloads)
            clients.mutate { $0.append(client) }
            return client
        }
    }
}

final class FakeAgent: NetdAgentControl, @unchecked Sendable {
    let calls = Locked<[String]>([])
    /// Whether `status` reports an installed agent as loaded.
    let loadsOnInstall = Locked(false)
    var platformSupported: Bool { true }

    func install(executable: String) async throws { calls.mutate { $0.append("install \(executable)") } }
    func uninstall() async throws { calls.mutate { $0.append("uninstall") } }
    func restart() async throws { calls.mutate { $0.append("restart") } }

    func status() async throws -> NetdLaunchAgent.Status {
        var status = NetdLaunchAgent.parsePrint("")
        status.installed = calls.get().contains { $0.hasPrefix("install") }
        status.loaded = status.installed && loadsOnInstall.get()
        status.plistPath = "/Users/alice/Library/LaunchAgents/\(AppPaths.netdLabel).plist"
        return status
    }
}

final class FakeCA: CAControl, @unchecked Sendable {
    let state = Locked(CAStatus.none)
    let synced = Locked<[Bool]>([])

    func status() -> CAStatus { state.get() }

    func prepareInspection() async throws -> CAStatus {
        state.set(CAStatus(exists: true, fingerprint: "AB:CD", published: .current))
        return state.get()
    }

    func syncSandboxEnvironment(_ policy: NetworkPolicy) throws {
        synced.mutate { $0.append(policy.inspection.enabled) }
    }
}

// MARK: - Workflow

/// Every service of agent D; each call throws `notImplemented` unless a test sets a handler.
final class FakeWorkflow: HandoffService, RepoService, ToolService, MigrationService, KeyService, @unchecked Sendable {
    let readinessHandler = Locked<(@Sendable (String) throws -> ReadinessReport)?>(nil)
    let handOffHandler = Locked<(@Sendable (HandoffRequest) throws -> HandoffResult)?>(nil)
    let reposHandler = Locked<(@Sendable () throws -> [RepoStatus])?>(nil)
    let fetchHandler = Locked<(@Sendable (HandoffRecord) throws -> RepoStatus)?>(nil)
    let toolHandler = Locked<(@Sendable (String) throws -> ToolStatus)?>(nil)
    let grantHandler = Locked<(@Sendable (String, ToolGrantMethod) throws -> ToolGrant)?>(nil)
    let planHandler = Locked<(@Sendable ([MigrationItem]) throws -> MigrationPlan)?>(nil)
    let applyHandler = Locked<(@Sendable (MigrationPlan) throws -> [MigrationEntry])?>(nil)
    let keysValue = Locked<[AuthorizedKey]?>(nil)
    let requests = Locked<[HandoffRequest]>([])

    private func missing(_ what: String) -> SandvaultError { .notImplemented(what) }

    func readiness(of source: String) async throws -> ReadinessReport {
        guard let handler = readinessHandler.get() else { throw missing("Workflow.readiness") }
        return try handler(source)
    }

    func handOff(_ request: HandoffRequest) async throws -> HandoffResult {
        requests.mutate { $0.append(request) }
        guard let handler = handOffHandler.get() else { throw missing("Workflow.handOff") }
        return try handler(request)
    }

    func repositories() async throws -> [RepoStatus] {
        guard let handler = reposHandler.get() else { throw missing("Workflow.repositories") }
        return try handler()
    }

    func fetchBack(_ record: HandoffRecord) async throws -> RepoStatus {
        guard let handler = fetchHandler.get() else { throw missing("Workflow.fetchBack") }
        return try handler(record)
    }

    func status(of name: String) async throws -> ToolStatus {
        guard let handler = toolHandler.get() else { throw missing("Workflow.toolStatus") }
        return try handler(name)
    }

    func grant(_ name: String, method: ToolGrantMethod) async throws -> ToolGrant {
        guard let handler = grantHandler.get() else { throw missing("Workflow.grant") }
        return try handler(name, method)
    }

    func plan(_ items: [MigrationItem]) async throws -> MigrationPlan {
        guard let handler = planHandler.get() else { throw missing("Workflow.plan") }
        return try handler(items)
    }

    func apply(_ plan: MigrationPlan) async throws -> [MigrationEntry] {
        guard let handler = applyHandler.get() else { throw missing("Workflow.apply") }
        return try handler(plan)
    }

    func keys() async throws -> [AuthorizedKey] {
        guard let keys = keysValue.get() else { throw missing("Workflow.keys") }
        return keys
    }

    func add(name: String, publicKey: String) async throws -> AuthorizedKey {
        guard keysValue.get() != nil else { throw missing("Workflow.addKey") }
        let key = AuthorizedKey(name: name, type: "ssh-ed25519", fingerprint: "SHA256:test")
        keysValue.mutate { $0?.append(key) }
        return key
    }

    func remove(name: String) async throws {
        guard keysValue.get() != nil else { throw missing("Workflow.removeKey") }
        keysValue.mutate { $0?.removeAll { $0.name == name } }
    }
}

final class FakeSandbox: SandboxService, @unchecked Sendable {
    let current = Locked(SandboxState(installed: true, profile: true, home: true, workspace: true))
    let runs = Locked<[(command: SandboxCommand, terminal: TerminalApp, svOptions: [String], followUp: [[String]])]>([])
    let failure = Locked<Error?>(nil)

    func state() async -> SandboxState { current.get() }

    func run(_ command: SandboxCommand, terminal: TerminalApp, svOptions: [String], followUp: [[String]]) async throws -> SandboxLaunch {
        if let failure = failure.get() { throw failure }
        runs.mutate { $0.append((command, terminal, svOptions, followUp)) }
        return SandboxLaunch(command: "sv", launched: true)
    }
}

final class MemoryPreferences: PreferencesStore, @unchecked Sendable {
    let stored = Locked(AppPreferences())
    func load() -> AppPreferences { stored.get() }
    func save(_ preferences: AppPreferences) { stored.set(preferences) }
}

// MARK: - Assembly

/// One test's world: a temporary directory for config.json and the sandbox profile, and a fake for every seam.
struct TestWorld {
    let directory: URL
    let environment = SandvaultEnvironment(hostUser: "alice", hostHome: "/Users/alice")
    let clock = TestClock()
    let processes = FakeProcesses()
    let connections = FakeConnections()
    let violations = FakeViolations()
    let policy = FakePolicy()
    let helperSetup = FakeHelperSetup()
    let netd = FakeNetdConnector()
    let agent = FakeAgent()
    let ca = FakeCA()
    let workflow = FakeWorkflow()
    let sandbox = FakeSandbox()
    let preferences = MemoryPreferences()
    var checks: [Check] = []

    init(checks: [Check] = []) {
        directory = FileManager.default.temporaryDirectory.appendingPathComponent("appmodel-\(UUID().uuidString)")
        try? FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        self.checks = checks
    }

    var store: ConfigStore { ConfigStore(path: directory.appendingPathComponent("config.json").path) }
    var profilePath: String { directory.appendingPathComponent("sandbox.sb").path }

    var appEnvironment: AppEnvironment {
        AppEnvironment(
            environment: environment, paths: AppPaths(environment: environment), runner: FakeCommandRunner(), configStore: store,
            bundled: BundledTools(svctl: "/Applications/Sandvault Config.app/Contents/MacOS/svctl", helper: "/Applications/Sandvault Config.app/Contents/MacOS/svctl-helper", netd: "/Applications/Sandvault Config.app/Contents/MacOS/sandvault-netd"),
            clock: clock.clock, preferences: preferences,
            processes: processes, processControl: processes, connections: connections, violations: violations,
            doctor: FakeDoctor(checks: checks), status: FakeStatus(),
            policy: policy, profiles: ProfileInspector(profilePath: profilePath, recordPath: directory.appendingPathComponent("record.json").path),
            sandboxUID: FakeUID(), localPorts: FakePorts(), helperSetup: helperSetup,
            netd: netd, netdAgent: agent, ca: ca,
            handoff: workflow, repos: workflow, tools: workflow, migration: workflow, keys: workflow, sandbox: sandbox
        )
    }

    @MainActor func model() -> AppModel { AppModel(environment: appEnvironment) }

    func cleanUp() {
        try? FileManager.default.removeItem(at: directory)
    }
}

/// Polls `condition` on the main actor until it holds or two seconds pass.
@MainActor
func eventually(_ condition: () -> Bool) async -> Bool {
    for _ in 0..<2000 {
        if condition() { return true }
        try? await Task.sleep(nanoseconds: 1_000_000)
    }
    return condition()
}

func process(_ pid: Int32, ppid: Int32 = 1, command: String, session: String? = nil) -> SandboxProcess {
    SandboxProcess(pid: pid, ppid: ppid, user: "sandvault-alice", command: command, sessionID: session)
}

func record(_ host: String, _ decision: ConnectionDecision, port: UInt16? = 443, at time: Date, process: String? = "node") -> ConnectionRecord {
    ConnectionRecord(timestamp: time, kind: .transparentTLS, host: host, port: port, decision: decision, pid: 42, process: process, bytesIn: 100, bytesOut: 10)
}
