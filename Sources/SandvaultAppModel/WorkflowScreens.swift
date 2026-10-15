import Foundation
import Observation
import SandvaultCore

/// Whether a workflow service exists in this build. `notImplemented` from a service is a state, not an error.
public enum Availability: Sendable, Equatable {
    case unknown
    case available
    case notAvailableYet(String)

    public var isAvailable: Bool { if case .notAvailableYet = self { false } else { true } }
}

/// Runs a workflow call and sorts its outcome into a value, "not available yet", or a message.
@MainActor
enum WorkflowCall {
    enum Outcome<Value> {
        case value(Value)
        case notAvailable(String)
        case failed(UserMessage)
    }

    static func run<Value>(_ action: String, _ body: () async throws -> Value) async -> Outcome<Value> {
        do {
            return .value(try await body())
        } catch SandvaultError.notImplemented(let what) {
            return .notAvailable("\(action) is not part of this build yet (\(what)).")
        } catch {
            return .failed(UserMessage(error: error, action: action))
        }
    }
}

// MARK: - Hand-off

/// Hand-off of a repository to an agent: readiness first, the button only when nothing blocks.
@MainActor @Observable
public final class HandoffModel {
    public private(set) var source: String?
    public private(set) var readiness: ReadinessReport?
    public private(set) var isChecking = false
    public private(set) var isHandingOff = false
    public private(set) var availability = Availability.unknown
    public private(set) var lastResult: HandoffResult?
    public var agent: AgentKind
    public var task = ""
    public var includeUncommitted = false
    public var deployKey = HandoffRequest.DeployKeyMode.none
    /// sv or a Docker Sandboxes VM (D47); change it with `choose(_:)` so the report follows.
    public private(set) var target = HandoffTarget.sandvault
    public var message: UserMessage?
    /// Called after a successful hand-off (the repos list refreshes).
    @ObservationIgnored public var onHandedOff: (@MainActor () async -> Void)?

    @ObservationIgnored private let service: HandoffService
    @ObservationIgnored private let editor: ConfigEditor
    @ObservationIgnored private let docker: DockerSandboxesModel?

    public init(service: HandoffService, editor: ConfigEditor, docker: DockerSandboxesModel? = nil) {
        self.service = service
        self.editor = editor
        self.docker = docker
        agent = editor.config.handoff.defaultAgent
    }

    public var terminal: TerminalApp { editor.config.handoff.terminal }
    /// The target picker shows only when `sbx` is installed.
    public var offersDocker: Bool { docker?.installed == true }
    public var agents: [AgentKind] { target == .dockerSandbox ? AgentKind.allCases.filter { $0.sbxAgent != nil } : AgentKind.allCases }

    public func choose(_ target: HandoffTarget) async {
        guard target != self.target else { return }
        self.target = target
        if !agents.contains(agent) { agent = agents.contains(editor.config.handoff.defaultAgent) ? editor.config.handoff.defaultAgent : .claude }
        readiness = nil
        await recheck()
    }

    /// A repository URL typed in: sv clones it in the sandbox, Docker Sandboxes get a clone in the clone folder first.
    public func select(url: String) async {
        let trimmed = url.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmed.isEmpty else { return }
        await select(trimmed)
    }
    public var blockers: [ReadinessFinding] { readiness?.findings.filter { $0.severity == .blocker } ?? [] }

    /// Selects a folder (picker or drop) and checks it.
    public func select(_ path: String) async {
        source = path
        readiness = nil
        lastResult = nil
        agent = editor.config.handoff.defaultAgent
        await recheck()
    }

    public func clear() {
        source = nil
        readiness = nil
        lastResult = nil
        task = ""
    }

    public func recheck() async {
        guard let source else { return }
        isChecking = true
        defer { isChecking = false }
        let target = self.target
        switch await WorkflowCall.run("Check the repository", { try await self.service.readiness(of: source, target: target) }) {
        case .value(let report):
            // A newer selection or target wins over a slow check of an older one.
            guard self.source == source, self.target == target else { return }
            readiness = report
            availability = .available
            message = nil
        case .notAvailable(let note):
            availability = .notAvailableYet(note)
        case .failed(let failure):
            message = failure
        }
    }

    /// Why the hand-off button is disabled, or `nil` when it is enabled.
    public var disabledReason: String? {
        if case .notAvailableYet = availability { return "Hand-off is not available in this build yet." }
        guard source != nil else { return "Choose or drop a repository folder." }
        if target == .dockerSandbox && agent.sbxAgent == nil { return "\(agent.displayName) does not run in Docker Sandboxes." }
        if isChecking { return "Checking the repository..." }
        if isHandingOff { return "Handing off..." }
        guard let readiness else { return "The repository has not been checked." }
        let count = readiness.findings.filter { $0.severity == .blocker }.count
        if count > 0 { return count == 1 ? "Resolve the blocker first." : "Resolve the \(count) blockers first." }
        return nil
    }

    public var canHandOff: Bool { disabledReason == nil }

    public func handOff() async {
        guard canHandOff, let source else { return }
        isHandingOff = true
        defer { isHandingOff = false }
        let settings = editor.config.handoff
        let trimmed = task.trimmingCharacters(in: .whitespacesAndNewlines)
        let docker = target == .dockerSandbox
        let request = HandoffRequest(
            source: source, agent: agent, task: trimmed.isEmpty ? nil : trimmed, includeUncommitted: !docker && includeUncommitted,
            terminal: settings.terminal, svOptions: docker ? [] : settings.svOptions, deployKey: docker ? .none : deployKey, target: target
        )
        switch await WorkflowCall.run("Hand off", { try await self.service.handOff(request) }) {
        case .value(let result):
            lastResult = result
            editor.reload()
            let place = docker ? " in a Linux VM" : ""
            message = result.launched
                ? .success("Handed off \(result.record.repoName) to \(agent.displayName)\(place)", detail: "Started in \(settings.terminal.displayName).")
                : UserMessage(kind: .warning, title: "Prepared \(result.record.repoName), but the terminal did not start", detail: result.command.joined(separator: " "))
            await onHandedOff?()
            if docker { await self.docker?.refresh() }
        case .notAvailable(let note):
            availability = .notAvailableYet(note)
        case .failed(let failure):
            message = failure
        }
    }
}

// MARK: - Repos

/// Repositories in the shared workspace and the way back.
@MainActor @Observable
public final class ReposModel {
    public private(set) var repositories: [RepoStatus] = []
    public private(set) var availability = Availability.unknown
    public private(set) var isLoading = false
    public private(set) var fetching: Set<String> = []
    public var message: UserMessage?

    @ObservationIgnored private let service: RepoService

    public init(service: RepoService) {
        self.service = service
    }

    public func refresh() async {
        isLoading = true
        defer { isLoading = false }
        switch await WorkflowCall.run("List repositories", { try await self.service.repositories() }) {
        case .value(let repositories):
            self.repositories = repositories
            availability = .available
        case .notAvailable(let note):
            availability = .notAvailableYet(note)
        case .failed(let failure):
            message = failure
        }
    }

    /// `git fetch sandvault` in the host repository the clone came from.
    public func fetchBack(_ repo: RepoStatus) async {
        guard let record = repo.record else {
            message = .info("\(repo.name) has no host repository", detail: "It was not handed off from this Mac, so there is nothing to fetch into.")
            return
        }
        fetching.insert(repo.id)
        defer { fetching.remove(repo.id) }
        switch await WorkflowCall.run("Fetch \(repo.name)", { try await self.service.fetchBack(record) }) {
        case .value(let updated):
            if let index = repositories.firstIndex(where: { $0.id == updated.id }) { repositories[index] = updated }
            let remote = record.dockerSandbox.map { "sandbox-" + $0 } ?? "sandvault"
            message = .success("Fetched \(repo.name) into \(record.hostPath)", detail: "Branches are under \(remote)/ in the host repository.")
        case .notAvailable(let note):
            availability = .notAvailableYet(note)
        case .failed(let failure):
            message = failure
        }
    }
}

// MARK: - Tools

/// Whether a host command works in the sandbox, and granting it.
@MainActor @Observable
public final class ToolsModel {
    public var query = ""
    public private(set) var status: ToolStatus?
    public private(set) var availability = Availability.unknown
    public private(set) var isBusy = false
    public var message: UserMessage?

    @ObservationIgnored private let service: ToolService
    @ObservationIgnored private let editor: ConfigEditor

    public init(service: ToolService, editor: ConfigEditor) {
        self.service = service
        self.editor = editor
    }

    public var grants: [ToolGrant] { editor.config.tools.sorted { $0.grantedAt > $1.grantedAt } }

    public func check() async {
        let name = query.trimmingCharacters(in: .whitespaces)
        guard !name.isEmpty else { return }
        isBusy = true
        defer { isBusy = false }
        switch await WorkflowCall.run("Check \(name)", { try await self.service.status(of: name) }) {
        case .value(let status):
            self.status = status
            availability = .available
            message = nil
        case .notAvailable(let note):
            availability = .notAvailableYet(note)
        case .failed(let failure):
            status = nil
            message = failure
        }
    }

    public func grant(_ method: ToolGrantMethod) async {
        guard let name = status?.name else { return }
        isBusy = true
        defer { isBusy = false }
        switch await WorkflowCall.run("Grant \(name)", { try await self.service.grant(name, method: method) }) {
        case .value(let grant):
            editor.reload()
            message = .success("Granted \(grant.name)", detail: method.displayName)
            status = (try? await service.status(of: name)) ?? status
        case .notAvailable(let note):
            availability = .notAvailableYet(note)
        case .failed(let failure):
            message = failure
        }
    }
}

// MARK: - Migration

/// Copying host configuration into `$SHARED_WORKSPACE/user`, always through a previewed plan.
@MainActor @Observable
public final class MigrationModel {
    public var selected: Set<MigrationItem> = Set(MigrationItem.allCases)
    public private(set) var plan: MigrationPlan?
    public private(set) var copied: [MigrationEntry]?
    public private(set) var availability = Availability.unknown
    public private(set) var isBusy = false
    public var message: UserMessage?

    @ObservationIgnored private let service: MigrationService

    public init(service: MigrationService) {
        self.service = service
    }

    public var blocked: [MigrationEntry] { plan?.entries.filter { $0.blockedReason != nil } ?? [] }
    public var copyable: [MigrationEntry] { plan?.copyable ?? [] }

    public func toggle(_ item: MigrationItem) {
        if selected.contains(item) { selected.remove(item) } else { selected.insert(item) }
        plan = nil
    }

    public func preview() async {
        let items = MigrationItem.allCases.filter(selected.contains)
        isBusy = true
        defer { isBusy = false }
        copied = nil
        switch await WorkflowCall.run("Preview the migration", { try await self.service.plan(items) }) {
        case .value(let plan):
            self.plan = plan
            availability = .available
            message = nil
        case .notAvailable(let note):
            availability = .notAvailableYet(note)
        case .failed(let failure):
            message = failure
        }
    }

    /// Copies the previewed plan; blocked entries are never copied (the service skips them as well).
    public func apply() async {
        guard let plan, !plan.copyable.isEmpty else { return }
        isBusy = true
        defer { isBusy = false }
        switch await WorkflowCall.run("Copy configuration", { try await self.service.apply(plan) }) {
        case .value(let entries):
            copied = entries
            message = .success("Copied \(entries.count) file\(entries.count == 1 ? "" : "s") into the shared workspace")
            self.plan = nil
        case .notAvailable(let note):
            availability = .notAvailableYet(note)
        case .failed(let failure):
            message = failure
        }
    }
}

// MARK: - Keys

/// Public keys in sv's `authorized_keys.d` (SSH into the sandbox).
@MainActor @Observable
public final class KeysModel {
    public private(set) var keys: [AuthorizedKey] = []
    public private(set) var availability = Availability.unknown
    public var message: UserMessage?

    @ObservationIgnored private let service: KeyService

    public init(service: KeyService) {
        self.service = service
    }

    public func refresh() async {
        switch await WorkflowCall.run("List keys", { try await self.service.keys() }) {
        case .value(let keys):
            self.keys = keys
            availability = .available
        case .notAvailable(let note):
            availability = .notAvailableYet(note)
        case .failed(let failure):
            message = failure
        }
    }

    @discardableResult
    public func add(name: String, publicKey: String) async -> Bool {
        let name = name.trimmingCharacters(in: .whitespaces)
        let key = publicKey.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !name.isEmpty, !key.isEmpty else {
            message = UserMessage(error: SandvaultError.invalidInput("name and public key are required"), action: "Add key")
            return false
        }
        switch await WorkflowCall.run("Add key", { try await self.service.add(name: name, publicKey: key) }) {
        case .value(let added):
            message = .success("Added \(added.name)", detail: added.fingerprint)
            await refresh()
            return true
        case .notAvailable(let note):
            availability = .notAvailableYet(note)
        case .failed(let failure):
            message = failure
        }
        return false
    }

    public func remove(_ key: AuthorizedKey) async {
        switch await WorkflowCall.run("Remove key", { try await self.service.remove(name: key.name) }) {
        case .value:
            message = .success("Removed \(key.name)")
            await refresh()
        case .notAvailable(let note):
            availability = .notAvailableYet(note)
        case .failed(let failure):
            message = failure
        }
    }
}
