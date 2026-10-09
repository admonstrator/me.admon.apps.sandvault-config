import Foundation
import Observation
import SandvaultCore
import SandvaultEnforce
import SandvaultObserve

/// Sandbox Rules & Learn screen: the rules in config.json, the profile plan (drift, diff), apply and reset,
/// and learn mode, which turns live sandbox violations into rule suggestions.
@MainActor @Observable
public final class RulesModel {
    public private(set) var plan: ProfilePlan?
    public private(set) var planError: UserMessage?
    public private(set) var isBusy = false
    public var message: UserMessage?

    public private(set) var isLearning = false
    /// Violations seen while learning, oldest first.
    public private(set) var observed: [SandboxViolation] = []
    public private(set) var learnError: UserMessage?
    /// Suggestions accepted or dismissed in this session.
    public private(set) var hiddenSuggestions: Set<String> = []
    /// Also learn from violations whose pid was not a sandbox process when seen.
    public var includeUnattributed = false

    public static let observedLimit = 5000

    @ObservationIgnored private let editor: ConfigEditor
    @ObservationIgnored private let profiles: ProfileSource
    @ObservationIgnored private let policy: PolicyControl
    @ObservationIgnored private let violations: ViolationSource
    @ObservationIgnored private let environment: SandvaultEnvironment
    @ObservationIgnored private var learnTask: Task<Void, Never>?

    public init(editor: ConfigEditor, profiles: ProfileSource, policy: PolicyControl, violations: ViolationSource, environment: SandvaultEnvironment) {
        self.editor = editor
        self.profiles = profiles
        self.policy = policy
        self.violations = violations
        self.environment = environment
    }

    public var settings: SandboxSettings { editor.config.sandbox }
    public var rules: [SandboxRule] { settings.rules }

    public func refreshPlan() {
        do {
            plan = try profiles.plan(for: settings)
            planError = nil
        } catch {
            plan = nil
            planError = UserMessage(error: error, action: "Read the sandbox profile")
        }
    }

    // MARK: Editing

    public func setPreset(_ preset: SandboxPreset) async {
        await edit("Set the preset") { $0.preset = preset }
    }

    public func setAutoReapply(_ on: Bool) async {
        await edit("Change auto re-apply") { $0.autoReapply = on }
    }

    @discardableResult
    public func addFileRule(path: String, match: PathMatch, access: FileAccess, effect: RuleEffect, note: String) async -> Bool {
        let rule = FileRule(path: path.trimmingCharacters(in: .whitespaces), match: match, access: access, effect: effect, note: FirewallModel.note(note))
        return await edit("Add rule") { try $0.add(rule) }
    }

    @discardableResult
    public func addMachRule(name: String, effect: RuleEffect, note: String) async -> Bool {
        let rule = MachRule(name: name.trimmingCharacters(in: .whitespaces), effect: effect, note: FirewallModel.note(note))
        return await edit("Add rule") { try $0.add(rule) }
    }

    @discardableResult
    public func addExecRule(path: String, effect: RuleEffect, note: String) async -> Bool {
        let rule = ExecRule(path: path.trimmingCharacters(in: .whitespaces), effect: effect, note: FirewallModel.note(note))
        return await edit("Add rule") { try $0.add(rule) }
    }

    public func removeRule(_ id: UUID) async {
        await edit("Remove rule") { try $0.removeRule(idPrefix: id.uuidString) }
    }

    // MARK: Apply and reset (root helper)

    public func apply() async {
        await runHelper("Apply rules") { try await self.policy.applyProfile(AppliedState(config: self.editor.config)) }
    }

    /// Removes the managed block; sv's own profile text stays as it is.
    public func reset() async {
        await runHelper("Reset rules") { try await self.policy.resetProfile() }
    }

    // MARK: Learn mode

    public var suggestions: [RuleSuggestion] {
        let relevant = includeUnattributed ? observed : observed.filter(\.attributedToSandbox)
        return RuleSuggester.suggestions(for: relevant, environment: environment).filter { !hiddenSuggestions.contains($0.id) }
    }

    /// Follows the unified log (`log stream`, needs an administrator account) until `stopLearning`.
    public func startLearning() {
        guard learnTask == nil else { return }
        isLearning = true
        learnError = nil
        let stream = violations.stream()
        learnTask = Task { [weak self] in
            do {
                for try await violation in stream {
                    self?.record(violation)
                }
                self?.learningEnded(nil)
            } catch {
                self?.learningEnded(error)
            }
        }
    }

    public func stopLearning() {
        learnTask?.cancel()
        learnTask = nil
        isLearning = false
    }

    public func accept(_ suggestion: RuleSuggestion) async {
        if await edit("Add suggested rule", { try $0.add(suggestion.proposal) }) {
            hiddenSuggestions.insert(suggestion.id)
            message = .success("Rule added", detail: "Apply the rules to write it into the profile.")
        }
    }

    public func dismiss(_ suggestion: RuleSuggestion) {
        hiddenSuggestions.insert(suggestion.id)
    }

    public func clearObserved() {
        observed = []
        hiddenSuggestions = []
    }

    // MARK: -

    func record(_ violation: SandboxViolation) {
        observed.append(violation)
        if observed.count > Self.observedLimit { observed.removeFirst(observed.count - Self.observedLimit) }
    }

    private func learningEnded(_ error: Error?) {
        guard learnTask != nil else { return }
        learnTask = nil
        isLearning = false
        if let error, !(error is CancellationError) {
            learnError = UserMessage(error: error, action: "Learn mode")
        }
    }

    @discardableResult
    private func edit<T>(_ action: String, _ change: (inout SandboxSettings) throws -> T) async -> Bool {
        do {
            try await editor.edit(reloadNetd: false) { _ = try change(&$0.sandbox) }
            message = nil
            refreshPlan()
            return true
        } catch {
            message = UserMessage(error: error, action: action)
            return false
        }
    }

    private func runHelper(_ action: String, _ body: () async throws -> HelperResult) async {
        guard !isBusy else { return }
        isBusy = true
        defer { isBusy = false }
        do {
            let result = try await body()
            message = result.ok ? .success(result.message) : UserMessage(kind: .error, title: "\(action) failed", detail: result.message)
        } catch {
            message = UserMessage(error: error, action: action)
        }
        refreshPlan()
    }
}
