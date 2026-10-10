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
    /// What the user chose per suggestion in this session, so a card can show it and undo it.
    public private(set) var decisions: [String: LearnDecision] = [:]
    public private(set) var learningSince: Date?

    public static let observedLimit = 5000

    @ObservationIgnored private let editor: ConfigEditor
    @ObservationIgnored private let profiles: ProfileSource
    @ObservationIgnored private let policy: PolicyControl
    @ObservationIgnored private let violations: ViolationSource
    @ObservationIgnored private let environment: SandvaultEnvironment
    @ObservationIgnored private let clock: AppClock
    @ObservationIgnored private var learnTask: Task<Void, Never>?

    public init(
        editor: ConfigEditor, profiles: ProfileSource, policy: PolicyControl, violations: ViolationSource, environment: SandvaultEnvironment,
        clock: AppClock = .live
    ) {
        self.editor = editor
        self.profiles = profiles
        self.policy = policy
        self.violations = violations
        self.environment = environment
        self.clock = clock
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
        allSuggestions.filter { !hiddenSuggestions.contains($0.id) }
    }

    /// Every suggestion in plain words (D46), the decided ones included so their card shows the choice.
    public var learnCards: [LearnCard] {
        allSuggestions.map { LearnCard.make($0, environment: environment) }
    }

    private var allSuggestions: [RuleSuggestion] {
        let relevant = includeUnattributed ? observed : observed.filter(\.attributedToSandbox)
        return RuleSuggester.suggestions(for: relevant, environment: environment)
    }

    /// `Watching for 4 min`, or `nil` while not learning.
    public func watchingText(now: Date) -> String? {
        guard let learningSince else { return nil }
        let seconds = Int(now.timeIntervalSince(learningSince))
        return seconds < 60 ? "Watching" : "Watching for \(Format.duration(seconds))"
    }

    /// Follows the unified log (`log stream`, needs an administrator account) until `stopLearning`.
    public func startLearning() {
        guard learnTask == nil else { return }
        isLearning = true
        learningSince = clock.now()
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
        learningSince = nil
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

    /// One of the card's allow choices: adds its rule to config.json (applied with Apply Rules).
    public func allow(_ card: LearnCard, _ choice: LearnChoice) async {
        var ruleID: UUID?
        var added = false
        let saved = await edit("Add suggested rule") { settings in
            let before = settings.rules.count
            ruleID = try settings.add(choice.proposal)
            added = settings.rules.count > before
        }
        guard saved, let ruleID else { return }
        hiddenSuggestions.insert(card.id)
        decisions[card.id] = .allowed(choice: choice.title, ruleID: added ? ruleID : nil)
        message = .success("Rule added", detail: "Apply the rules to write it into the profile.")
    }

    /// Keep Blocked: nothing changes, the card only remembers the answer.
    public func keepBlocked(_ card: LearnCard) {
        hiddenSuggestions.insert(card.id)
        decisions[card.id] = .keptBlocked
    }

    /// Takes the answer back; an added rule is removed again.
    public func undo(_ card: LearnCard) async {
        if case .allowed(_, let ruleID?) = decisions[card.id] {
            guard await edit("Remove the rule", { _ = try $0.removeRule(idPrefix: ruleID.uuidString) }) else { return }
            message = nil
        }
        decisions[card.id] = nil
        hiddenSuggestions.remove(card.id)
    }

    public func clearObserved() {
        observed = []
        hiddenSuggestions = []
        decisions = [:]
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
        learningSince = nil
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

/// What the user answered on a learn card.
public enum LearnDecision: Equatable, Sendable {
    /// `ruleID` is `nil` when an identical rule existed before (undo then leaves it).
    case allowed(choice: String, ruleID: UUID?)
    case keptBlocked
}
