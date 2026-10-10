import Foundation
import Observation
import SandvaultCore
import SandvaultEnforce
import SandvaultNet

/// Firewall & Proxy screen. Edits change config.json only (like `svctl firewall ...` and `svctl proxy ...`);
/// netd reloads domain rules at once, the pf anchor changes on `apply`, which first shows the generated rules.
@MainActor @Observable
public final class FirewallModel {
    /// What the helper loaded last (`svctl-helper status`).
    public private(set) var loaded: HelperStatus?
    public private(set) var loadedError: String?
    public private(set) var ca = CAStatus.none
    /// Rules waiting for the user's confirmation; `nil` when no apply is in progress.
    public private(set) var pendingApply: FirewallApplyPlan?
    /// A pf-relevant setting changed here since the last apply.
    public private(set) var changedSinceApply = false
    public private(set) var isBusy = false
    public var message: UserMessage?

    @ObservationIgnored private let editor: ConfigEditor
    @ObservationIgnored private let policy: PolicyControl
    @ObservationIgnored private let sandboxUID: SandboxUIDSource
    @ObservationIgnored private let localPorts: LocalPortSource
    @ObservationIgnored private let caControl: CAControl
    @ObservationIgnored private let clock: AppClock

    public init(editor: ConfigEditor, policy: PolicyControl, sandboxUID: SandboxUIDSource, localPorts: LocalPortSource, ca: CAControl, clock: AppClock) {
        self.editor = editor
        self.policy = policy
        self.sandboxUID = sandboxUID
        self.localPorts = localPorts
        self.caControl = ca
        self.clock = clock
    }

    public var network: NetworkPolicy { editor.config.network }
    public var panicActive: Bool { loaded?.panicActive ?? false }

    /// The configured mode differs from the loaded one, or a pf setting changed here since the last apply.
    public var needsApply: Bool {
        if changedSinceApply { return true }
        guard let loaded else { return false }
        return (loaded.firewallMode ?? .off) != network.mode
    }

    /// What pf has loaded, for the mode section.
    public var loadedSummary: String {
        guard let loaded else { return loadedError.map { "unknown (\($0))" } ?? "unknown" }
        var parts = [(loaded.firewallMode ?? .off).displayName.lowercased()]
        if let enabled = loaded.pfEnabled { parts.append(enabled ? "pf enabled" : "pf disabled") }
        if loaded.panicActive { parts.append("PANIC active") }
        if loaded.anchorChanged { parts.append("anchor differs from the last apply") }
        return parts.joined(separator: ", ")
    }

    public var caSummary: String {
        guard ca.exists else { return "not created (turning inspection on creates it)" }
        let published = ca.published.map { "published copy \($0.rawValue)" } ?? "published copy unknown"
        return "SHA-256 \(ca.fingerprint ?? "?") · \(published)"
    }

    public func refreshStatus() async {
        do {
            loaded = try await policy.status()
            loadedError = nil
        } catch {
            loaded = nil
            loadedError = UserMessage.describe(error)
        }
        ca = caControl.status()
    }

    // MARK: pf settings (take effect on apply)

    public func setMode(_ mode: FirewallMode) async {
        await editFirewall("Set mode") { $0.mode = mode }
    }

    public func setBlockLAN(_ on: Bool) async {
        await editFirewall("Change the LAN guard") { $0.blockLAN = on }
    }

    public func setLocalhost(_ localhost: LocalhostPolicy) async {
        await editFirewall("Change the localhost policy") { $0.localhost = localhost }
    }

    /// `port` empty means every port. Returns whether the exception was added.
    @discardableResult
    public func addException(proto: TransportProtocol, destination: String, port: String, note: String) async -> Bool {
        let trimmed = port.trimmingCharacters(in: .whitespaces)
        let number: UInt16?
        if trimmed.isEmpty {
            number = nil
        } else if let value = UInt16(trimmed), value > 0 {
            number = value
        } else {
            message = UserMessage(error: SandvaultError.invalidInput("port '\(port)' must be 1-65535 or empty"), action: "Add exception")
            return false
        }
        let exception = PortException(
            proto: proto, destination: destination.trimmingCharacters(in: .whitespaces), port: number, note: Self.note(note)
        )
        return await editFirewall("Add exception") { try $0.add(exception) }
    }

    public func removeException(_ id: UUID) async {
        await editFirewall("Remove exception") { try $0.removeException(idPrefix: id.uuidString) }
    }

    // MARK: netd settings (take effect on reload)

    public func setDefaultAction(_ action: DomainAction) async {
        await editProxy("Set the default action") { $0.defaultAction = action }
    }

    public func setAskFallback(_ action: DomainAction) async {
        await editProxy("Set the ask fallback") { $0.askFallback = action }
    }

    public func setAskTimeout(_ seconds: Int) async {
        await editProxy("Set the ask timeout") { $0.askTimeoutSeconds = min(max(seconds, 5), 300) }
    }

    public func setBlockPrivateDestinations(_ on: Bool) async {
        await editProxy("Change private destinations") { $0.blockPrivateDestinations = on }
    }

    @discardableResult
    public func upsertDomainRule(pattern: String, action: DomainAction, inspect: Bool? = nil, port: UInt16? = nil) async -> Bool {
        let now = clock.now()
        return await editProxy("Save rule") {
            try $0.upsertDomainRule(pattern: pattern, action: action, inspect: inspect, now: now, port: port)
        }
    }

    public func setInspect(_ rule: DomainRule, _ inspect: Bool) async {
        await upsertDomainRule(pattern: rule.pattern, action: rule.action, inspect: inspect, port: rule.port)
    }

    public func removeDomainRule(_ id: UUID) async {
        await editProxy("Remove rule") { try $0.removeDomainRule(selector: id.uuidString) }
    }

    @discardableResult
    public func upsertDnsOverride(pattern: String, address: String) async -> Bool {
        await editProxy("Save DNS override") { try $0.upsertDnsOverride(pattern: pattern, address: address) }
    }

    public func removeDnsOverride(_ id: UUID) async {
        await editProxy("Remove DNS override") { try $0.removeDnsOverride(selector: id.uuidString) }
    }

    /// `on` creates and publishes the CA first, like `svctl proxy inspection on`; both directions sync the sandbox's
    /// `.zshenv` block (CA variables).
    public func setInspection(_ enabled: Bool) async {
        isBusy = true
        defer { isBusy = false }
        do {
            if enabled { ca = try await caControl.prepareInspection() }
            let edit = try await editor.edit { config -> NetworkPolicy in
                config.network.inspection.enabled = enabled
                return config.network
            }
            try caControl.syncSandboxEnvironment(edit.value)
            ca = caControl.status()
            message = .success("Inspection \(enabled ? "on" : "off")", detail: netdReloadNote(edit.netdReloaded))
        } catch {
            message = UserMessage(error: error, action: "Turn inspection \(enabled ? "on" : "off")")
        }
    }

    // MARK: Protection level (simple window)

    /// The simple window's level; `nil` for settings only expert mode makes.
    public var protection: ProtectionLevel? { ProtectionLevel.current(network) }

    /// Saves the level and loads it at once, without the rule preview; Off flushes the anchor. Like every
    /// deliberate apply it also ends a panic.
    public func setProtection(_ level: ProtectionLevel) async {
        if level == .off { return await turnOff() }
        guard await editFirewall("Set protection", { level.apply(to: &$0) }) else { return }
        await prepareApply()
        await confirmApply()
    }

    // MARK: Apply, panic, off

    /// Builds the state `apply` would send and the anchor text it generates; nothing is loaded yet.
    public func prepareApply() async {
        isBusy = true
        defer { isBusy = false }
        editor.reload()
        let config = editor.config
        let needsPorts = config.network.mode != .off && config.network.localhost == .sandboxAndHelpers
        var ports: [UInt16] = []
        var notes: [String] = []
        if needsPorts {
            do {
                ports = try await localPorts.allowedLocalPorts()
            } catch {
                notes.append("Sandbox listening ports unknown (\(UserMessage.describe(error))); none allowed on loopback.")
            }
        }
        let state = AppliedState(config: config, dynamicLocalPorts: ports)
        do {
            var plan = FirewallApplyPlan(state: state, uid: nil, rules: nil, notes: notes)
            if config.network.mode != .off {
                let uid = try await sandboxUID.sandboxUID()
                plan.uid = uid
                plan.rules = try Enforce.firewallPreview(state: state, uid: uid)
            }
            pendingApply = plan
        } catch {
            message = UserMessage(error: error, action: "Preview firewall rules")
        }
    }

    public func cancelApply() {
        pendingApply = nil
    }

    /// Loads the previewed state through the helper; a deliberate apply also ends a panic (D20).
    public func confirmApply() async {
        guard let plan = pendingApply else { return }
        pendingApply = nil
        isBusy = true
        defer { isBusy = false }
        do {
            let result = try await policy.applyFirewall(plan.state, releasingPanic: true)
            let reloaded = await editor.reloadNetd()
            if result.ok {
                changedSinceApply = false
                message = .success("Firewall \(plan.mode.displayName.lowercased()) applied", detail: [result.message, netdReloadNote(reloaded)].compactMap { $0 }.joined(separator: "; "))
            } else {
                message = UserMessage(kind: .error, title: "Firewall apply failed", detail: result.message)
            }
        } catch {
            message = UserMessage(error: error, action: "Apply firewall")
        }
        await refreshStatus()
    }

    /// Blocks the sandbox's network and ends its processes. The mode is saved first so netd's next apply keeps it.
    public func panic() async {
        isBusy = true
        defer { isBusy = false }
        do {
            let edit = try await editor.edit(reloadNetd: false) { config -> AppConfig in
                config.network.mode = .blocked
                return config
            }
            let result = try await policy.panic(AppliedState(config: edit.value))
            _ = await editor.reloadNetd()
            message = result.ok
                ? UserMessage(kind: .warning, title: "Panic: the sandbox is blocked", detail: "To end it, choose a mode and apply, or turn the firewall off.")
                : UserMessage(kind: .error, title: "Panic failed", detail: result.message)
        } catch {
            message = UserMessage(error: error, action: "Panic")
        }
        await refreshStatus()
    }

    /// Mode off and the anchor flushed: the way back from any mode, also after a panic.
    public func turnOff() async {
        isBusy = true
        defer { isBusy = false }
        do {
            try await editor.edit(reloadNetd: false) { $0.network.mode = .off }
            let result = try await policy.disableFirewall()
            let reloaded = await editor.reloadNetd()
            changedSinceApply = false
            message = result.ok
                ? .success("Firewall off", detail: netdReloadNote(reloaded))
                : UserMessage(kind: .error, title: "Turning the firewall off failed", detail: result.message)
        } catch {
            message = UserMessage(error: error, action: "Turn the firewall off")
        }
        await refreshStatus()
    }

    // MARK: -

    @discardableResult
    private func editFirewall(_ action: String, _ change: (inout NetworkPolicy) throws -> Void) async -> Bool {
        do {
            try await editor.edit { try change(&$0.network) }
            changedSinceApply = true
            message = nil
            return true
        } catch {
            message = UserMessage(error: error, action: action)
            return false
        }
    }

    @discardableResult
    private func editProxy<T>(_ action: String, _ change: (inout NetworkPolicy) throws -> T) async -> Bool {
        do {
            let edit = try await editor.edit { try change(&$0.network) }
            message = edit.netdReloaded == false ? .info("Saved", detail: netdReloadNote(false)) : nil
            return true
        } catch {
            message = UserMessage(error: error, action: action)
            return false
        }
    }

    static func note(_ text: String) -> String? {
        let trimmed = text.trimmingCharacters(in: .whitespacesAndNewlines)
        return trimmed.isEmpty ? nil : trimmed
    }
}

/// What `apply` will send and load, shown before anything changes.
public struct FirewallApplyPlan: Identifiable, Sendable, Equatable {
    public var id = UUID()
    public var state: AppliedState
    /// The sandbox user's uid the rules name; `nil` for `off`.
    public var uid: UInt32?
    /// The anchor text; `nil` for `off` (the anchor is flushed).
    public var rules: String?
    public var notes: [String]

    public var mode: FirewallMode { state.network.mode }

    public var previewText: String {
        rules ?? "# mode off: the anchor \(AppPaths.pfAnchor) is flushed\n"
    }

    /// `Anchor com.apple/sandvault-config for uid 601; loopback ports 3000, 9222`.
    public var summary: String {
        guard let uid else { return "Flushes the anchor \(AppPaths.pfAnchor); the sandbox's network is no longer filtered." }
        var text = "Anchor \(AppPaths.pfAnchor) for uid \(uid)"
        if state.network.localhost == .sandboxAndHelpers {
            let ports = state.dynamicLocalPorts.map(String.init).joined(separator: ", ")
            text += "; loopback ports " + (ports.isEmpty ? "none" : ports)
        }
        return text
    }
}
