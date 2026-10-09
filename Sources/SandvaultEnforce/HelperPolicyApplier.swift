import Foundation
import SandvaultCore

/// Applies state through the root helper (`sudo -n <helper> <subcommand> --json`, state on stdin).
///
/// `applyFirewall` is what netd calls whenever the sandbox's listening ports change: it remembers the last
/// successfully applied firewall inputs and returns without running sudo when nothing relevant changed.
/// The helper is idempotent as well (it skips reloading an identical anchor).
public actor HelperPolicyApplier: PolicyApplier {
    let runner: CommandRunner
    let isMacOS: Bool
    private var lastFirewall: FirewallInputs?
    private var lastFirewallResult: HelperResult?

    public init(runner: CommandRunner, isMacOS: Bool = EnforcePlatform.isMacOS) {
        self.runner = runner
        self.isMacOS = isMacOS
    }

    public func applyFirewall(_ state: AppliedState) async throws -> HelperResult {
        try await applyFirewall(state, releasingPanic: false)
    }

    /// `releasingPanic` marks a deliberate user action (CLI, app) that may leave the panic state; netd never sets it.
    public func applyFirewall(_ state: AppliedState, releasingPanic: Bool) async throws -> HelperResult {
        let inputs = FirewallInputs(state)
        if !releasingPanic, inputs == lastFirewall, let lastFirewallResult {
            return HelperResult(ok: true, message: "firewall unchanged", details: lastFirewallResult.details)
        }
        let result = try await call(.pfApply, arguments: releasingPanic ? ["--release-panic"] : [], state: state)
        lastFirewall = result.ok ? inputs : nil
        lastFirewallResult = result.ok ? result : nil
        return result
    }

    public func applyProfile(_ state: AppliedState) async throws -> HelperResult {
        try await call(.profileApply, state: state)
    }

    public func resetProfile() async throws -> HelperResult {
        try await call(.profileReset)
    }

    public func disableFirewall() async throws -> HelperResult {
        invalidate()
        return try await call(.pfDisable)
    }

    /// Blocks the sandbox's network and terminates its processes. Callers should also persist `mode = .blocked`
    /// in the config so later applies keep it.
    public func panic(_ state: AppliedState? = nil) async throws -> HelperResult {
        invalidate()
        return try await call(.panic, state: state)
    }

    public func status() async throws -> HelperStatus {
        let result = try await call(.status)
        guard result.ok else { throw SandvaultError.commandFailed("svctl-helper status", 1, result.message) }
        return HelperStatus(details: result.details)
    }

    /// Forget the cached firewall inputs, so the next `applyFirewall` always reaches the helper.
    public func invalidate() {
        lastFirewall = nil
        lastFirewallResult = nil
    }

    func call(_ subcommand: HelperSubcommand, arguments: [String] = [], state: AppliedState? = nil) async throws -> HelperResult {
        guard isMacOS else {
            throw SandvaultError.unsupportedPlatform("the root helper (sandbox-exec, pf) exists on macOS only")
        }
        let stdin = try state.map { try JSONCoding.lineEncoder.encode($0) }
        let result = try await runner.run(.viaHelper(subcommand.rawValue, ["--json"] + arguments, stdin: stdin))
        if let decoded = try? JSONCoding.decoder.decode(HelperResult.self, from: result.stdout) { return decoded }
        if result.stderrString.contains("a password is required") || result.stderrString.contains("not allowed") {
            throw SandvaultError.permissionDenied("helper sudoers rule missing; run `svctl helper install`")
        }
        throw SandvaultError.commandFailed("svctl-helper \(subcommand.rawValue)", result.exitCode, result.stderrString)
    }
}

/// The parts of `AppliedState` that change the pf anchor.
struct FirewallInputs: Equatable {
    var mode: FirewallMode
    var blockLAN: Bool
    var localhost: LocalhostPolicy
    var ports: ProxyPorts
    var exceptions: [PortException]
    var dynamicLocalPorts: [UInt16]

    init(_ state: AppliedState) {
        mode = state.network.mode
        blockLAN = state.network.blockLAN
        localhost = state.network.localhost
        ports = state.network.ports
        exceptions = state.network.portExceptions
        dynamicLocalPorts = Array(Set(state.dynamicLocalPorts)).sorted()
    }
}

public enum EnforcePlatform {
    public static var isMacOS: Bool {
        #if os(macOS)
        true
        #else
        false
        #endif
    }
}
