import Foundation
import SandvaultCore

/// One command a control action ran, with its honest outcome.
public struct ControlStep: Codable, Sendable, Equatable {
    public var command: String
    public var ok: Bool
    /// First line of stderr/stdout, or `exit <n>`.
    public var detail: String

    public init(command: String, ok: Bool, detail: String) {
        self.command = command
        self.ok = ok
        self.detail = detail
    }

    init(_ invocation: CommandInvocation, _ result: CommandResult, ok: Bool? = nil) {
        self.init(command: invocation.description, ok: ok ?? result.succeeded, detail: result.succeeded ? "" : result.message)
    }
}

public struct ControlReport: Codable, Sendable, Equatable {
    /// `terminate`, `kill`, `terminate-session`, `kill-session`, `terminate-all`, `throttle`.
    public var action: String
    public var targets: [Int32]
    public var steps: [ControlStep]
    /// Sandbox processes still alive after a termination (`SIGTERM` may need longer than the settle delay).
    public var remaining: [Int32]

    public init(action: String, targets: [Int32], steps: [ControlStep], remaining: [Int32] = []) {
        self.action = action
        self.targets = targets
        self.steps = steps
        self.remaining = remaining
    }

    public var succeeded: Bool { steps.allSatisfy(\.ok) && remaining.isEmpty }
}

/// Signals and throttles sandbox processes. Every signal is sent as the sandbox user, so the kernel itself
/// refuses anything outside the sandbox; ownership is also checked against a fresh snapshot first.
public struct ProcessController: Sendable {
    public var environment: SandvaultEnvironment
    public var runner: CommandRunner
    /// Wait before checking which processes survived.
    public var settleDelay: Duration

    public init(environment: SandvaultEnvironment, runner: CommandRunner, settleDelay: Duration = .milliseconds(300)) {
        self.environment = environment
        self.runner = runner
        self.settleDelay = settleDelay
    }

    var monitor: ProcessMonitor { ProcessMonitor(environment: environment, runner: runner) }

    /// `SIGTERM` (or `SIGKILL` with `force`) to one sandbox process.
    public func terminate(pid: Int32, force: Bool = false) async throws -> ControlReport {
        try await requireSandboxProcess(pid)
        return try await signal([pid], force: force, action: force ? "kill" : "terminate")
    }

    /// Signals every process of one session (`idOrPrefix` as in `ProcessSnapshot.session(matching:)`).
    public func terminateSession(_ idOrPrefix: String, force: Bool = false) async throws -> ControlReport {
        let snapshot = try await monitor.snapshot()
        let session = try snapshot.session(matching: idOrPrefix)
        let pids = snapshot.processes(inSession: session.id).map(\.pid)
        return try await signal(pids, force: force, action: force ? "kill-session" : "terminate-session")
    }

    /// Everything of the sandbox user, the way sv's uninstall does it and with sv's own sudoers rules:
    /// `launchctl bootout user/<uid>`, then `pkill -9 -u <sandbox>` for survivors.
    public func terminateAll() async throws -> ControlReport {
        let before = try await monitor.sandboxProcesses().map(\.pid)
        guard !before.isEmpty else { return ControlReport(action: "terminate-all", targets: [], steps: []) }
        var steps: [ControlStep] = []

        let lookup = Invocations.dsclRead("/Users/\(environment.sandvaultUser)", ["UniqueID"])
        let uid = (try? await runner.run(lookup)).flatMap { result in
            result.succeeded ? DsclParser.parse(result.stdoutString)["UniqueID"]?.first.flatMap { Int($0) } : nil
        }
        if let uid {
            let bootout = Invocations.launchctlBootout(uid: uid)
            steps.append(await step(bootout))
            try await Task.sleep(for: settleDelay)
        } else {
            // Not a failure by itself: pkill below still runs, and `remaining` tells whether it worked.
            steps.append(ControlStep(
                command: lookup.description, ok: true,
                detail: "cannot read the UID of \(environment.sandvaultUser); skipped launchctl bootout"
            ))
        }

        if try await !monitor.sandboxProcesses().isEmpty {
            let pkill = Invocations.pkillAll(environment)
            // pkill exits 1 when nothing matched any more; that is success here.
            steps.append(await step(pkill, accept: [0, 1]))
            try await Task.sleep(for: settleDelay)
        }
        let remaining = try await monitor.sandboxProcesses().map(\.pid)
        return ControlReport(action: "terminate-all", targets: before, steps: steps, remaining: remaining)
    }

    /// Lowers the priority (`renice +<nice>`) and/or moves the process to the background QoS band (`taskpolicy -b`).
    public func throttle(pid: Int32, nice: Int? = 10, background: Bool = false) async throws -> ControlReport {
        if let nice, !(1...20).contains(nice) {
            throw SandvaultError.invalidInput("nice must be between 1 and 20 (an unprivileged user can only lower priority)")
        }
        guard nice != nil || background else { throw SandvaultError.invalidInput("nothing to do: pass a nice value or background") }
        try await requireSandboxProcess(pid)

        var steps: [ControlStep] = []
        if let nice { steps.append(try await sandboxStep(Invocations.renice(environment, pid: pid, nice: nice))) }
        if background { steps.append(try await sandboxStep(Invocations.taskpolicyBackground(environment, pid: pid))) }
        return ControlReport(action: "throttle", targets: [pid], steps: steps)
    }

    // MARK: - Internals

    func requireSandboxProcess(_ pid: Int32) async throws {
        let all = try await monitor.allProcesses()
        guard let process = all.first(where: { $0.pid == pid }) else {
            throw SandvaultError.invalidInput("no process with pid \(pid)")
        }
        guard process.user == environment.sandvaultUser else {
            throw SandvaultError.permissionDenied("pid \(pid) belongs to \(process.user), not \(environment.sandvaultUser)")
        }
        guard ProcessMonitor.sandboxOnly(all, environment: environment).contains(where: { $0.pid == pid }) else {
            throw SandvaultError.permissionDenied("pid \(pid) is an inspection process of this tool")
        }
    }

    func signal(_ pids: [Int32], force: Bool, action: String) async throws -> ControlReport {
        guard !pids.isEmpty else { return ControlReport(action: action, targets: [], steps: []) }
        let step = try await sandboxStep(Invocations.kill(environment, pids: pids, force: force))
        try await Task.sleep(for: settleDelay)
        let alive = Set(try await monitor.sandboxProcesses().map(\.pid))
        return ControlReport(action: action, targets: pids, steps: [step], remaining: pids.filter(alive.contains))
    }

    /// Runs a command as the sandbox user; a refused sudo is an error, not a step.
    func sandboxStep(_ invocation: CommandInvocation) async throws -> ControlStep {
        let result = try await runner.run(invocation)
        if result.sudoRefused { throw SandvaultError.sudoMissing(environment) }
        return ControlStep(invocation, result)
    }

    func step(_ invocation: CommandInvocation, accept: Set<Int32> = [0]) async -> ControlStep {
        do {
            let result = try await runner.run(invocation)
            if result.sudoRefused {
                return ControlStep(command: invocation.description, ok: false, detail: "sudo refused; sv's sudoers rule is missing (`sv build --rebuild`)")
            }
            let ok = accept.contains(result.exitCode)
            return ControlStep(command: invocation.description, ok: ok, detail: ok ? "" : result.message)
        } catch {
            return ControlStep(command: invocation.description, ok: false, detail: "\(error)")
        }
    }
}
