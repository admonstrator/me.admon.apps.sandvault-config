import ArgumentParser
import Foundation
import SandvaultCore
import SandvaultEnforce
import SandvaultNet
import SandvaultObserve

/// Doctor checks of every module, in the order Observe, Enforce, Net. A config that cannot be read is
/// reported as a check and the defaults are used.
func allChecks(_ global: GlobalOptions) async -> [Check] {
    let environment = global.environment, runner = global.runner
    var config = AppConfig()
    var configCheck: Check?
    do {
        config = try global.configStore.load()
    } catch {
        configCheck = Check(id: "config.file", title: "Configuration", state: .failure, detail: "\(error); using defaults",
                            fix: "fix or remove \(global.configStore.url.path)")
    }
    var checks = await Observe.makeCheckProvider(environment: environment, runner: runner).checks()
    checks += await Enforce.makeCheckProvider(environment: environment, runner: runner, config: config).checks()
    checks += await Net.makeCheckProvider(environment: environment, runner: runner, config: config).checks()
    return (configCheck.map { [$0] } ?? []) + checks
}

struct StatusCommand: AsyncParsableCommand {
    static let configuration = CommandConfiguration(
        commandName: "status",
        abstract: "One-screen overview: installation, sessions, processes, listening ports, firewall mode, doctor state."
    )

    @OptionGroup var global: GlobalOptions

    func run() async throws {
        try ObservePlatform.require("status")
        let mode = (try? global.configStore.load().network.mode) ?? .off
        let summary = await StatusSummary.collect(
            environment: global.environment, runner: global.runner, firewallMode: mode, checks: await allChecks(global)
        )
        if global.json { return try Output.json(summary) }

        let installation = summary.installation.map { "\(Output.symbol($0.state))  \($0.detail)" } ?? "?"
        let problems = summary.problems.count
        let rows = [
            ("sandvault", installation),
            ("firewall", summary.firewallMode.rawValue),
            ("processes", "\(summary.processCount) in \(summary.sessions.count) session(s)"),
            ("listening", summary.listeningPorts.isEmpty ? "-" : summary.listeningPorts.map(String.init).joined(separator: ", ")),
            ("doctor", Output.symbol(summary.worstCheck) + (problems > 0 ? "  \(problems) problem(s), see `svctl doctor`" : "")),
        ]
        for (label, value) in rows { Output.line(label.padding(toLength: 11, withPad: " ", startingAt: 0) + value) }
        if !summary.sessions.isEmpty {
            Output.line()
            SessionsCommand.print(summary.sessions, short: true)
        }
        for error in summary.errors { Output.error(error) }
    }
}

struct DoctorCommand: AsyncParsableCommand {
    static let configuration = CommandConfiguration(
        commandName: "doctor",
        abstract: "Check whether sandvault and Sandvault Config are set up correctly.",
        discussion: "Exits with status 1 when any check fails."
    )

    @OptionGroup var global: GlobalOptions

    func run() async throws {
        try ObservePlatform.require("doctor")
        let report = CheckReport(checks: await allChecks(global))
        if global.json {
            try Output.json(report)
        } else {
            for check in report.checks {
                Output.line("\(Output.symbol(check.state).padding(toLength: 5, withPad: " ", startingAt: 0)) \(check.title): \(check.detail)")
                if let fix = check.fix, check.state >= .warning { Output.line("      fix: \(fix)") }
            }
        }
        if report.worst == .failure { throw ExitCode.failure }
    }
}
