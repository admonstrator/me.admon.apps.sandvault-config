import ArgumentParser
import Foundation
import SandvaultCore
import SandvaultObserve
#if canImport(Darwin)
import Darwin
#elseif canImport(Glibc)
import Glibc
#endif

struct PsCommand: AsyncParsableCommand {
    static let configuration = CommandConfiguration(
        commandName: "ps",
        abstract: "List the sandbox user's processes with their sv session."
    )

    @OptionGroup var global: GlobalOptions

    @Flag(name: .long, help: "Show the process tree.")
    var tree = false

    @Option(name: .long, help: "Only this session (full id or unique prefix).")
    var session: String?

    func run() async throws {
        try ObservePlatform.require("ps")
        var snapshot = try await ProcessMonitor(environment: global.environment, runner: global.runner).snapshot()
        if let session {
            let id = try snapshot.session(matching: session).id
            snapshot.processes = snapshot.processes(inSession: id)
            snapshot.sessions = snapshot.sessions.filter { $0.id == id }
            snapshot.helpers = snapshot.helpers.filter { $0.sessionID == id }
        }
        if global.json { return try Output.json(snapshot) }

        let entries = tree ? snapshot.tree() : snapshot.processes.map { ProcessTreeEntry(depth: 0, process: $0) }
        let rows = entries.map { entry in
            let p = entry.process
            return [
                String(p.pid), String(p.ppid), String(format: "%.1f", p.cpuPercent), String(format: "%.1f", p.memPercent),
                Format.bytes(Int64(p.rssKiB) * 1024), Format.duration(p.elapsedSeconds), p.state,
                Format.shortSession(p.sessionID), Format.command(p.command, indent: entry.depth),
            ]
        }
        if rows.isEmpty {
            Output.line("no processes of \(global.environment.sandvaultUser)")
        } else {
            Output.table(["PID", "PPID", "%CPU", "%MEM", "RSS", "ELAPSED", "STATE", "SESSION", "COMMAND"], rows)
        }
        if !snapshot.helpers.isEmpty {
            Output.line()
            Output.table(["HELPER", "PID", "PORT", "SESSION"], snapshot.helpers.map {
                [$0.kind.rawValue, String($0.pid), $0.port.map(String.init) ?? "-", Format.shortSession($0.sessionID)]
            })
        }
        if !snapshot.environmentReadable {
            Output.error("cannot read the environment of \(global.environment.sandvaultUser)'s processes (sudo); session ids are incomplete")
        }
    }
}

struct SessionsCommand: AsyncParsableCommand {
    static let configuration = CommandConfiguration(
        commandName: "sessions",
        abstract: "List running sv sessions."
    )

    @OptionGroup var global: GlobalOptions

    func run() async throws {
        try ObservePlatform.require("sessions")
        let snapshot = try await ProcessMonitor(environment: global.environment, runner: global.runner).snapshot()
        if global.json { return try Output.json(snapshot.sessions) }
        if snapshot.sessions.isEmpty {
            Output.line("no running sessions")
        } else {
            Self.print(snapshot.sessions, short: false)
        }
        if !snapshot.environmentReadable {
            Output.error("cannot read the environment of \(global.environment.sandvaultUser)'s processes (sudo); sessions may be incomplete")
        }
    }

    static func print(_ sessions: [SandboxSession], short: Bool) {
        Output.table(["SESSION", "ROOT", "PROCS", "ELAPSED", "COMMAND", "HELPERS"], sessions.map { session in
            [
                short ? Format.shortSession(session.id) : session.id, String(session.rootPID), String(session.processCount),
                Format.duration(session.elapsedSeconds), session.command,
                session.helpers.isEmpty ? "-" : session.helpers.map(Format.helper).joined(separator: ", "),
            ]
        })
    }
}

struct KillCommand: AsyncParsableCommand {
    static let configuration = CommandConfiguration(
        commandName: "kill",
        abstract: "Terminate a sandbox process, a session, or everything the sandbox user runs.",
        discussion: """
        Signals are sent as the sandbox user, so nothing outside the sandbox can be hit. --all uses sv's own \
        sudoers rules (launchctl bootout, then pkill -9) and asks for confirmation unless --yes is given.
        """
    )

    @OptionGroup var global: GlobalOptions

    @Argument(help: "Process id.")
    var pid: Int32?

    @Option(name: .long, help: "Every process of this session (full id or unique prefix).")
    var session: String?

    @Flag(name: .long, help: "Every process of the sandbox user.")
    var all = false

    @Flag(name: .long, help: "SIGKILL instead of SIGTERM (--all always ends with SIGKILL).")
    var force = false

    @Flag(name: .long, help: "Do not ask for confirmation.")
    var yes = false

    func validate() throws {
        let targets = [pid != nil, session != nil, all].filter { $0 }.count
        guard targets == 1 else { throw ValidationError("give exactly one of <pid>, --session or --all") }
    }

    func run() async throws {
        try ObservePlatform.require("kill")
        let controller = ProcessController(environment: global.environment, runner: global.runner)
        let report: ControlReport
        if let pid {
            report = try await controller.terminate(pid: pid, force: force)
        } else if let session {
            report = try await controller.terminateSession(session, force: force)
        } else {
            try confirm("Terminate every process of \(global.environment.sandvaultUser)?")
            report = try await controller.terminateAll()
        }
        try printReport(report, json: global.json)
        if !report.succeeded { throw ExitCode.failure }
    }

    func confirm(_ question: String) throws {
        guard !yes else { return }
        guard isatty(STDIN_FILENO) == 1 else { throw ValidationError("stdin is not a terminal; pass --yes to confirm") }
        FileHandle.standardOutput.write(Data("\(question) [y/N] ".utf8))
        guard let answer = readLine()?.lowercased(), answer == "y" || answer == "yes" else { throw ExitCode.failure }
    }
}

struct ThrottleCommand: AsyncParsableCommand {
    static let configuration = CommandConfiguration(
        commandName: "throttle",
        abstract: "Lower a sandbox process's priority (renice) and/or move it to background QoS (taskpolicy).",
        discussion: "Without options the process is reniced to 10."
    )

    @OptionGroup var global: GlobalOptions

    @Argument(help: "Process id.")
    var pid: Int32

    @Option(name: .long, help: "Nice value, 1 (slightly lower) to 20 (lowest).")
    var nice: Int?

    @Flag(name: .long, help: "Background QoS: low CPU and I/O priority (taskpolicy -b).")
    var background = false

    func run() async throws {
        try ObservePlatform.require("throttle")
        let report = try await ProcessController(environment: global.environment, runner: global.runner)
            .throttle(pid: pid, nice: nice ?? (background ? nil : 10), background: background)
        try printReport(report, json: global.json)
        if !report.succeeded { throw ExitCode.failure }
    }
}

func printReport(_ report: ControlReport, json: Bool) throws {
    if json { return try Output.json(report) }
    for step in report.steps {
        Output.line("\(step.ok ? "ok  " : "FAIL") \(step.command)" + (step.detail.isEmpty ? "" : ": \(step.detail)"))
    }
    if report.targets.isEmpty { Output.line("nothing to do") }
    if !report.remaining.isEmpty {
        Output.line("still running: " + report.remaining.map(String.init).joined(separator: " "))
    } else if report.action != "throttle", !report.targets.isEmpty {
        Output.line("ended: " + report.targets.map(String.init).joined(separator: " "))
    }
}
