import Foundation
import SandvaultCore

/// Everything the sandbox user runs, grouped into sv sessions, plus sv's host helpers.
public struct ProcessSnapshot: Codable, Sendable, Equatable {
    /// Processes of the sandbox user, sorted by pid.
    public var processes: [SandboxProcess]
    /// Longest-running first.
    public var sessions: [SandboxSession]
    /// Host-side helpers (headless Chrome, iOS bridge) that are alive.
    public var helpers: [HostHelperProcess]
    /// `ps -E` as the sandbox user worked. When `false`, session ids come only from the command line of the
    /// `sudo`/`ssh` process that started each session, so processes re-parented to launchd have none.
    public var environmentReadable: Bool
    public var takenAt: Date

    public init(
        processes: [SandboxProcess], sessions: [SandboxSession], helpers: [HostHelperProcess],
        environmentReadable: Bool, takenAt: Date = Date()
    ) {
        self.processes = processes
        self.sessions = sessions
        self.helpers = helpers
        self.environmentReadable = environmentReadable
        self.takenAt = takenAt
    }

    /// The session whose id equals or uniquely starts with `idOrPrefix` (case-insensitive).
    public func session(matching idOrPrefix: String) throws -> SandboxSession {
        let wanted = idOrPrefix.uppercased()
        if let exact = sessions.first(where: { $0.id == wanted }) { return exact }
        let matches = sessions.filter { $0.id.hasPrefix(wanted) }
        guard !wanted.isEmpty, matches.count == 1 else {
            throw SandvaultError.invalidInput(
                matches.isEmpty ? "no running session matches '\(idOrPrefix)'" : "'\(idOrPrefix)' matches \(matches.count) sessions"
            )
        }
        return matches[0]
    }

    public func processes(inSession id: String) -> [SandboxProcess] {
        processes.filter { $0.sessionID == id }
    }

    /// Processes in depth-first tree order (children sorted by pid); roots are processes whose parent
    /// is not a sandbox process.
    public func tree() -> [ProcessTreeEntry] {
        let pids = Set(processes.map(\.pid))
        let children = Dictionary(grouping: processes.filter { pids.contains($0.ppid) && $0.ppid != $0.pid }, by: \.ppid)
        var result: [ProcessTreeEntry] = []
        func visit(_ process: SandboxProcess, depth: Int) {
            result.append(ProcessTreeEntry(depth: depth, process: process))
            for child in (children[process.pid] ?? []).sorted(by: { $0.pid < $1.pid }) where depth < 64 {
                visit(child, depth: depth + 1)
            }
        }
        for root in processes where !pids.contains(root.ppid) || root.ppid == root.pid {
            visit(root, depth: 0)
        }
        return result
    }
}

public struct ProcessTreeEntry: Codable, Sendable, Equatable {
    public var depth: Int
    public var process: SandboxProcess

    public init(depth: Int, process: SandboxProcess) {
        self.depth = depth
        self.process = process
    }
}

/// Reads the sandbox user's processes with `ps`. Cheap enough to poll every 1-2 seconds.
public struct ProcessMonitor: Sendable {
    public var environment: SandvaultEnvironment
    public var runner: CommandRunner
    public var files: HostFiles

    public init(environment: SandvaultEnvironment, runner: CommandRunner, files: HostFiles = .live) {
        self.environment = environment
        self.runner = runner
        self.files = files
    }

    /// Processes of the sandbox user without session ids: one `ps` call, no sudo.
    public func sandboxProcesses() async throws -> [SandboxProcess] {
        try await Self.sandboxOnly(allProcesses(), environment: environment)
    }

    /// Processes with session ids, sessions and host helpers. Falls back to session ids from the session
    /// launchers when `ps -E` as the sandbox user is not possible.
    public func snapshot() async throws -> ProcessSnapshot {
        let all = try await allProcesses()
        // Sequential on purpose: the `ps -E` call itself must not show up in the first listing.
        let sessions = await environmentSessions()
        return Self.assemble(all: all, environmentSessions: sessions, environment: environment, files: files)
    }

    /// sv's host helpers that are alive, with ports from their logs. One `ps` call, no sudo.
    public func helpers() async throws -> [HostHelperProcess] {
        try await Self.assemble(all: allProcesses(), environmentSessions: nil, environment: environment, files: files).helpers
    }

    func allProcesses() async throws -> [SandboxProcess] {
        ProcessParser.parse(try await runner.checked(Invocations.psAll).stdoutString)
    }

    /// pid -> `SV_SESSION_ID`, or `nil` when the environment of the sandbox processes cannot be read.
    func environmentSessions() async -> [Int32: String]? {
        guard let result = try? await runner.run(Invocations.psEnvironment(environment)), !result.sudoRefused else { return nil }
        // `ps -U` exits 1 without output when the user has no processes.
        guard result.succeeded || (result.stdout.isEmpty && result.stderr.isEmpty) else { return nil }
        return ProcessParser.sessionIDs(result.stdoutString)
    }

    // MARK: - Assembly (pure)

    static func assemble(
        all: [SandboxProcess], environmentSessions: [Int32: String]?, environment: SandvaultEnvironment,
        files: HostFiles, now: Date = Date()
    ) -> ProcessSnapshot {
        let byPID = Dictionary(all.map { ($0.pid, $0) }, uniquingKeysWith: { first, _ in first })
        // Host processes whose arguments carry `SV_SESSION_ID=<uuid>`: sv's `sudo --login ... /usr/bin/env -i ...`
        // (root) or `ssh ... /usr/bin/env -i ...` (host user). Their parent is the `sv` process of that session.
        var launchers: [Int32: String] = [:]
        var svProcesses: [Int32: String] = [:]
        for process in all where process.user != environment.sandvaultUser {
            guard let id = ProcessParser.sessionID(in: process.command) else { continue }
            launchers[process.pid] = id
            svProcesses[process.ppid] = id
        }

        func inheritedSession(_ pid: Int32) -> String? {
            var current = pid
            for _ in 0..<64 {
                guard let process = byPID[current] else { return nil }
                if process.user != environment.sandvaultUser { return launchers[current] }
                if let id = environmentSessions?[current] { return id }
                guard process.ppid != current, process.ppid > 1 else { return nil }
                current = process.ppid
            }
            return nil
        }

        var processes = sandboxOnly(all, environment: environment)
        for index in processes.indices {
            processes[index].sessionID = environmentSessions?[processes[index].pid] ?? inheritedSession(processes[index].pid)
        }

        let helpers = hostHelpers(in: all, environment: environment, svProcesses: svProcesses, files: files)
        var sessions: [SandboxSession] = []
        for (id, members) in Dictionary(grouping: processes.filter { $0.sessionID != nil }, by: { $0.sessionID! }) {
            sessions.append(session(id: id, members: members, helpers: helpers.filter { $0.sessionID == id }))
        }
        sessions.sort { ($0.elapsedSeconds, $1.id) > ($1.elapsedSeconds, $0.id) }
        return ProcessSnapshot(
            processes: processes, sessions: sessions, helpers: helpers,
            environmentReadable: environmentSessions != nil, takenAt: now
        )
    }

    /// The sandbox user's processes, minus the `ps`/`lsof` this module itself runs as that user.
    static func sandboxOnly(_ all: [SandboxProcess], environment: SandvaultEnvironment) -> [SandboxProcess] {
        let ownInspection = Set([Invocations.psEnvironment(environment), Invocations.lsof(environment)].map { $0.argv.joined(separator: " ") })
        let inspectionLaunchers = Set(all.filter { ownInspection.contains($0.command) }.map(\.pid))
        return all
            .filter { $0.user == environment.sandvaultUser && !inspectionLaunchers.contains($0.ppid) }
            .sorted { $0.pid < $1.pid }
    }

    static func session(id: String, members: [SandboxProcess], helpers: [HostHelperProcess]) -> SandboxSession {
        let pids = Set(members.map(\.pid))
        let roots = members.filter { !pids.contains($0.ppid) }.sorted { ($0.elapsedSeconds, $1.pid) > ($1.elapsedSeconds, $0.pid) }
        let root = roots.first ?? members.min { $0.pid < $1.pid }!

        // Depth below the root decides which agent is "the" command when several match.
        let children = Dictionary(grouping: members, by: \.ppid)
        var queue = [root]
        var command: String?
        var seen: Set<Int32> = []
        while !queue.isEmpty, command == nil {
            var next: [SandboxProcess] = []
            for process in queue.sorted(by: { $0.pid < $1.pid }) where seen.insert(process.pid).inserted {
                if command == nil, let agent = CommandName.agent(in: process.command) { command = agent }
                next += children[process.pid] ?? []
            }
            queue = next
        }
        return SandboxSession(
            id: id, rootPID: root.pid, processCount: members.count,
            command: command ?? CommandName.display(root.command), elapsedSeconds: root.elapsedSeconds,
            helpers: helpers.sorted { $0.pid < $1.pid }
        )
    }

    static func hostHelpers(
        in all: [SandboxProcess], environment: SandvaultEnvironment, svProcesses: [Int32: String], files: HostFiles
    ) -> [HostHelperProcess] {
        let chromeMarker = "/.local/state/sandvault/chrome-data-"
        var helpers: [HostHelperProcess] = []
        for process in all where process.user == environment.hostUser {
            let command = process.command
            if command.contains("--user-data-dir="), !command.contains(" --type="),
               let marker = command.range(of: chromeMarker) {
                let id = ProcessParser.normalizedUUID(command[marker.upperBound...].prefix(36))
                let port = id.flatMap { files.read("\(environment.sessionStateDir)/chrome-\($0).log", 1 << 16) }
                    .flatMap(HelperLogParser.chromePort)
                helpers.append(HostHelperProcess(pid: process.pid, kind: .chrome, port: port, sessionID: id))
            } else if command.contains(" --udid "),
                      command.split(separator: " ").prefix(3).contains(where: { $0 == "sv-ios-bridge" || $0.hasSuffix("/sv-ios-bridge") }) {
                let id = svProcesses[process.ppid]
                let port = id.flatMap { files.read("\(environment.sessionStateDir)/ios-bridge-\($0).log", 1 << 16) }
                    .flatMap(HelperLogParser.bridgePort)
                helpers.append(HostHelperProcess(pid: process.pid, kind: .iosBridge, port: port, sessionID: id))
            }
        }
        return helpers.sorted { $0.pid < $1.pid }
    }
}

/// Short, human names for command lines.
public enum CommandName {
    /// Agents sv starts (`sv claude`, `sv codex`, ...).
    public static let agents: Set<String> = Set(AgentKind.allCases.filter { $0 != .shell }.map(\.rawValue))
    static let interpreters: Set<String> = ["node", "bun", "deno", "python", "python3", "ruby", "perl"]

    /// Basename of the executable, or of the script for interpreters (`node /opt/homebrew/bin/codex` -> `codex`).
    public static func display(_ command: String) -> String {
        let words = command.split(separator: " ").map(String.init)
        guard let first = words.first else { return command }
        let name = basename(first)
        if interpreters.contains(name), let script = words.dropFirst().first(where: { !$0.hasPrefix("-") }) {
            return basename(script)
        }
        return name
    }

    /// The agent a command line runs, if any.
    public static func agent(in command: String) -> String? {
        let name = display(command)
        return agents.contains(name) ? name : nil
    }

    static func basename(_ word: String) -> String {
        var name = word.split(separator: "/").last.map(String.init) ?? word
        if name.hasPrefix("-") { name.removeFirst() }  // login shells: `-zsh`
        return name
    }
}
