import ArgumentParser
import Foundation
import SandvaultCore
import SandvaultNet
import SandvaultObserve

/// Lab mode (D52): checkpoints of the sandbox's files, what changed between them, rewinding.
struct LabCommand: AsyncParsableCommand {
    static let configuration = CommandConfiguration(
        commandName: "lab",
        abstract: "Record checkpoints of the sandbox's files, compare them and rewind.",
        discussion: """
        A lab session keeps APFS clones of the sandbox home and the shared workspace. Checkpoints come from \
        `svctl lab watch` or the app (every interval when something changed, and when a program starts) and from \
        `svctl lab mark`. Rewinding terminates the sandbox's processes and puts the files back to a checkpoint. \
        Needs the helper with the lab command (`svctl helper install`).
        """,
        subcommands: [List.self, Start.self, Mark.self, Compare.self, Show.self, Rewind.self, Finish.self, Watch.self],
        defaultSubcommand: List.self
    )

    static func client(_ global: GlobalOptions) throws -> LabClient {
        try WorkflowCLI.requireMacOS("lab mode needs the helper and APFS")
        return LabClient(runner: global.runner)
    }

    static func bytes(_ count: Int64) -> String {
        ByteCountFormatter.string(fromByteCount: count, countStyle: .file)
    }

    static func time(_ date: Date) -> String {
        let formatter = DateFormatter()
        formatter.dateFormat = "HH:mm:ss"
        return formatter.string(from: date)
    }

    static func show(_ response: LabResponse) {
        guard let session = response.session else { return Output.line("no lab session (svctl lab start)") }
        Output.line("lab session since \(WorkflowCLI.date(session.startedAt)): \(session.checkpoints.count) checkpoints, "
            + "about \(bytes(session.estimatedBytes)) held" + (response.freeBytes.map { ", \(bytes($0)) free" } ?? "")
            + (session.pruned > 0 ? ", \(session.pruned) older ones removed" : ""))
        Output.table(["ID", "TIME", "WHAT", "CREATED", "CHANGED", "DELETED", "FINDINGS"], session.checkpoints.map { checkpoint in
            [
                (checkpoint.id == session.head ? "*" : " ") + String(checkpoint.id), time(checkpoint.takenAt), checkpoint.label,
                String(checkpoint.created), String(checkpoint.changed), String(checkpoint.deleted), String(checkpoint.findings),
            ]
        })
        Output.line("* = the files now descend from this checkpoint")
    }

    struct List: AsyncParsableCommand {
        static let configuration = CommandConfiguration(abstract: "The running session and its checkpoints.")
        @OptionGroup var global: GlobalOptions

        func run() async throws {
            let response = try await LabCommand.client(global).send(.status)
            if global.json { return try Output.json(response) }
            LabCommand.show(response)
        }
    }

    struct Start: AsyncParsableCommand {
        static let configuration = CommandConfiguration(abstract: "Start a session with a first checkpoint (settings from config.json, \"lab\").")
        @OptionGroup var global: GlobalOptions

        func run() async throws {
            let settings = try global.configStore.load().lab
            let response = try await LabCommand.client(global).send(.start(settings))
            if global.json { return try Output.json(response) }
            Output.line(response.message)
            Output.line("run svctl lab watch (or keep the app open) for automatic checkpoints; svctl lab mark takes one now")
        }
    }

    struct Mark: AsyncParsableCommand {
        static let configuration = CommandConfiguration(abstract: "Take a checkpoint now.")
        @OptionGroup var global: GlobalOptions
        @Argument(help: "A name for it, e.g. \"after npm install\".") var label: String?

        func run() async throws {
            let response = try await LabCommand.client(global).send(.checkpoint(reason: .manual, label: label, onlyIfChanged: false))
            if global.json { return try Output.json(response) }
            Output.line(response.message)
        }
    }

    struct Compare: AsyncParsableCommand {
        static let configuration = CommandConfiguration(abstract: "What changed from one checkpoint to another, or to now.")
        @OptionGroup var global: GlobalOptions
        @Argument(help: "From this checkpoint (default: the start).") var from: Int?
        @Argument(help: "To this checkpoint (default: now).") var to: Int?

        func run() async throws {
            let client = try LabCommand.client(global)
            var start = from ?? 0
            if from == nil { start = try await client.send(.status).session?.start?.id ?? 0 }
            let response = try await client.send(.compare(from: start, to: to))
            guard let comparison = response.comparison else { return Output.line(response.message) }
            if global.json { return try Output.json(comparison) }
            let findings = LabFindings.findings(in: comparison.changes)
            if !findings.isEmpty {
                Output.line("worth a look:")
                for finding in findings { Output.line("  \(finding.kind.title): \(finding.path.display) - \(finding.detail)") }
                Output.line()
            }
            if let session = response.session {
                let end = to.flatMap { session.checkpoint($0)?.takenAt }
                let begin = session.checkpoint(start)?.takenAt ?? session.startedAt
                let records = (try? ConnectionLog.read(path: global.paths.connectionLog, limit: 100_000)) ?? []
                let servers = LabServer.summarize(records, from: begin, to: end)
                if !servers.isEmpty {
                    Output.line("servers contacted:")
                    for server in servers {
                        Output.line("  \(server.host) (\(server.connections)x\(server.blocked > 0 ? ", \(server.blocked) blocked" : "")"
                            + (server.programs.isEmpty ? "" : ", " + server.programs.joined(separator: ", ")) + ")")
                    }
                    Output.line()
                }
            }
            for change in comparison.changes {
                let mark = switch change.kind {
                case .created: "+"
                case .changed: "~"
                case .deleted: "-"
                }
                Output.line("\(mark) \(change.path.display)" + (change.secret.map { "  (\($0))" } ?? ""))
            }
            Output.line("\(comparison.created) created, \(comparison.changed) changed, \(comparison.deleted) deleted"
                + (comparison.truncated ? " (list cut at \(LabComparison.maxChanges))" : ""))
        }
    }

    struct Show: AsyncParsableCommand {
        static let configuration = CommandConfiguration(abstract: "A text file's content at a checkpoint or now.")
        @OptionGroup var global: GlobalOptions
        @Argument(help: "~/path for the sandbox home, Workspace/path for the shared workspace.") var path: String
        @Option(name: .long, help: "Checkpoint id (default: now).") var at: Int?

        func run() async throws {
            let labPath = try LabCommand.parsePath(path)
            let response = try await LabCommand.client(global).send(.file(labPath, at: at))
            guard let file = response.file else { return Output.line(response.message) }
            if global.json { return try Output.json(file) }
            guard file.exists else { return Output.line("\(labPath.display) does not exist there") }
            guard let text = file.text else { return Output.line("\(labPath.display): \(LabCommand.bytes(file.size)), not text") }
            print(text, terminator: text.hasSuffix("\n") ? "" : "\n")
            if file.truncated { Output.line("[cut at \(LabCommand.bytes(Int64(LabFileContent.maxBytes)))]") }
        }
    }

    /// `~/x` and `home/x` name the sandbox home, `Workspace/x` and `workspace/x` the shared workspace.
    static func parsePath(_ text: String) throws -> LabPath {
        let pairs: [(String, LabRoot)] = [("~/", .home), ("home/", .home), ("Workspace/", .workspace), ("workspace/", .workspace)]
        for (prefix, root) in pairs where text.hasPrefix(prefix) {
            let path = LabPath(root: root, path: String(text.dropFirst(prefix.count)))
            try LabPath.validate(path.path)
            return path
        }
        throw SandvaultError.invalidInput("start the path with ~/ (sandbox home) or Workspace/ (shared workspace)")
    }

    struct Rewind: AsyncParsableCommand {
        static let configuration = CommandConfiguration(
            abstract: "Terminate the sandbox's processes and put its files back to a checkpoint (the state before is kept as a checkpoint)."
        )
        @OptionGroup var global: GlobalOptions
        @Argument(help: "Checkpoint id.") var id: Int
        @Flag(name: .long, help: "Do it: every program in the sandbox is terminated.") var yes = false

        func run() async throws {
            guard yes else {
                throw SandvaultError.invalidInput("rewinding terminates every program in the sandbox; add --yes to go ahead")
            }
            let response = try await LabCommand.client(global).send(.rewind(to: id))
            if global.json { return try Output.json(response) }
            Output.line(response.message)
        }
    }

    struct Finish: AsyncParsableCommand {
        static let configuration = CommandConfiguration(abstract: "End the session: keep the files as they are, or discard every change since the start.")
        @OptionGroup var global: GlobalOptions
        @Flag(name: .long, help: "Keep the files as they are now.") var keep = false
        @Flag(name: .long, help: "Put the files back to the start (terminates the sandbox's programs).") var discard = false

        func run() async throws {
            guard keep != discard else { throw SandvaultError.invalidInput("pass --keep or --discard") }
            let response = try await LabCommand.client(global).send(.finish(keep: keep))
            if global.json { return try Output.json(response) }
            Output.line(response.message)
        }
    }

    struct Watch: AsyncParsableCommand {
        static let configuration = CommandConfiguration(
            abstract: "Take automatic checkpoints until Ctrl-C: every interval when something changed, and when a program starts."
        )
        @OptionGroup var global: GlobalOptions

        func run() async throws {
            let client = try LabCommand.client(global)
            guard let session = try await client.send(.status).session else { throw SandvaultError.invalidInput("no lab session; run svctl lab start") }
            let processes = ProcessMonitor(environment: global.environment, runner: global.runner)
            var autopilot = LabAutopilot(settings: session.settings, now: Date())
            Output.line("watching; Ctrl-C stops (the session keeps running)")
            while !Task.isCancelled {
                let snapshot = try? await processes.snapshot()
                for request in autopilot.tick(now: Date(), processes: snapshot?.processes) {
                    do {
                        let response = try await client.send(request)
                        if let checkpoint = response.checkpoint {
                            Output.line("\(LabCommand.time(checkpoint.takenAt)) checkpoint \(checkpoint.id): \(checkpoint.label), \(checkpoint.changeCount) changes")
                        }
                    } catch {
                        Output.error("\(error)")
                    }
                }
                try await Task.sleep(nanoseconds: UInt64(LabAutopilot.pollSeconds * 1_000_000_000))
            }
        }
    }
}
