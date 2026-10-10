import ArgumentParser
import Foundation
import SandvaultCore
import SandvaultObserve

struct ActivityCommand: AsyncParsableCommand {
    static let configuration = CommandConfiguration(
        commandName: "activity",
        abstract: "Record and show the files and programs the sandbox touches.",
        discussion: """
            Recording runs macOS's eslogger through the root helper (reinstall it after an update with \
            `svctl helper install`), which needs Full Disk Access for the terminal or app that starts it. \
            Only the sandbox user's processes are recorded; what is stored follows Settings > Recording.
              svctl activity record
              svctl activity show --since 10m
              svctl activity clear
            """,
        subcommands: [Record.self, Show.self, Clear.self],
        defaultSubcommand: Show.self
    )

    struct Record: AsyncParsableCommand {
        static let configuration = CommandConfiguration(abstract: "Record in the foreground and print each event (Ctrl-C to stop).")
        @OptionGroup var global: GlobalOptions

        @Flag(name: .long, help: "Keep every open and close and system file reads, whatever the settings say.")
        var all = false

        @Flag(name: .customLong("no-store"), help: "Print only; do not add the events to the activity log.")
        var noStore = false

        func run() async throws {
            try ObservePlatform.require("activity record")
            var settings = try global.configStore.load().activity
            if all {
                settings.openAndClose = true
                settings.hideSystemFiles = false
            }
            let recorder = LiveActivityRecorder(paths: global.paths, runner: global.runner, stores: !noStore)
            if !global.json { Output.line("recording files and programs of \(global.environment.sandvaultUser) (Ctrl-C to stop)") }
            for try await event in recorder.record(settings: settings) {
                if global.json {
                    FileHandle.standardOutput.write(try JSONCoding.lineEncoder.encode(event) + Data("\n".utf8))
                } else {
                    Output.line(ActivityCommand.row(event).joined(separator: "  "))
                }
            }
        }
    }

    struct Show: AsyncParsableCommand {
        static let configuration = CommandConfiguration(abstract: "Print the stored events, oldest first.")
        @OptionGroup var global: GlobalOptions

        @Option(name: .long, help: "Only events of the last 30s, 10m, 2h ...")
        var since: String?

        func validate() throws {
            if let since {
                do { _ = try ViolationMonitor.duration(since) } catch { throw ValidationError("\(error)") }
            }
        }

        func run() async throws {
            let settings = try global.configStore.load().activity
            let start = try since.map { Date().addingTimeInterval(-ActivityCommand.seconds(try ViolationMonitor.duration($0))) }
            let recorder = LiveActivityRecorder(paths: global.paths, runner: global.runner)
            let events = try await recorder.stored(since: start, retentionDays: settings.retentionDays)
            if global.json { return try Output.json(events) }
            if events.isEmpty { return Output.line("no activity recorded" + (since.map { " in the last \($0)" } ?? "")) }
            for event in events { Output.line(ActivityCommand.row(event).joined(separator: "  ")) }
        }
    }

    struct Clear: AsyncParsableCommand {
        static let configuration = CommandConfiguration(abstract: "Delete the stored events.")
        @OptionGroup var global: GlobalOptions

        func run() async throws {
            let recorder = LiveActivityRecorder(paths: global.paths, runner: global.runner)
            let bytes = await recorder.storageBytes()
            try await recorder.clear()
            if global.json { return try Output.json(["cleared": bytes]) }
            Output.line("activity log cleared (\(Format.bytes(bytes)))")
        }
    }

    static func seconds(_ duration: Duration) -> TimeInterval {
        Double(duration.components.seconds)
    }

    /// `12:00:01  claude(812)  changed  /Users/Shared/sv-alice/notes.txt`.
    static func row(_ event: FileActivityEvent) -> [String] {
        [Format.time(event.timestamp), "\(event.process)(\(event.pid))", verb(event), target(event)]
    }

    static func verb(_ event: FileActivityEvent) -> String {
        switch event.kind {
        case .exec: "started"
        case .open: event.forWriting ? "opened to write" : "read"
        case .close: event.modified ? "changed" : "closed"
        case .create: "created"
        case .write: "wrote"
        case .rename: "renamed"
        case .delete: "deleted"
        }
    }

    static func target(_ event: FileActivityEvent) -> String {
        switch event.kind {
        case .exec:
            Format.command(([event.path] + event.arguments.dropFirst()).joined(separator: " "))
        case .rename:
            "\(event.path) -> \(event.destination ?? "?")"
        default:
            event.path
        }
    }
}
