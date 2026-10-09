import ArgumentParser
import Foundation
import SandvaultCore
import SandvaultObserve

struct ViolationsCommand: AsyncParsableCommand {
    static let configuration = CommandConfiguration(
        commandName: "violations",
        abstract: "Watch sandbox denials in the unified log and suggest rules for them (learn mode).",
        discussion: """
        Follows `log stream`, which needs an administrator account. Live only: macOS does not keep the kernel's \
        sandbox reports in the log store, so there is no look back. Runs until interrupted, or for the time given \
        with --for and then prints a summary. Only denials of processes known to belong to the sandbox user are \
        shown unless --all is given; short-lived processes can exit before they are seen and then count as \
        unattributed.
        """
    )

    @OptionGroup var global: GlobalOptions

    @Option(name: .customLong("for"), help: "Stop after this time (30s, 5m, 1h).")
    var duration: String?

    @Flag(name: .long, help: "Include violations that cannot be attributed to the sandbox user.")
    var all = false

    @Flag(name: .long, help: "Propose allow rules for the violations seen (needs --for).")
    var suggest = false

    func validate() throws {
        if suggest && duration == nil { throw ValidationError("--suggest needs a finished window; add --for, e.g. --for 2m") }
        if let duration {
            do {
                _ = try ViolationMonitor.duration(duration)
            } catch {
                throw ValidationError("\(error)")
            }
        }
    }

    struct ViolationsOutput: Encodable {
        var violations: [SandboxViolation]
        var suggestions: [RuleSuggestion]?
    }

    func run() async throws {
        try ObservePlatform.require("violations")
        let monitor = ViolationMonitor(environment: global.environment, runner: global.runner)
        let all = all, json = global.json
        let printLive: @Sendable (SandboxViolation) -> Void = { violation in
            guard all || violation.attributedToSandbox, !json else { return }
            Output.line(Self.row(violation).joined(separator: "  "))
        }

        guard let duration else {
            if !json { Output.line("watching for sandbox violations (Ctrl-C to stop)") }
            for try await violation in monitor.stream() where all || violation.attributedToSandbox {
                if json {
                    FileHandle.standardOutput.write(try ControlCodec.encode(violation))
                } else {
                    printLive(violation)
                }
            }
            return
        }

        if !json { Output.line("watching for sandbox violations for \(duration)") }
        let found = try await monitor.collect(for: try ViolationMonitor.duration(duration), onEach: printLive)
        let shown = all ? found : found.filter(\.attributedToSandbox)
        let suggestions = suggest ? RuleSuggester.suggestions(for: shown, environment: global.environment) : nil
        if json { return try Output.json(ViolationsOutput(violations: shown, suggestions: suggestions)) }

        if shown.isEmpty { Output.line("no sandbox violations in \(duration)") }
        let hidden = found.count - shown.count
        if hidden > 0 { Output.line("\(hidden) more from processes not attributed to the sandbox user (--all shows them)") }

        if let suggestions {
            Output.line()
            if suggestions.isEmpty { Output.line("no rule suggestions (network denials are handled by the firewall)") }
            for suggestion in suggestions {
                Output.line("\(Self.describe(suggestion.proposal))  (\(suggestion.occurrences)x by \(suggestion.processes.joined(separator: ", ")))")
                for example in suggestion.examples { Output.line("    \(example)") }
                if case .file(let rule) = suggestion.proposal, let note = rule.note { Output.line("    note: \(note)") }
            }
        }
    }

    static func row(_ violation: SandboxViolation) -> [String] {
        [
            Format.time(violation.timestamp), String(violation.pid), violation.process + (violation.attributedToSandbox ? "" : " (?)"),
            String(violation.occurrences), violation.operation, violation.target ?? "-",
        ]
    }

    static func describe(_ proposal: RuleSuggestion.Proposal) -> String {
        switch proposal {
        case .file(let rule): "allow file-\(rule.access.rawValue) \(rule.match.rawValue) \(rule.path)"
        case .mach(let rule): "allow mach-lookup \(rule.name)"
        case .exec(let rule): "allow process-exec \(rule.path)"
        }
    }
}
