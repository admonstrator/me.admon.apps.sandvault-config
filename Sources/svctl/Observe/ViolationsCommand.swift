import ArgumentParser
import Foundation
import SandvaultCore
import SandvaultObserve

struct ViolationsCommand: AsyncParsableCommand {
    static let configuration = CommandConfiguration(
        commandName: "violations",
        abstract: "Show sandbox denials from the unified log and suggest rules for them (learn mode).",
        discussion: """
        Reads `log show` (or `log stream` with --follow), which needs an administrator account. macOS 27 does \
        not keep the kernel's sandbox reports in the log store, so `log show` rarely finds any; --follow sees \
        them as they happen. Only denials of \
        processes known to belong to the sandbox user are shown unless --all is given; short-lived processes can \
        exit before they are seen and then count as unattributed.
        """
    )

    @OptionGroup var global: GlobalOptions

    @Option(name: .long, help: "Time window for `log show`: a number with m, h or d.")
    var last = "10m"

    @Flag(name: .long, help: "Stream new violations until interrupted.")
    var follow = false

    @Flag(name: .long, help: "Include violations that cannot be attributed to the sandbox user.")
    var all = false

    @Flag(name: .long, help: "Propose allow rules for the violations shown.")
    var suggest = false

    func validate() throws {
        if follow && suggest { throw ValidationError("--suggest works on a finished window; use --last instead of --follow") }
        do {
            try ViolationMonitor.validate(duration: last)
        } catch {
            throw ValidationError("\(error)")
        }
    }

    struct ViolationsOutput: Encodable {
        var violations: [SandboxViolation]
        var suggestions: [RuleSuggestion]?
    }

    func run() async throws {
        try ObservePlatform.require("violations")
        let monitor = ViolationMonitor(environment: global.environment, runner: global.runner)
        if follow {
            if !global.json { Output.line("watching for sandbox violations (Ctrl-C to stop)") }
            for try await violation in monitor.stream() where all || violation.attributedToSandbox {
                if global.json {
                    FileHandle.standardOutput.write(try ControlCodec.encode(violation))
                } else {
                    Output.line(Self.row(violation).joined(separator: "  "))
                }
            }
            return
        }

        let found = try await monitor.recent(last: last)
        let shown = all ? found : found.filter(\.attributedToSandbox)
        let suggestions = suggest ? RuleSuggester.suggestions(for: shown, environment: global.environment) : nil
        if global.json { return try Output.json(ViolationsOutput(violations: shown, suggestions: suggestions)) }

        if shown.isEmpty {
            Output.line("no sandbox violations in the last \(last)")
            Output.line("macOS does not keep sandbox denials in the log store; --follow shows them as they happen")
        } else {
            Output.table(["TIME", "PID", "PROCESS", "COUNT", "OPERATION", "TARGET"], shown.map(Self.row))
        }
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
