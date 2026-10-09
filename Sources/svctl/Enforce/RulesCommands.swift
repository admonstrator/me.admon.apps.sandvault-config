import ArgumentParser
import Foundation
import SandvaultCore
import SandvaultEnforce

struct RulesCommand: AsyncParsableCommand {
    static let configuration = CommandConfiguration(
        commandName: "rules",
        abstract: "Sandbox rules: the managed block at the end of sv's sandbox profile.",
        discussion: """
        Rules are stored in config.json; `apply` validates them with sandbox-exec and writes the block through the \
        root helper. SBPL is last-match-wins, so these rules override sv's. Paths must be absolute real paths \
        (/private/tmp, not /tmp).
        """,
        subcommands: [List.self, Add.self, Mach.self, Exec.self, Remove.self, Preset.self, Preview.self, Diff.self, Apply.self, Reset.self, Status.self]
    )
}

extension RulesCommand {
    struct List: AsyncParsableCommand {
        static let configuration = CommandConfiguration(abstract: "List the preset and the configured rules.")
        @OptionGroup var global: GlobalOptions

        func run() async throws {
            let sandbox = try global.configStore.load().sandbox
            if global.json { return try Output.json(sandbox) }
            Output.line("preset: \(sandbox.preset.rawValue)" + (sandbox.preset == .hardened ? " (\(HardenedPreset.entries.count) denials, see svctl rules preview)" : ""))
            guard !sandbox.rules.isEmpty else { return Output.line("no rules") }
            Output.table(["ID", "KIND", "EFFECT", "RULE", "NOTE"], sandbox.rules.map {
                [EnforceCLI.shortID($0.id), $0.kind, $0.effect.rawValue, $0.summary, $0.note ?? ""]
            })
        }
    }

    struct Add: AsyncParsableCommand {
        static let configuration = CommandConfiguration(abstract: "Add a file rule (allow unless --deny).")
        @OptionGroup var global: GlobalOptions
        @Argument(help: "read, write or rw.") var access: EnforceCLI.AccessArgument
        @Argument(help: "Absolute path.") var path: String
        @Flag var match: EnforceCLI.MatchFlag = .subpath
        @Flag(name: .long, help: "Deny instead of allow.") var deny = false
        @Option(name: .long, help: "Free-text note, shown in the generated block.") var note: String?

        func run() async throws {
            let rule = FileRule(path: path, match: match.match, access: access.access, effect: deny ? .deny : .allow, note: note)
            try RulesCommand.edit(global) { try $0.add(rule) }
        }
    }

    struct Mach: AsyncParsableCommand {
        static let configuration = CommandConfiguration(abstract: "Allow or deny a mach service lookup.")
        @OptionGroup var global: GlobalOptions
        @Argument(help: "allow or deny.") var effect: EnforceCLI.EffectArgument
        @Argument(help: "Mach service name, e.g. com.apple.pasteboard.1.") var name: String
        @Option(name: .long, help: "Free-text note.") var note: String?

        func run() async throws {
            try RulesCommand.edit(global) { try $0.add(MachRule(name: name, effect: effect.effect, note: note)) }
        }
    }

    struct Exec: AsyncParsableCommand {
        static let configuration = CommandConfiguration(abstract: "Deny or allow executing a program.")
        @OptionGroup var global: GlobalOptions
        @Argument(help: "deny or allow.") var effect: EnforceCLI.EffectArgument
        @Argument(help: "Absolute path of the executable.") var path: String
        @Option(name: .long, help: "Free-text note.") var note: String?

        func run() async throws {
            try RulesCommand.edit(global) { try $0.add(ExecRule(path: path, effect: effect.effect, note: note)) }
        }
    }

    struct Remove: AsyncParsableCommand {
        static let configuration = CommandConfiguration(abstract: "Remove a rule by id prefix (see svctl rules list).")
        @OptionGroup var global: GlobalOptions
        @Argument(help: "First characters of the rule id (at least 4).") var idPrefix: String

        func run() async throws {
            var config = try global.configStore.load()
            let removed = try config.sandbox.removeRule(idPrefix: idPrefix)
            try global.configStore.save(config)
            if global.json { return try Output.json(["removed": removed.id.uuidString.lowercased()]) }
            Output.line("removed \(EnforceCLI.shortID(removed.id)) \(removed.effect.rawValue) \(removed.summary); run svctl rules apply")
        }
    }

    struct Preset: AsyncParsableCommand {
        static let configuration = CommandConfiguration(abstract: "Select the preset: standard (sv's profile) or hardened (opt-in denials).")
        @OptionGroup var global: GlobalOptions
        @Argument(help: "standard or hardened.") var preset: EnforceCLI.PresetArgument

        func run() async throws {
            var config = try global.configStore.load()
            config.sandbox.preset = preset.preset
            try global.configStore.save(config)
            if global.json { return try Output.json(config.sandbox) }
            Output.line("preset: \(preset.rawValue); run svctl rules apply")
            if preset == .hardened {
                Output.line("The hardened preset is conservative but unverified on your macOS release; try it with sv shell first.")
                for entry in HardenedPreset.entries {
                    let target = switch entry.kind {
                    case .exec(let path): "exec \(path)"
                    case .mach(let name): "mach \(name)"
                    }
                    Output.line("  deny \(target): \(entry.reason)")
                }
            }
        }
    }

    struct Preview: AsyncParsableCommand {
        static let configuration = CommandConfiguration(abstract: "Print the managed block the config generates.")
        @OptionGroup var global: GlobalOptions

        func run() async throws {
            let body = try SBPLGenerator.block(for: try global.configStore.load().sandbox)
            if global.json { return try Output.json(["block": body]) }
            guard let body else { return Output.line("no block: standard preset and no rules") }
            print(ManagedBlock.sandboxProfile.replace(in: "", with: body), terminator: "")
        }
    }

    struct Diff: AsyncParsableCommand {
        static let configuration = CommandConfiguration(abstract: "Show what apply would change in sv's profile.")
        @OptionGroup var global: GlobalOptions
        @Option(name: .long, help: "Diff against this file instead of sv's profile (e.g. a copy).") var profile: String?

        func run() async throws {
            let plan = try RulesCommand.plan(global, profile: profile, requireProfile: true)
            if global.json { return try Output.json(plan) }
            Output.line("drift: \(plan.drift.rawValue)" + (plan.svPartChanged ? " (sv rewrote its part since the last apply)" : ""))
            Output.line(plan.hasChanges ? plan.unifiedDiff : "no changes")
        }
    }

    struct Apply: AsyncParsableCommand {
        static let configuration = CommandConfiguration(abstract: "Validate and write the managed block (root helper).")
        @OptionGroup var global: GlobalOptions
        @Flag(name: .long, help: "Do not ask for confirmation.") var yes = false

        func run() async throws {
            try EnforceCLI.requireMacOS("rules apply")
            let config = try global.configStore.load()
            let plan = try RulesCommand.plan(global, profile: nil, requireProfile: true)
            guard plan.hasChanges else {
                return try EnforceCLI.report(HelperResult(ok: true, message: "profile already matches the config"), json: global.json)
            }
            if !global.json {
                if plan.svPartChanged { Output.line("note: sv rewrote its part of the profile since the last apply") }
                Output.line(plan.unifiedDiff)
            }
            guard try EnforceCLI.confirm("Write this to \(plan.profilePath)?", yes: yes, json: global.json) else { throw ExitCode.failure }
            let result = try await EnforceCLI.applier(global).applyProfile(AppliedState(config: config))
            try EnforceCLI.report(result, json: global.json)
        }
    }

    struct Reset: AsyncParsableCommand {
        static let configuration = CommandConfiguration(abstract: "Remove the managed block (sv's profile as sv wrote it).")
        @OptionGroup var global: GlobalOptions
        @Flag(name: .long, help: "Do not ask for confirmation.") var yes = false

        func run() async throws {
            try EnforceCLI.requireMacOS("rules reset")
            guard try EnforceCLI.confirm("Remove the managed block from \(global.environment.sandboxProfilePath)?", yes: yes, json: global.json) else {
                throw ExitCode.failure
            }
            try EnforceCLI.report(try await EnforceCLI.applier(global).resetProfile(), json: global.json)
        }
    }

    struct Status: AsyncParsableCommand {
        static let configuration = CommandConfiguration(abstract: "Profile block drift and rule counts.")
        @OptionGroup var global: GlobalOptions

        struct Report: Encodable {
            var profilePath: String
            var drift: ProfileDrift
            var svPartChanged: Bool
            var preset: SandboxPreset
            var rules: Int
        }

        func run() async throws {
            let sandbox = try global.configStore.load().sandbox
            let plan = try RulesCommand.plan(global, profile: nil, requireProfile: false)
            let report = Report(profilePath: plan.profilePath, drift: plan.drift, svPartChanged: plan.svPartChanged, preset: sandbox.preset, rules: sandbox.rules.count)
            if global.json { return try Output.json(report) }
            Output.line("profile: \(report.profilePath)")
            Output.line("drift: \(report.drift.rawValue)")
            if report.svPartChanged { Output.line("sv rewrote its part of the profile since the last apply") }
            Output.line("preset: \(report.preset.rawValue), rules: \(report.rules)")
        }
    }

    /// Load, change, save; prints the id of the rule now in effect.
    static func edit(_ global: GlobalOptions, _ change: (inout SandboxSettings) throws -> UUID) throws {
        var config = try global.configStore.load()
        let id = try change(&config.sandbox)
        try global.configStore.save(config)
        if global.json { return try Output.json(["id": id.uuidString.lowercased()]) }
        Output.line("rule \(EnforceCLI.shortID(id)) in config; run svctl rules apply")
    }

    static func plan(_ global: GlobalOptions, profile: String?, requireProfile: Bool) throws -> ProfilePlan {
        let sandbox = try global.configStore.load().sandbox
        let inspector = profile.map { ProfileInspector(profilePath: $0) } ?? ProfileInspector(environment: global.environment)
        let plan = try inspector.plan(for: sandbox)
        if requireProfile, plan.current == nil {
            throw SandvaultError.notInstalled("sandbox profile \(inspector.profilePath) not found (pass --profile <file> to diff against a copy)")
        }
        return plan
    }
}
