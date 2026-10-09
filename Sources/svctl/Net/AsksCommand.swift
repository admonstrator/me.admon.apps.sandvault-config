import ArgumentParser
import Foundation
import SandvaultCore
import SandvaultNet

struct NetAsksCommand: AsyncParsableCommand {
    static let configuration = CommandConfiguration(
        commandName: "asks",
        abstract: "Pending connection asks: list, answer, or watch them.",
        discussion: """
            netd raises asks only while a client watches them (this command with --follow, or the app); \
            otherwise the ask fallback applies at once.
              svctl asks --follow
              svctl asks --answer 1a2b3c4d allow-always --domain
            """
    )

    @OptionGroup var global: GlobalOptions
    @Option(help: "Answer the pending ask whose id starts with this.") var answer: String?
    @Argument(help: "With --answer: allow-once, allow-always, deny-once or deny-always.") var decision: String?
    @Flag(help: "With an *-always answer: save the rule for *.<domain> instead of the exact host.") var domain = false
    @Flag(help: "Watch for asks and their resolution until interrupted.") var follow = false

    static let decisions: [String: AskDecision] = [
        "allow-once": .allowOnce, "allow-always": .allowAlways, "deny-once": .denyOnce, "deny-always": .denyAlways,
    ]

    func validate() throws {
        if answer != nil {
            guard let decision, Self.decisions[decision.lowercased()] != nil else {
                throw ValidationError("--answer needs a decision: allow-once, allow-always, deny-once or deny-always")
            }
            guard !follow else { throw ValidationError("--answer and --follow cannot be combined") }
        } else if decision != nil || domain {
            throw ValidationError("a decision and --domain only go with --answer <id-prefix>")
        }
    }

    func run() async throws {
        let client = try await ControlClient.connect(socketPath: NetCLI.socketPath(global))
        defer { client.close() }

        if let prefix = answer?.lowercased(), let text = decision?.lowercased(), let decision = Self.decisions[text] {
            let matches = try await client.pendingAsks().filter { $0.id.uuidString.lowercased().hasPrefix(prefix) }
            guard matches.count == 1, let ask = matches.first else {
                throw SandvaultError.invalidInput(matches.isEmpty ? "no pending ask matches '\(prefix)'" : "'\(prefix)' matches several asks")
            }
            try await client.answer(AskAnswer(id: ask.id, decision: decision, scope: domain ? .domain : .host))
            if global.json { return try Output.json(["id": ask.id.uuidString.lowercased(), "decision": decision.rawValue]) }
            let rule = decision == .allowAlways || decision == .denyAlways
                ? " (rule \(RegistrableDomain.rulePattern(for: ask.host, scope: domain ? .domain : .host)))" : ""
            Output.line("\(text) \(ask.host)\(rule)")
            return
        }

        if follow {
            try await client.subscribe([.asks])
            for ask in try await client.pendingAsks() { try emit(.ask(ask)) }
            for await event in client.events { try emit(event) }
            throw SandvaultError.io("netd closed the control connection")
        }

        let pending = try await client.pendingAsks()
        if global.json { return try Output.json(pending) }
        guard !pending.isEmpty else { return Output.line("no pending asks") }
        Output.table(["ID", "HOST", "PORT", "KIND", "PROCESS", "EXPIRES"], pending.map(Self.row))
    }

    static func row(_ ask: AskRequest) -> [String] {
        let process = ask.process.map { "\($0)(\(ask.pid.map(String.init) ?? "?"))" } ?? ""
        return [NetCLI.shortID(ask.id), ask.host, ask.port.map(String.init) ?? "dns", ask.kind.rawValue, process, NetCLI.timestamp(ask.expiresAt)]
    }

    private func emit(_ event: ControlEvent) throws {
        switch event {
        case .ask(let ask):
            if global.json { return FileHandle.standardOutput.write(try ControlCodec.encode(ask)) }
            let row = Self.row(ask)
            Output.line("ASK \(row[0])  \(row[1]):\(row[2])  \(row[3])  \(row[4])  (answer: svctl asks --answer \(row[0]) allow-once)")
        case .askResolved(let id, let decision):
            if global.json { return FileHandle.standardOutput.write(try ControlCodec.encode(event)) }
            Output.line("RESOLVED \(NetCLI.shortID(id))  \(decision.rawValue)")
        default:
            break
        }
    }
}
