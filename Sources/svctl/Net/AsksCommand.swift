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
              svctl asks --answer 5e6f7a8b deny-always --port
            """
    )

    @OptionGroup var global: GlobalOptions
    @Option(help: "Answer the pending ask whose id starts with this.") var answer: String?
    @Argument(help: "With --answer: allow-once, allow-always, deny-once or deny-always.") var decision: String?
    @Flag(help: "With an *-always answer: save the rule for *.<domain> instead of the exact host.") var domain = false
    @Flag(help: "With an *-always answer: save the rule for the exact host and only the ask's port.") var port = false
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
            guard !(domain && port) else { throw ValidationError("--domain and --port cannot be combined") }
        } else if decision != nil || domain || port {
            throw ValidationError("a decision, --domain and --port only go with --answer <id-prefix>")
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
            let scope: AskScope = domain ? .domain : port ? .hostAndPort : .host
            try await client.answer(AskAnswer(id: ask.id, decision: decision, scope: scope))
            if global.json { return try Output.json(["id": ask.id.uuidString.lowercased(), "decision": decision.rawValue]) }
            let pattern = DomainRule(
                pattern: RegistrableDomain.rulePattern(for: ask.host, scope: scope), action: .allow, port: scope == .hostAndPort ? ask.port : nil
            ).displayPattern
            let rule = decision == .allowAlways || decision == .denyAlways ? " (rule \(pattern))" : ""
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
        for ask in pending where ask.details != nil {
            Output.line()
            Output.line(Self.row(ask)[0])
            for line in Self.detailLines(ask) { Output.line(line) }
        }
    }

    /// The details netd collected, one per line, then the assessment and its signals.
    static func detailLines(_ ask: AskRequest) -> [String] {
        guard let details = ask.details else { return [] }
        var lines: [String] = []
        if let address = details.address { lines.append("address   \(address)") }
        if let name = details.name {
            lines.append("name      " + (name.name.map { "\($0) (from \(name.source.rawValue))" } ?? "none, IP address only"))
        }
        if let reverse = details.reverseName { lines.append("reverse   " + (reverse.isEmpty ? "no PTR name" : reverse)) }
        if let service = details.service { lines.append("port      \(service.port) \(service.name ?? "(not in any list)")") }
        if let network = details.network {
            let parts = [network.owner, network.asn.map { "AS\($0)" }, network.country, network.kind.rawValue, network.source.rawValue]
            lines.append("network   " + parts.compactMap { $0 }.joined(separator: ", "))
        }
        if let encryption = details.encryption { lines.append("protocol  \(encryption)") }
        if let history = details.history {
            let seen = history.lastSeen.map { ", last \(NetCLI.timestamp($0))" } ?? ""
            lines.append("history   \(history.allowed) allowed, \(history.denied) denied\(seen)")
        }
        if let program = details.program {
            let signature: String
            switch program.signature {
            case .apple: signature = "Apple"
            case .developer(let team): signature = "developer" + (team.map { " \($0)" } ?? "")
            case .adHoc: signature = "ad hoc"
            case .unsigned: signature = "unsigned"
            case .unknown: signature = "signature unknown"
            }
            lines.append("program   \(program.path ?? "?") (\(signature)\(program.inTemporaryFolder ? ", temporary folder" : ""))")
        }
        if let assessment = details.assessment {
            lines.append("verdict   \(assessment.level.rawValue), \(assessment.score) points")
            for signal in assessment.signals {
                let points = signal.points > 0 ? "+\(signal.points)" : "\(signal.points)"
                lines.append("  \(points.padding(toLength: 3, withPad: " ", startingAt: 0)) \(signal.text)")
            }
        }
        return lines.map { "  " + $0 }
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
            for line in Self.detailLines(ask) { Output.line(line) }
        case .askResolved(let id, let decision):
            if global.json { return FileHandle.standardOutput.write(try ControlCodec.encode(event)) }
            Output.line("RESOLVED \(NetCLI.shortID(id))  \(decision.rawValue)")
        default:
            break
        }
    }
}
