import Foundation
import SandvaultCore

/// Custom programs (D54): a host command such as `claude-lm` with the helpers it calls, the files it reads from the
/// home and the loopback ports it talks to. Commands go through `ToolAccess` (brew or a copy into `user/bin`), files
/// through the same checks as the configuration migration, ports become TCP exceptions to 127.0.0.1.
public struct ProgramMigration: ProgramService {
    public let tools: ToolAccess

    static let maxFileBytes = 1 << 20

    public init(environment: SandvaultEnvironment, runner: CommandRunner, configStore: ConfigStore, shared: SharedFiles? = nil) {
        tools = ToolAccess(environment: environment, runner: runner, configStore: configStore, shared: shared)
    }

    var layout: SharedLayout { tools.layout }
    var configStore: ConfigStore { tools.configStore }

    /// What a known helper needs besides itself; files that hold credentials still need the user's explicit allow.
    /// shortcut: one entry (LM Studio's CLI talks to the app on 41343 with the key in lms-key-2); add helpers as users bring them.
    static let knownHelpers: [String: (ports: [UInt16], files: [String])] = [
        "lms": ([41343], [".lmstudio/.internal/http-server.json", ".lmstudio/.internal/lms-key-2"]),
    ]

    /// Credentials SecretScan cannot recognise by name or content; they too need the user's explicit allow.
    static let knownSecrets: [String: String] = [".lmstudio/.internal/lms-key-2": "LM Studio's CLI key"]

    // MARK: - Suggestion

    public func suggest(_ name: String) async throws -> CustomProgram {
        try ToolAccess.validate(name: name)
        if let saved = try configStore.load().programs.first(where: { $0.name == name }) { return saved }
        let status = try await tools.status(of: name)
        guard let path = status.hostPath else { throw SandvaultError.invalidInput("\(name) is not on the host's PATH: \(status.reason)") }
        let real = HostPath.resolved(path) ?? path
        var program = CustomProgram(name: name)
        if (FileKind.size(real) ?? .max) <= Self.maxFileBytes, let data = FileManager.default.contents(atPath: real), data.starts(with: Array("#!".utf8)) {
            let found = Self.scan(String(decoding: data, as: UTF8.self))
            program.dependencies = found.commands.filter { $0 != name }
            program.hostPorts = found.ports
        }
        for helper in program.dependencies {
            guard let extra = Self.knownHelpers[helper] else { continue }
            program.hostPorts += extra.ports.filter { !program.hostPorts.contains($0) }
            program.files += extra.files.filter { !program.files.contains($0) }
        }
        // An agent wrapper passes its arguments on, so a hand-off task becomes the agent's first prompt.
        program.takesPrompt = program.dependencies.contains { HandoffCommandLine.promptArguments(AgentKind(rawValue: $0) ?? .shell, "") == [""] }
        return program
    }

    /// Commands a script looks up (`command -v jq`, `which fzf`) and loopback ports it names (`localhost:1234`).
    static func scan(_ text: String) -> (commands: [String], ports: [UInt16]) {
        var commands: [String] = []
        for name in captures(#"(?:command\s+-v|which)\s+([A-Za-z0-9._+-]{1,64})"#, in: text) where !commands.contains(name) {
            if (try? ToolAccess.validate(name: name)) != nil { commands.append(name) }
        }
        var ports: [UInt16] = []
        for value in captures(#"(?:localhost|127\.0\.0\.1|\[::1\]):([0-9]{2,5})\b"#, in: text) {
            if let port = UInt16(value), port > 0, !ports.contains(port) { ports.append(port) }
        }
        return (commands, ports)
    }

    private static func captures(_ pattern: String, in text: String) -> [String] {
        guard let regex = try? NSRegularExpression(pattern: pattern) else { return [] }
        return regex.matches(in: text, range: NSRange(text.startIndex..., in: text)).compactMap {
            Range($0.range(at: 1), in: text).map { String(text[$0]) }
        }
    }

    // MARK: - Migration

    public func migrate(_ program: CustomProgram) async throws -> ProgramReport {
        for command in [program.name] + program.dependencies { try ToolAccess.validate(name: command) }
        for file in program.files { try Self.validate(file: file) }
        guard Set(program.allowedSecrets).isSubset(of: program.files) else {
            throw SandvaultError.invalidInput("allowed credential files must be among the program's files")
        }
        guard !program.hostPorts.contains(0) else { throw SandvaultError.invalidInput("port 0 is not a port") }
        try layout.requireWorkspace()

        var steps: [ProgramStep] = []
        // Helpers first: a script copies only when the sandbox can run its interpreter.
        for command in program.dependencies + [program.name] {
            steps.append(await grant(command, preferCopy: command == program.name))
        }
        for file in program.files {
            steps.append(copy(file, allowSecret: program.allowedSecrets.contains(file)))
        }
        var config = try configStore.load()
        var firewallChanged = false
        for port in program.hostPorts {
            // Same identity as `NetworkPolicy.add` in SandvaultEnforce, which this module does not link.
            let added = !config.network.portExceptions.contains { $0.proto == .tcp && $0.destination == "127.0.0.1" && $0.port == port }
            if added {
                config.network.portExceptions.append(PortException(proto: .tcp, destination: "127.0.0.1", port: port, note: program.exceptionNote))
            }
            firewallChanged = firewallChanged || added
            steps.append(ProgramStep(kind: .port, subject: String(port), done: true,
                detail: added ? "TCP to 127.0.0.1:\(port) allowed once the firewall is applied" : "TCP to 127.0.0.1:\(port) was already allowed"))
        }
        var saved = program
        let previous = config.programs.first { $0.name == program.name }
        saved.migratedAt = steps.allSatisfy(\.done) ? Date() : previous?.migratedAt
        config.programs.removeAll { $0.name == program.name }
        config.programs.append(saved)
        try configStore.save(config)
        return ProgramReport(program: saved, steps: steps, firewallChanged: firewallChanged)
    }

    /// Available already, or the best grant; a program in the home copies rather than taking a Homebrew formula of the same name.
    private func grant(_ command: String, preferCopy: Bool) async -> ProgramStep {
        do {
            let status = try await tools.status(of: command)
            if status.reachableInSandbox { return ProgramStep(kind: .command, subject: command, done: true, detail: status.reason) }
            let copyFirst = (preferCopy || status.location == .hostHome) && status.options.contains(.copy)
            guard let method = copyFirst ? .copy : status.options.first else {
                return ProgramStep(kind: .command, subject: command, done: false, detail: status.reason + "; no automatic way, install it inside the sandbox")
            }
            let grant = try await tools.grant(command, method: method)
            return ProgramStep(kind: .command, subject: command, done: true, detail: "\(method.rawValue) from \(grant.source)")
        } catch {
            return ProgramStep(kind: .command, subject: command, done: false, detail: "\(error)")
        }
    }

    private func copy(_ relative: String, allowSecret: Bool) -> ProgramStep {
        func failed(_ detail: String) -> ProgramStep { ProgramStep(kind: .file, subject: relative, done: false, detail: detail) }
        let source = layout.environment.hostHome + "/" + relative
        switch FileKind.of(source) {
        case .missing: return failed("not found on the host")
        case .symlink: return failed("a symlink; name the file it points to instead")
        case .directory, .other: return failed("not a regular file")
        case .regular: break
        }
        guard (FileKind.size(source) ?? .max) <= Self.maxFileBytes else { return failed("larger than 1 MB") }
        guard let content = FileManager.default.contents(atPath: source) else { return failed("cannot read the file") }
        let base = ReadinessCheck.baseName(source)
        if !allowSecret, let reason = Self.knownSecrets[relative] ?? SecretScan.fileNameReason(base)
            ?? SecretScan.contentReason(String(decoding: content, as: UTF8.self), fileName: base) {
            return failed("\(reason); copy it only if you allow this credential in the sandbox")
        }
        do {
            try layout.shared.write(content, to: "\(layout.userRelative)/\(relative)", permissions: 0o640)
        } catch {
            return failed("\(error)")
        }
        return ProgramStep(kind: .file, subject: relative, done: true,
            detail: allowSecret ? "copied as an allowed credential; the sandbox can read it" : "copied, \(content.count) bytes")
    }

    /// A plain path below the home: relative, no `.` or `..`, no control characters.
    static func validate(file: String) throws {
        let parts = file.split(separator: "/", omittingEmptySubsequences: false)
        guard !file.isEmpty, !file.hasPrefix("/"), !Text.hasControlCharacters(file),
              parts.allSatisfy({ !$0.isEmpty && $0 != "." && $0 != ".." })
        else { throw SandvaultError.invalidInput("'\(file)' is not a path relative to the home") }
    }

    // MARK: - Removal

    public func remove(_ name: String) async throws {
        var config = try configStore.load()
        guard let program = config.programs.first(where: { $0.name == name }) else {
            throw SandvaultError.invalidInput("no custom program '\(name)'")
        }
        for file in program.files {
            try Self.validate(file: file)
            try layout.shared.remove("\(layout.userRelative)/\(file)")
        }
        if config.tools.contains(where: { $0.name == name && $0.method == .copy }) {
            try layout.shared.remove("\(layout.userRelative)/bin/\(name)")
            config.tools.removeAll { $0.name == name }
        }
        config.network.portExceptions.removeAll { $0.note == program.exceptionNote }
        config.programs.removeAll { $0.name == name }
        try configStore.save(config)
    }
}
