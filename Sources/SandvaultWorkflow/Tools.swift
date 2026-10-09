import Foundation
import SandvaultCore

/// Whether a host command works inside the sandbox, and making it available (`brew install` or a copy into
/// `$SHARED_WORKSPACE/user/bin`, which sv's `.zprofile` puts first on the sandbox's PATH).
/// `status` only looks; side effects happen in `grant`.
public struct ToolAccess: ToolService {
    public let layout: SharedLayout
    public let runner: CommandRunner
    public let configStore: ConfigStore
    /// `brew` on the host, when installed.
    public let brewPath: String?

    static let maxCopyBytes = 256 << 20

    public init(
        environment: SandvaultEnvironment, runner: CommandRunner, configStore: ConfigStore,
        shared: SharedFiles? = nil, brewPath: String? = ToolAccess.defaultBrewPath()
    ) {
        layout = SharedLayout(environment: environment, shared: shared)
        self.runner = runner
        self.configStore = configStore
        self.brewPath = brewPath
    }

    public static func defaultBrewPath() -> String? {
        ["/opt/homebrew/bin/brew", "/usr/local/bin/brew"].first { FileManager.default.isExecutableFile(atPath: $0) }
    }

    public static func validate(name: String) throws {
        guard Text.matches(name, "^[A-Za-z0-9._+-]{1,64}$"), name != ".", name != ".." else {
            throw SandvaultError.invalidInput("'\(name)' is not a command name ([A-Za-z0-9._+-], at most 64 characters)")
        }
    }

    public func status(of name: String) async throws -> ToolStatus {
        try Self.validate(name: name)
        let environment = layout.environment
        let lookup = try await runner.run(CommandInvocation("/bin/zsh", ["-lc", "command -v -- " + ShellQuoting.quote(name)], timeout: 15))
        let found = lookup.succeeded ? Text.lines(lookup.stdoutString).first?.trimmingCharacters(in: .whitespaces) : nil

        var status = ToolStatus(name: name, hostPath: nil, location: .missing, reachableInSandbox: false, reason: "")
        var copyable = false
        if let found, found.hasPrefix("/") {
            let real = HostPath.resolved(found) ?? found
            status.hostPath = found
            status.location = Self.location(of: found, resolved: real, environment: environment)
            let inspection = try await inspect(real)
            status.kind = inspection.kind
            copyable = inspection.copyable
            status.formula = Self.cellarFormula(real)
        } else if let found, !found.isEmpty {
            status.kind = "shell builtin, alias or function (\(found))"
        }
        switch try await sandboxLookup(name) {
        case .found(let path):
            status.reachableInSandbox = true
            status.reason = "the sandbox finds it at \(path)"
            status.options = [.available]
            return status
        case .missing:
            status.reason = Self.reason(for: status)
        case .unknown(let why):
            status.reason = "could not check inside the sandbox: \(why)"
        }
        if status.formula == nil, status.location != .homebrew {
            status.formula = try await brewFormula(name)
        }
        if status.formula != nil, status.location != .homebrew, brewPath != nil { status.options.append(.brew) }
        if copyable, status.hostPath != nil { status.options.append(.copy) }
        return status
    }

    public func grant(_ name: String, method: ToolGrantMethod) async throws -> ToolGrant {
        let before = try await status(of: name)
        let source: String
        switch method {
        case .available:
            guard before.reachableInSandbox else { throw SandvaultError.invalidInput("\(name) is not available in the sandbox: \(before.reason)") }
            source = before.hostPath ?? name
        case .brew:
            guard let formula = before.formula, let brewPath else {
                throw SandvaultError.invalidInput("no Homebrew formula is known for \(name)")
            }
            guard Text.matches(formula, "^[A-Za-z0-9@._+-]+(/[A-Za-z0-9@._+-]+)*$") else {
                throw SandvaultError.invalidInput("unexpected formula name '\(formula)'")
            }
            _ = try await runner.checked(CommandInvocation(brewPath, ["install", formula], timeout: 1800))
            source = formula
        case .copy:
            guard before.options.contains(.copy), let hostPath = before.hostPath else {
                throw SandvaultError.invalidInput("\(name) cannot be copied: \(before.kind ?? before.reason)")
            }
            let real = HostPath.resolved(hostPath) ?? hostPath
            guard let size = FileKind.size(real), size <= Self.maxCopyBytes else {
                throw SandvaultError.invalidInput("\(real) is not a regular file of at most \(Self.maxCopyBytes >> 20) MB")
            }
            try layout.requireWorkspace()
            let data = try Data(contentsOf: URL(fileURLWithPath: real))
            try layout.shared.write(data, to: "\(layout.userRelative)/bin/\(name)", permissions: 0o750)
            source = real
        }
        let after = method == .available ? before : try await status(of: name)
        guard after.reachableInSandbox else {
            throw SandvaultError.io("\(method.rawValue) finished, but the sandbox still cannot run \(name): \(after.reason)")
        }
        let grant = ToolGrant(name: name, source: source, method: method)
        var config = try configStore.load()
        config.tools.removeAll { $0.name == name }
        config.tools.append(grant)
        try configStore.save(config)
        return grant
    }

    // MARK: - Sandbox lookup

    enum SandboxLookup: Equatable {
        case found(String)
        case missing
        case unknown(String)
    }

    static let marker = "sandvault-config:lookup"

    /// `command -v` as the sandbox user with sv's session environment and inside sv's profile, so whatever the
    /// sandbox put into its shell files runs sandboxed, as it does in a session.
    public static func sandboxLookupInvocation(_ environment: SandvaultEnvironment, name: String) -> CommandInvocation {
        let script = "source ~/.zshenv; source ~/.zprofile; print -r -- \(marker); command -v -- \(ShellQuoting.quote(name))"
        return CommandInvocation.asSandvault(environment, "-i", [
            "HOME=\(environment.sandvaultHome)", "USER=\(environment.sandvaultUser)", "SHELL=/bin/zsh",
            "SHARED_WORKSPACE=\(environment.sharedWorkspace)", "PATH=/usr/bin:/bin:/usr/sbin:/sbin",
            "/usr/bin/sandbox-exec", "-f", environment.sandboxProfilePath, "/bin/zsh", "-c", script,
        ], timeout: 20)
    }

    func sandboxLookup(_ name: String) async throws -> SandboxLookup {
        let result: CommandResult
        do {
            result = try await runner.run(Self.sandboxLookupInvocation(layout.environment, name: name))
        } catch {
            return .unknown("\(error)")
        }
        return Self.parseLookup(result)
    }

    static func parseLookup(_ result: CommandResult) -> SandboxLookup {
        let lines = Text.lines(result.stdoutString)
        guard let index = lines.lastIndex(of: marker) else {
            let detail = result.stderrString.trimmingCharacters(in: .whitespacesAndNewlines)
            return .unknown(detail.isEmpty ? "exit \(result.exitCode)" : detail)
        }
        if result.succeeded, let path = lines.dropFirst(index + 1).first { return .found(path) }
        return .missing
    }

    // MARK: - Classification

    static func location(of path: String, resolved: String, environment: SandvaultEnvironment) -> ToolLocation {
        for candidate in [path, resolved] {
            if HostPath.isInside(candidate, environment.sharedUserDir) { return .sharedUser }
            if HostPath.isInside(candidate, environment.sandvaultHome) { return .sandboxHome }
            if HostPath.isInside(candidate, environment.hostHome) { return .hostHome }
        }
        if resolved.hasPrefix("/opt/homebrew/") || resolved.hasPrefix("/home/linuxbrew/.linuxbrew/")
            || ["/usr/local/Cellar/", "/usr/local/Caskroom/", "/usr/local/Homebrew/", "/usr/local/opt/"].contains(where: resolved.hasPrefix) {
            return .homebrew
        }
        return .system
    }

    static func reason(for status: ToolStatus) -> String {
        guard let path = status.hostPath else {
            return status.kind == nil ? "not installed on the host either" : "not a program on the host: \(status.kind ?? "")"
        }
        switch status.location {
        case .hostHome: return "\(path) is in your home, which the sandbox cannot read"
        case .homebrew: return "\(path) is a Homebrew path the sandbox does not reach; run svctl doctor (homebrew.permissions)"
        case .sharedUser: return "\(path) is in the shared user directory but the sandbox shell does not find it"
        case .sandboxHome: return "\(path) is in the sandbox home but not on the sandbox's PATH"
        case .system, .missing: return "\(path) is not on the sandbox's PATH or not readable for it"
        }
    }

    /// `<prefix>/Cellar/<formula>/<version>/...` names the formula.
    static func cellarFormula(_ resolved: String) -> String? {
        guard let range = resolved.range(of: "/Cellar/") else { return nil }
        let formula = resolved[range.upperBound...].split(separator: "/").first.map(String.init)
        return formula.flatMap { $0.isEmpty ? nil : $0 }
    }

    private func brewFormula(_ name: String) async throws -> String? {
        guard let brewPath else { return nil }
        let result = try? await runner.run(CommandInvocation(brewPath, ["info", "--json=v2", name], timeout: 60))
        guard let result, result.succeeded else { return nil }
        return Self.formulaName(brewInfo: result.stdout)
    }

    /// The first formula's `name` in `brew info --json=v2` (aliases resolve to the formula).
    static func formulaName(brewInfo: Data) -> String? {
        struct Info: Decodable {
            struct Formula: Decodable { var name: String }
            var formulae: [Formula]
        }
        return (try? JSONDecoder().decode(Info.self, from: brewInfo))?.formulae.first?.name
    }

    struct Inspection: Equatable {
        var kind: String
        var copyable: Bool
    }

    /// Mach-O with only `/usr/lib` and `/System` libraries copies as is; a script copies when the sandbox can
    /// run its interpreter. Anything else (other libraries, `@rpath`, data files) needs Homebrew.
    func inspect(_ path: String) async throws -> Inspection {
        guard let handle = FileHandle(forReadingAtPath: path) else { return Inspection(kind: "unreadable file", copyable: false) }
        let head = (try? handle.read(upToCount: 512)) ?? Data()
        try? handle.close()
        if Self.isMachO(head) {
            let otool = try? await runner.run(CommandInvocation("/usr/bin/otool", ["-L", path], timeout: 20))
            guard let otool, otool.succeeded else { return Inspection(kind: "Mach-O (libraries unknown: otool failed)", copyable: false) }
            let foreign = Self.libraries(otool: otool.stdoutString).filter { !$0.hasPrefix("/usr/lib/") && !$0.hasPrefix("/System/") }
            return foreign.isEmpty
                ? Inspection(kind: "Mach-O, system libraries only", copyable: true)
                : Inspection(kind: "Mach-O linked against \(foreign.joined(separator: ", "))", copyable: false)
        }
        if let shebang = Self.shebang(head) {
            let runnable = try await interpreterRunnable(shebang)
            return Inspection(kind: "script for \(shebang.joined(separator: " "))" + (runnable ? "" : " (not runnable in the sandbox)"), copyable: runnable)
        }
        return Inspection(kind: "not a program (no Mach-O header or #! line)", copyable: false)
    }

    private func interpreterRunnable(_ shebang: [String]) async throws -> Bool {
        guard let interpreter = shebang.first else { return false }
        if interpreter == "/usr/bin/env" {
            let program = shebang.dropFirst().first { !$0.hasPrefix("-") }
            guard let program, (try? Self.validate(name: program)) != nil else { return false }
            if case .found = try await sandboxLookup(program) { return true }
            return false
        }
        let location = Self.location(of: interpreter, resolved: HostPath.resolved(interpreter) ?? interpreter, environment: layout.environment)
        return location == .system || location == .homebrew || location == .sharedUser
    }

    static func isMachO(_ head: Data) -> Bool {
        guard head.count >= 4 else { return false }
        let magic = head.prefix(4).reduce(UInt32(0)) { $0 << 8 | UInt32($1) }
        return [0xFEEDFACE, 0xFEEDFACF, 0xCEFAEDFE, 0xCFFAEDFE, 0xCAFEBABE, 0xBEBAFECA].contains(magic)
    }

    /// `#!/usr/bin/env python3` -> `["/usr/bin/env", "python3"]`.
    static func shebang(_ head: Data) -> [String]? {
        guard head.starts(with: Array("#!".utf8)) else { return nil }
        let line = head.dropFirst(2).prefix { $0 != 0x0A }
        let words = String(decoding: line, as: UTF8.self).split(whereSeparator: { $0 == " " || $0 == "\t" || $0 == "\r" }).map(String.init)
        guard let first = words.first, first.hasPrefix("/") else { return nil }
        return words
    }

    /// Library paths from `otool -L` (one indented line per library, per architecture for universal binaries).
    static func libraries(otool output: String) -> [String] {
        var result: [String] = []
        for line in output.split(separator: "\n") where line.first == "\t" || line.first == " " {
            let trimmed = line.trimmingCharacters(in: .whitespaces)
            let path = trimmed.range(of: " (compatibility version").map { String(trimmed[..<$0.lowerBound]) } ?? trimmed
            if !path.isEmpty, !result.contains(path) { result.append(path) }
        }
        return result
    }
}
