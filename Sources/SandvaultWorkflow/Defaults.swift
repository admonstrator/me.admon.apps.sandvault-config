import Foundation
import SandvaultCore

/// `sv`'s session options (`sv --help`, sv lines 960-1068) that make sense for a hand-off or as defaults.
/// None of them takes a value, so `sv-clone` never mistakes an option value for the sv command.
public enum SvOptions {
    public static let allowed: Set<String> = [
        "-s", "--ssh", "-v", "--verbose", "-vv", "-vvv", "-n", "--no-build",
        "-b", "--browser", "--chrome", "--lightpanda", "-i", "--ios", "-I", "--ios-gui", "-N", "--native-install",
    ]

    /// Real sv options we refuse, and why.
    public static let refused: [String: String] = [
        "-x": "disables sandbox-exec for the session",
        "--no-sandbox": "disables sandbox-exec for the session",
        "-r": "rewrites sv's sandbox profile and drops the managed rules block; run `sv --rebuild` by hand, then `svctl rules apply`",
        "--rebuild": "rewrites sv's sandbox profile and drops the managed rules block; run `sv --rebuild` by hand, then `svctl rules apply`",
        "--fix-permissions": "only works standalone or with `sv build`",
        "-e": "prints the browser endpoint and exits", "--endpoint": "prints the browser endpoint and exits",
        "-h": "prints help and exits", "--help": "prints help and exits", "--version": "prints the version and exits",
        "-c": "was removed from sv (sv-clone replaces it)", "--clone": "was removed from sv (sv-clone replaces it)",
    ]

    public static func validate(_ options: [String]) throws {
        for option in options {
            if let reason = refused[option] { throw SandvaultError.invalidInput("sv option \(option) \(reason)") }
            guard allowed.contains(option) else {
                throw SandvaultError.invalidInput("unknown sv option '\(option)'; allowed: \(allowed.sorted().joined(separator: " "))")
            }
        }
    }
}

/// Default `sv` arguments: `export SANDVAULT_ARGS='…'` in a managed block of the host's `~/.zshenv`.
/// sv prepends `$SANDVAULT_ARGS` to every command line (sv lines 1001-1008).
public struct SandvaultDefaults: Sendable {
    public static let block = ManagedBlock(name: "defaults", commentPrefix: "#")

    public struct State: Codable, Sendable, Equatable {
        public var file: String
        /// `nil` when there is no managed block.
        public var arguments: [String]?
        /// `SANDVAULT_ARGS` is also assigned outside the block (the later assignment wins).
        public var assignedOutsideBlock: Bool
    }

    /// The host user's `~/.zshenv`; host-owned, never sandbox-visible.
    public let file: String

    public init(environment: SandvaultEnvironment) {
        self.init(file: environment.hostHome + "/.zshenv")
    }

    public init(file: String) {
        self.file = file
    }

    public func read() throws -> State {
        let text = try contents()
        let outside = Self.block.remove(from: text)
        let assigned = Text.lines(outside).contains { Text.matches($0, #"^\s*(export\s+)?SANDVAULT_ARGS="#) }
        return State(file: file, arguments: Self.block.extract(from: text).map(Self.arguments(inBody:)), assignedOutsideBlock: assigned)
    }

    /// Validates and writes the block; an empty list removes it.
    @discardableResult
    public func set(_ arguments: [String]) throws -> State {
        guard !arguments.isEmpty else {
            try clear()
            return try read()
        }
        try SvOptions.validate(arguments)
        try write(Self.block.replace(in: try contents(), with: Self.body(for: arguments)))
        return try read()
    }

    /// Removes the block; `false` when there was none.
    @discardableResult
    public func clear() throws -> Bool {
        let text = try contents()
        guard Self.block.contains(in: text) else { return false }
        try write(Self.block.remove(from: text))
        return true
    }

    static func body(for arguments: [String]) -> String {
        "export SANDVAULT_ARGS=\(ShellQuoting.quote(arguments.joined(separator: " ")))"
    }

    /// The words of the block's assignment. Only validated options are ever written, so splitting on spaces suffices.
    static func arguments(inBody body: String) -> [String] {
        for line in Text.lines(body) {
            guard let range = line.range(of: "SANDVAULT_ARGS=") else { continue }
            var value = String(line[range.upperBound...]).trimmingCharacters(in: .whitespaces)
            if value.count >= 2, let first = value.first, first == "'" || first == "\"", value.last == first {
                value = String(value.dropFirst().dropLast())
            }
            return value.split(separator: " ").map(String.init)
        }
        return []
    }

    // MARK: - File access

    /// A dotfile manager often links `~/.zshenv` elsewhere; edit the link's target instead of replacing the link.
    private var target: String {
        FileKind.of(file) == .symlink ? (HostPath.resolved(file) ?? file) : file
    }

    private func contents() throws -> String {
        guard FileManager.default.fileExists(atPath: target) else { return "" }
        do {
            return try String(contentsOfFile: target, encoding: .utf8)
        } catch {
            throw SandvaultError.io("cannot read \(target): \(error)")
        }
    }

    private func write(_ text: String) throws {
        let path = target
        try AtomicFile.write(Data(text.utf8), to: path, permissions: FileKind.mode(path) ?? 0o644)
    }
}
