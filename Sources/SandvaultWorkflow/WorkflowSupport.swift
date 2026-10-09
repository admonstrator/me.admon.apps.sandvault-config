import Foundation
#if canImport(Darwin)
import Darwin
#elseif canImport(Glibc)
import Glibc
#endif
import SandvaultCore

public enum WorkflowPlatform {
    /// Terminals, `sudo -u <sandbox>`, `otool` and `brew` exist on macOS only.
    public static var isMacOS: Bool {
        #if os(macOS)
        true
        #else
        false
        #endif
    }
}

/// The parts of the shared workspace this module touches, rooted at `shared.root`: the real workspace in
/// production, a temporary directory in tests. Relative paths come from `SandvaultEnvironment` / `AppPaths`.
public struct SharedLayout: Sendable {
    public let environment: SandvaultEnvironment
    public let shared: SharedFiles

    public init(environment: SandvaultEnvironment, shared: SharedFiles? = nil) {
        self.environment = environment
        self.shared = shared ?? SharedFiles(environment: environment)
    }

    /// `path` (one of the environment's shared workspace paths) relative to the workspace root.
    public func relative(_ path: String) -> String {
        SharedFiles(environment: environment).relativePath(for: path) ?? path
    }

    public func absolute(_ relative: String) -> String { shared.root + "/" + relative }

    public var reposDir: String { absolute(relative(environment.sharedReposDir)) }
    public var userRelative: String { relative(environment.sharedUserDir) }
    public var handoffRelative: String { relative(AppPaths(environment: environment).handoffDir) }
    public var deployKeysDir: String { absolute(relative(environment.svPrivateDir)) + "/.ssh" }

    /// Throws `notInstalled` when the workspace does not exist yet (sv creates it on its first run).
    public func requireWorkspace() throws {
        guard FileKind.of(shared.root) == .directory else {
            throw SandvaultError.notInstalled("shared workspace \(shared.root) (run `sv` once to create it)")
        }
    }

    /// Whether `path` lies in a tree the sandbox can write (the shared workspace or the sandbox home).
    public func isSandboxWritable(_ path: String) -> Bool {
        let roots = [shared.root, environment.sharedWorkspace, environment.sandvaultHome]
        return (roots + roots.compactMap(HostPath.resolved)).contains { HostPath.isInside(path, $0) }
    }
}

/// Commands that read or execute what the sandbox controls run the way sv starts a session: as the sandbox user
/// with a clean environment, inside sv's profile. Whatever they trigger (shell files, git filters, fsmonitor,
/// gpg) is then confined like the agent itself.
public enum SandboxedCommand {
    public static let path = "/usr/bin:/bin:/usr/sbin:/sbin"

    /// `sudo -n -u <sandbox> /usr/bin/env -i HOME=… USER=… [variables] PATH=… /usr/bin/sandbox-exec -f <profile> <command…>`
    public static func invocation(
        _ environment: SandvaultEnvironment, variables: [String] = [], _ command: [String], timeout: Double = 15
    ) -> CommandInvocation {
        CommandInvocation.asSandvault(environment, "-i", [
            "HOME=\(environment.sandvaultHome)", "USER=\(environment.sandvaultUser)",
        ] + variables + ["PATH=\(path)", "/usr/bin/sandbox-exec", "-f", environment.sandboxProfilePath] + command, timeout: timeout)
    }

    /// git in a sandbox clone. `safe.directory=*` is needed because the host owns the clone; trusting its config is
    /// fine here, since anything that config makes git run stays inside the profile.
    public static func git(_ environment: SandvaultEnvironment, clone: String, _ arguments: [String], timeout: Double = 15) -> CommandInvocation {
        invocation(environment, [GitSafe.gitPath] + GitSafe.hardeningArguments + ["-c", "safe.directory=*", "-C", clone] + arguments,
                   timeout: timeout)
    }
}

/// `lstat` without following symlinks.
public enum FileKind: Sendable, Equatable {
    case missing, regular, directory, symlink, other

    public static func of(_ path: String) -> FileKind {
        var info = stat()
        guard lstat(path, &info) == 0 else { return .missing }
        switch info.st_mode & S_IFMT {
        case S_IFREG: return .regular
        case S_IFDIR: return .directory
        case S_IFLNK: return .symlink
        default: return .other
        }
    }

    /// Size in bytes of a regular file (no symlink following), `nil` otherwise.
    public static func size(_ path: String) -> Int? {
        var info = stat()
        guard lstat(path, &info) == 0, info.st_mode & S_IFMT == S_IFREG else { return nil }
        return Int(info.st_size)
    }

    /// Permission bits (no symlink following).
    public static func mode(_ path: String) -> Int? {
        var info = stat()
        guard lstat(path, &info) == 0 else { return nil }
        return Int(info.st_mode & 0o7777)
    }
}

enum HostPath {
    /// `realpath(3)`: absolute, symlinks resolved; `nil` when the path does not exist.
    static func resolved(_ path: String) -> String? {
        guard let pointer = realpath(path, nil) else { return nil }
        defer { free(pointer) }
        return String(cString: pointer)
    }

    /// Absolute form of a user-supplied path (`~` and relative paths), without resolving symlinks.
    static func absolute(_ path: String, home: String) -> String {
        if path == "~" { return home }
        if path.hasPrefix("~/") { return home + path.dropFirst(1) }
        if path.hasPrefix("/") { return path }
        return FileManager.default.currentDirectoryPath + "/" + path
    }

    static func isInside(_ path: String, _ root: String) -> Bool {
        path == root || path.hasPrefix(root.hasSuffix("/") ? root : root + "/")
    }

    /// Lexically normalized absolute path (`.` and `..` removed) of `target` relative to `directory`.
    static func normalized(_ target: String, relativeTo directory: String) -> String {
        let joined = target.hasPrefix("/") ? target : directory + "/" + target
        var parts: [Substring] = []
        for part in joined.split(separator: "/") {
            if part == "." || part.isEmpty { continue }
            if part == ".." {
                if !parts.isEmpty { parts.removeLast() }
            } else {
                parts.append(part)
            }
        }
        return "/" + parts.joined(separator: "/")
    }
}

/// POSIX shell quoting. Every argument that reaches a shell (a terminal window, `zsh -c`) goes through here.
public enum ShellQuoting {
    /// Plain words stay bare; everything else is single-quoted, with `'` written as `'\''`.
    /// `=`, `~`, `%`, `*`, `$` and non-ASCII characters are never bare (zsh expands `=cmd`, `~user`, globs).
    public static func quote(_ word: String) -> String {
        if !word.isEmpty, word.utf8.allSatisfy({ bare.contains($0) }) { return word }
        return "'" + word.replacingOccurrences(of: "'", with: "'\\''") + "'"
    }

    public static func join(_ words: [String]) -> String {
        words.map(quote).joined(separator: " ")
    }

    private static let bare: Set<UInt8> = Set("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_-./:,+@".utf8)
}

/// Text checks shared by the services.
enum Text {
    /// C0 controls, DEL and C1 controls (terminal escapes, line breaks).
    static func hasControlCharacters(_ text: String) -> Bool {
        text.unicodeScalars.contains { $0.value < 0x20 || (0x7F...0x9F).contains($0.value) }
    }

    static func matches(_ text: String, _ pattern: String) -> Bool {
        text.range(of: pattern, options: .regularExpression) != nil
    }

    static func isHex(_ text: String, lengths: Set<Int> = [40, 64]) -> Bool {
        lengths.contains(text.count) && text.utf8.allSatisfy { (48...57).contains($0) || (97...102).contains($0) }
    }

    /// A branch name we pass back to git as part of a ref (`refs/remotes/sandvault/<branch>`).
    static func isSafeBranch(_ name: String) -> Bool {
        matches(name, "^[A-Za-z0-9_][A-Za-z0-9._/+-]{0,199}$") && !name.contains("..") && !name.contains("//")
            && !name.hasSuffix("/") && !name.hasSuffix(".lock") && !name.hasSuffix(".")
    }

    static func lines(_ text: String) -> [String] {
        text.split(whereSeparator: \.isNewline).map(String.init)
    }

    /// NUL-separated records (`git ... -z`).
    static func records(_ data: Data) -> [String] {
        data.split(separator: 0).map { String(decoding: $0, as: UTF8.self) }
    }
}

/// How `sv-clone` names the clone (`$SHARED_WORKSPACE/repos/<name>`), sv-clone lines 160-176.
public enum RepositoryName {
    public static func derive(from source: String) -> String {
        var name = source
        if name.hasSuffix("/") { name.removeLast() }
        if name.contains("://"), let slash = name.lastIndex(of: "/") { name = String(name[name.index(after: slash)...]) }
        if let colon = name.lastIndex(of: ":") { name = String(name[name.index(after: colon)...]) }
        if let slash = name.lastIndex(of: "/") { name = String(name[name.index(after: slash)...]) }
        if name.hasSuffix(".git") { name.removeLast(4) }
        return name
    }

    /// Usable as one path component in the shared workspace (`repos/<name>`, `tmp/handoff-<name>.md`).
    public static func isValid(_ name: String) -> Bool {
        !name.isEmpty && name != "." && name != ".." && !name.contains("/") && !Text.hasControlCharacters(name)
            && name.utf8.count <= 200
    }
}

extension CommandResult {
    var trimmedOutput: String { stdoutString.trimmingCharacters(in: .whitespacesAndNewlines) }
}
