import Foundation
import SandvaultCore

/// What `sv-clone` will be given: a local repository or a remote URL (sv-clone decides with `[[ -d ]]`).
public enum RepositorySource: Equatable, Sendable {
    case local(String)
    case remote(String)
    case invalid(String)

    public static func classify(_ source: String, home: String) -> RepositorySource {
        guard !source.isEmpty, !Text.hasControlCharacters(source) else { return .invalid("the source is empty or contains control characters") }
        let path = HostPath.absolute(source, home: home)
        if FileKind.of(path) == .directory || (FileKind.of(path) == .symlink && HostPath.resolved(path).map { FileKind.of($0) == .directory } == true) {
            return .local(HostPath.resolved(path) ?? path)
        }
        if isRemoteURL(source) { return .remote(source) }
        return .invalid("'\(source)' is neither a local directory nor a repository URL (https://, ssh://, git:// or user@host:path)")
    }

    /// Shape only; nothing is contacted. Remote helpers (`ext::…`, `<transport>::`) and `file://` are refused.
    public static func isRemoteURL(_ text: String) -> Bool {
        let user = "([A-Za-z0-9_][A-Za-z0-9._~+-]*@)?"
        let host = "[A-Za-z0-9][A-Za-z0-9.-]*"
        let url = "^(https?|ssh|git|git\\+ssh|ssh\\+git)://\(user)\(host)(:[0-9]{1,5})?/[^\\s]+$"
        let scp = "^\(user)\(host):[^\\s:][^\\s]*$"
        guard !Text.hasControlCharacters(text), !text.contains("::") else { return false }
        return text.contains("://") ? Text.matches(text, url) : Text.matches(text, scp)
    }

    /// Whether git would read this URL from the local file system (which the sandbox cannot).
    static func isLocalURL(_ url: String) -> Bool {
        if url.hasPrefix("/") || url.hasPrefix("~") || url.hasPrefix("file:") { return true }
        if url.contains("://") { return false }
        if let colon = url.firstIndex(of: ":"), !url[..<colon].contains("/") { return false }
        return true
    }
}

/// The readiness check behind `HandoffService.readiness(of:)`. Severities follow what happens in the sandbox:
/// a blocker makes sv-clone fail, a warning loses or leaks something, info explains a difference.
struct ReadinessCheck: Sendable {
    let layout: SharedLayout
    let runner: CommandRunner

    static let findingLimit = 20
    static let largeRepositoryBytes = 1 << 30

    func run(_ source: String) async throws -> ReadinessReport {
        switch RepositorySource.classify(source, home: layout.environment.hostHome) {
        case .invalid(let message):
            let name = RepositoryName.derive(from: source)
            return ReadinessReport(repositoryPath: source, repositoryName: name, findings: [
                ReadinessFinding(kind: .notGitRepository, severity: .blocker, message: message),
            ])
        case .remote(let url):
            let name = RepositoryName.derive(from: url)
            var findings = nameFindings(name)
            if findings.isEmpty { findings += existingClone(name) }
            return ReadinessReport(repositoryPath: url, repositoryName: name, findings: findings)
        case .local(let path):
            let name = RepositoryName.derive(from: path)
            var findings = nameFindings(name)
            if findings.isEmpty {
                findings += try await local(path)
                findings += existingClone(name)
            }
            return ReadinessReport(repositoryPath: path, repositoryName: name, findings: Self.ordered(findings))
        }
    }

    private func nameFindings(_ name: String) -> [ReadinessFinding] {
        RepositoryName.isValid(name) ? [] : [ReadinessFinding(
            kind: .notGitRepository, severity: .blocker, message: "cannot derive a usable clone name ('\(name)')"
        )]
    }

    // MARK: - Local repository (host-owned and trusted: plain git)

    private func local(_ root: String) async throws -> [ReadinessFinding] {
        if layout.isSandboxWritable(root) {
            return [ReadinessFinding(kind: .notGitRepository, severity: .blocker,
                message: "\(root) is inside the sandbox's own files; hand off the host repository instead")]
        }
        let toplevel = try await git(root, ["rev-parse", "--show-toplevel"])
        guard toplevel.succeeded else {
            return [ReadinessFinding(kind: .notGitRepository, severity: .blocker, message: "\(root) is not a git working tree")]
        }
        let top = HostPath.resolved(toplevel.trimmedOutput) ?? toplevel.trimmedOutput
        guard top == root else {
            return [ReadinessFinding(kind: .notGitRepository, severity: .blocker,
                message: "\(root) is inside the repository \(top); hand off its root (git clone needs it)")]
        }

        var findings: [ReadinessFinding] = []
        if FileKind.of(root + "/.git") == .regular {
            let pointer = (try? String(contentsOfFile: root + "/.git", encoding: .utf8))?.trimmingCharacters(in: .whitespacesAndNewlines) ?? ""
            findings.append(ReadinessFinding(kind: .gitFileIndirection, severity: .info, path: ".git",
                message: "this is a worktree or submodule checkout (\(pointer)); the clone gets the branch checked out here"))
        }
        if try await !git(root, ["rev-parse", "--verify", "-q", "HEAD^{commit}"]).succeeded {
            findings.append(ReadinessFinding(kind: .noCommits, severity: .blocker, message: "the repository has no commits yet; commit once before handing it off"))
        }
        let origin = try await git(root, ["remote", "get-url", "origin"])
        // sv-clone v1.32 aborts on a local repository without `origin` (sv-clone line 156). The contract has no
        // dedicated kind for it; `notGitRepository` is the "sv-clone cannot use this source" bucket.
        if !origin.succeeded {
            findings.append(ReadinessFinding(kind: .notGitRepository, severity: .blocker,
                message: "no 'origin' remote: sv-clone refuses a local repository without one (git remote add origin <url>)"))
        }

        let status = try await git(root, ["status", "--porcelain=v1", "-z", "--untracked-files=all", "--no-renames"], timeout: 60)
        var changed = 0
        var untracked: [String] = []
        if status.succeeded {
            for record in Text.records(status.stdout) where record.count > 3 {
                let code = record.prefix(2)
                if code == "??" { untracked.append(String(record.dropFirst(3))) } else if code != "!!" { changed += 1 }
            }
        }
        if changed > 0 {
            findings.append(ReadinessFinding(kind: .uncommittedChanges, severity: .warning,
                message: "uncommitted changes in \(changed) file\(changed == 1 ? "" : "s") stay on the host unless they are included"))
        }
        if !untracked.isEmpty {
            findings.append(ReadinessFinding(kind: .untrackedFiles, severity: .info,
                message: "\(untracked.count) untracked file\(untracked.count == 1 ? " is" : "s are") not cloned (not even with uncommitted changes included)"))
        }

        let tracked = try await trackedEntries(root)
        findings += limited(tracked.filter { $0.mode == "120000" }.compactMap { symlinkFinding(root: root, path: $0.path) })
        for entry in tracked {
            let base = Self.baseName(entry.path)
            if Self.isDotenv(base) {
                findings.append(ReadinessFinding(kind: .dotenvFile, severity: .warning, path: entry.path,
                    message: "\(entry.path) is tracked: whatever secrets it holds are in git and in the clone"))
            } else if base == ".envrc" {
                findings.append(ReadinessFinding(kind: .envrc, severity: .info, path: entry.path,
                    message: "\(entry.path) is cloned, but direnv loads it in the sandbox only after `direnv allow`"))
            }
        }
        let ignored = try await git(root, ["ls-files", "-z", "--others", "--ignored", "--exclude-standard", "--directory"], timeout: 60)
        let leftBehind = untracked.map { ($0, "untracked") }
            + (ignored.succeeded ? Text.records(ignored.stdout).filter { !$0.hasSuffix("/") }.map { ($0, "ignored by git") } : [])
        var local: [ReadinessFinding] = []
        for (path, why) in leftBehind {
            let base = Self.baseName(path)
            if Self.isDotenv(base) {
                local.append(ReadinessFinding(kind: .dotenvFile, severity: .info, path: path,
                    message: "\(path) is \(why) and stays on the host; recreate it in the clone if the project needs it"))
            } else if base == ".envrc" {
                local.append(ReadinessFinding(kind: .envrc, severity: .info, path: path, message: "\(path) is \(why) and stays on the host"))
            }
        }
        findings += limited(local)

        findings += virtualenvFindings(root)
        if FileKind.of(root + "/.gitmodules") == .regular {
            findings += try await submoduleFindings(root, originURL: origin.succeeded ? origin.trimmedOutput : nil)
        }
        if let bytes = try await objectBytes(root), bytes > Self.largeRepositoryBytes {
            findings.append(ReadinessFinding(kind: .largeRepository, severity: .info,
                message: String(format: "the clone copies about %.1f GB of git history", Double(bytes) / 1e9)))
        }
        return findings
    }

    private func git(_ root: String, _ arguments: [String], timeout: Double = 30) async throws -> CommandResult {
        try await runner.run(CommandInvocation(GitSafe.gitPath, ["-C", root] + arguments, timeout: timeout))
    }

    private func trackedEntries(_ root: String) async throws -> [(mode: String, path: String)] {
        let result = try await git(root, ["ls-files", "-s", "-z"], timeout: 60)
        guard result.succeeded else { return [] }
        return Text.records(result.stdout).compactMap { record in
            guard let tab = record.firstIndex(of: "\t") else { return nil }
            return (String(record.prefix(6)), String(record[record.index(after: tab)...]))
        }
    }

    /// Absolute links into another home (or the host checkout) and relative links leaving the repository
    /// do not resolve in `$SHARED_WORKSPACE/repos/<name>`. Links to system paths keep working.
    private func symlinkFinding(root: String, path: String) -> ReadinessFinding? {
        guard let target = try? FileManager.default.destinationOfSymbolicLink(atPath: root + "/" + path) else { return nil }
        let environment = layout.environment
        if target.hasPrefix("/") {
            let unreadable = (target.hasPrefix("/Users/") && !HostPath.isInside(target, environment.sharedWorkspace)
                && !HostPath.isInside(target, environment.sandvaultHome))
                || (target.hasPrefix("/Volumes/") && !target.hasPrefix("/Volumes/Macintosh HD"))
            guard HostPath.isInside(target, root) || unreadable else { return nil }
            return ReadinessFinding(kind: .symlinkOutside, severity: .warning, path: path,
                message: "\(path) links to \(target), which the sandbox cannot read; it dangles in the clone")
        }
        let directory = HostPath.normalized((path as NSString).deletingLastPathComponent, relativeTo: root)
        guard !HostPath.isInside(HostPath.normalized(target, relativeTo: directory), root) else { return nil }
        return ReadinessFinding(kind: .symlinkOutside, severity: .warning, path: path,
            message: "\(path) links to \(target) outside the repository; it dangles in the clone")
    }

    private func virtualenvFindings(_ root: String) -> [ReadinessFinding] {
        [".venv", "venv"].compactMap { name in
            let config = root + "/" + name + "/pyvenv.cfg"
            guard FileKind.of(config) == .regular, let text = try? String(contentsOfFile: config, encoding: .utf8),
                  let home = Self.pyvenvHome(text), !HostPath.isInside(HostPath.normalized(home, relativeTo: root), root)
            else { return nil }
            return ReadinessFinding(kind: .virtualenvHostInterpreter, severity: .info, path: name,
                message: "\(name) uses the host interpreter in \(home) and does not work in the sandbox; recreate it in the clone (python3 -m venv \(name))")
        }
    }

    static func pyvenvHome(_ text: String) -> String? {
        for line in Text.lines(text) {
            let parts = line.split(separator: "=", maxSplits: 1).map { $0.trimmingCharacters(in: .whitespaces) }
            if parts.count == 2, parts[0] == "home", !parts[1].isEmpty { return parts[1] }
        }
        return nil
    }

    /// sv-clone does not check out submodules; `git submodule update` in the sandbox cannot read local URLs.
    /// Relative URLs resolve against `origin`, so they are local exactly when origin is.
    private func submoduleFindings(_ root: String, originURL: String?) async throws -> [ReadinessFinding] {
        let result = try await git(root, ["config", "-z", "--file", ".gitmodules", "--get-regexp", "^submodule\\..*\\.url$"])
        guard result.succeeded else { return [] }
        let findings: [ReadinessFinding] = Text.records(result.stdout).compactMap { record in
            let parts = record.split(separator: "\n", maxSplits: 1).map(String.init)
            guard parts.count == 2 else { return nil }
            let name = String(parts[0].dropFirst("submodule.".count).dropLast(".url".count))
            let url = parts[1]
            let relative = url.hasPrefix("./") || url.hasPrefix("../")
            let local = relative ? originURL.map(RepositorySource.isLocalURL) ?? true : RepositorySource.isLocalURL(url)
            guard local else { return nil }
            return ReadinessFinding(kind: .localSubmodule, severity: .warning, path: name,
                message: "submodule \(name) uses the local URL \(url); git submodule update cannot read it in the sandbox")
        }
        return limited(findings)
    }

    /// Loose plus packed object size from `git count-objects -v` (KiB values).
    private func objectBytes(_ root: String) async throws -> Int? {
        let result = try await git(root, ["count-objects", "-v"])
        guard result.succeeded else { return nil }
        return Self.objectBytes(countObjects: result.stdoutString)
    }

    static func objectBytes(countObjects output: String) -> Int? {
        var kib = 0
        var seen = false
        for line in Text.lines(output) {
            let parts = line.split(separator: ":", maxSplits: 1).map { $0.trimmingCharacters(in: .whitespaces) }
            guard parts.count == 2, parts[0] == "size" || parts[0] == "size-pack", let value = Int(parts[1]) else { continue }
            kib += value
            seen = true
        }
        return seen ? kib * 1024 : nil
    }

    // MARK: - The clone directory

    /// sv-clone fetches into an existing clone (it checks `repos/<name>/.git`) and leaves its working tree alone.
    private func existingClone(_ name: String) -> [ReadinessFinding] {
        let clone = layout.reposDir + "/" + name
        switch FileKind.of(clone) {
        case .missing:
            return []
        case .directory where FileKind.of(clone + "/.git") == .directory:
            return [ReadinessFinding(kind: .alreadyHandedOff, severity: .info,
                message: "\(clone) exists: sv-clone fetches into it and leaves its working tree as the agent left it")]
        default:
            return [ReadinessFinding(kind: .alreadyHandedOff, severity: .warning,
                message: "\(clone) exists but is not a clone; git clone fails unless it is an empty directory")]
        }
    }

    // MARK: - Helpers

    static func baseName(_ path: String) -> String {
        path.split(separator: "/").last.map(String.init) ?? path
    }

    /// `.env`, `.env.local`, `.env.production`, ...; not `.envrc` and not templates such as `.env.example`.
    static func isDotenv(_ name: String) -> Bool {
        guard name == ".env" || name.hasPrefix(".env.") else { return false }
        let templates = [".example", ".sample", ".template", ".dist", ".defaults", ".schema"]
        return !templates.contains { name.hasSuffix($0) }
    }

    /// At most `findingLimit` findings of one group, then one that counts the rest.
    private func limited(_ findings: [ReadinessFinding]) -> [ReadinessFinding] {
        guard findings.count > Self.findingLimit, let last = findings.last else { return findings }
        let rest = findings.count - Self.findingLimit
        return Array(findings.prefix(Self.findingLimit))
            + [ReadinessFinding(kind: last.kind, severity: last.severity, message: "... and \(rest) more like this")]
    }

    /// Blockers first, then warnings, then info; check order within a severity.
    static func ordered(_ findings: [ReadinessFinding]) -> [ReadinessFinding] {
        findings.enumerated().sorted { lhs, rhs in
            lhs.element.severity != rhs.element.severity ? lhs.element.severity > rhs.element.severity : lhs.offset < rhs.offset
        }.map(\.element)
    }
}
