import Foundation
import SandvaultCore

/// Clones in `$SHARED_WORKSPACE/repos` and the way back (`git fetch sandvault` in the host repository).
///
/// The host never runs git inside a clone. The sandbox can rewrite a clone's `.git/config` at any moment, and git
/// executes parts of it (filter drivers on `status`, `core.fsmonitor`, `gpg.program` for signatures), so reading the
/// config first and neutralizing it would race. Every git call on a clone goes through `SandboxedCommand.git`: as the
/// sandbox user inside sv's profile, where whatever the config runs is as confined as the agent. Its output is
/// untrusted text: bounded, strictly parsed, unknown when it does not fit.
public struct SandboxRepositories: RepoService {
    public let layout: SharedLayout
    public let runner: CommandRunner
    public let configStore: ConfigStore
    /// The sandboxed git needs sudo to the sandbox user and sandbox-exec; elsewhere the clone fields stay unknown.
    public let isMacOS: Bool

    static let timeout: Double = 15

    public init(
        environment: SandvaultEnvironment, runner: CommandRunner, configStore: ConfigStore,
        shared: SharedFiles? = nil, isMacOS: Bool = WorkflowPlatform.isMacOS
    ) {
        layout = SharedLayout(environment: environment, shared: shared)
        self.runner = runner
        self.configStore = configStore
        self.isMacOS = isMacOS
    }

    public func repositories() async throws -> [RepoStatus] {
        try layout.requireWorkspace()
        let names = try cloneNames()
        let records = try configStore.load().repos
        return await withTaskGroup(of: RepoStatus.self) { group in
            for name in names {
                let record = records.last { $0.repoName == name }
                group.addTask { await status(name: name, record: record) }
            }
            var result: [RepoStatus] = []
            for await status in group { result.append(status) }
            return result.sorted { $0.name < $1.name }
        }
    }

    /// Host-side: git in the host repository fetches from the clone. upload-pack serves the clone's objects and refs
    /// without running worktree filters, fsmonitor or hooks; the hardening reaches it through the environment git sets.
    public func fetchBack(_ record: HandoffRecord) async throws -> RepoStatus {
        guard RepositoryName.isValid(record.repoName) else { throw SandvaultError.invalidInput("bad repository name '\(record.repoName)'") }
        guard FileKind.of(record.hostPath) == .directory else {
            throw SandvaultError.invalidInput("\(record.repoName) has no host repository at \(record.hostPath) (handed off from a URL?)")
        }
        let remote = try await runner.run(CommandInvocation(GitSafe.gitPath, ["-C", record.hostPath, "remote", "get-url", "sandvault"], timeout: Self.timeout))
        guard remote.succeeded else {
            throw SandvaultError.invalidInput("\(record.hostPath) has no 'sandvault' remote (sv-clone adds it on hand-off)")
        }
        // No tags and no submodules: the sandbox must not plant tags or trigger fetches elsewhere.
        _ = try await runner.checked(GitSafe.invocation(
            repository: record.hostPath, ["fetch", "--no-tags", "--no-recurse-submodules", "sandvault"], timeout: 120
        ))
        return await status(name: record.repoName, record: record)
    }

    /// Real directories only; hidden entries and names with control characters are skipped (names are untrusted).
    func cloneNames() throws -> [String] {
        let directory = layout.reposDir
        guard FileKind.of(directory) == .directory else { return [] }
        let entries: [String]
        do {
            entries = try FileManager.default.contentsOfDirectory(atPath: directory)
        } catch {
            throw SandvaultError.io("cannot list \(directory): \(error)")
        }
        return entries.filter { name in
            !name.hasPrefix(".") && RepositoryName.isValid(name) && FileKind.of(directory + "/" + name) == .directory
        }.sorted()
    }

    func status(name: String, record: HandoffRecord?) async -> RepoStatus {
        let path = layout.reposDir + "/" + name
        var status = RepoStatus(record: record, name: name, sandboxPath: path)
        let key = layout.deployKeysDir + "/deploy_" + name
        if FileKind.of(key) == .regular { status.deployKey = key }
        // sv-clone makes plain clones; anything else (no `.git`, a gitfile pointing elsewhere) is not asked.
        guard isMacOS, FileKind.of(path + "/.git") == .directory else { return status }

        if let branch = await clone(path, ["symbolic-ref", "--quiet", "--short", "HEAD"], limit: 256), Text.isSafeBranch(branch) {
            status.branch = branch
        }
        // Signatures off: `--show-signature` output would precede the format line (and gpg would run for nothing).
        if let line = await clone(path, ["-c", "log.showSignature=false", "log", "-1", "--no-color", "--format=%H %ct", "HEAD"], limit: 128),
           let head = Self.parseHead(line) {
            status.headCommit = head.commit
            status.lastCommitDate = head.date
        }
        let porcelain = ["--no-optional-locks", "status", "--porcelain=v1", "-z", "--untracked-files=normal", "--ignore-submodules=all", "--no-renames"]
        if let result = try? await runner.run(SandboxedCommand.git(layout.environment, clone: path, porcelain, timeout: Self.timeout)),
           result.succeeded {
            status.dirty = !result.stdout.isEmpty
        }
        if let counts = await clone(path, ["rev-list", "--left-right", "--count", "@{upstream}...HEAD"], limit: 64),
           let parsed = Self.parseCounts(counts) {
            status.behindOrigin = parsed.behind
            status.aheadOfOrigin = parsed.ahead
        }
        if let record, let branch = status.branch {
            status.unfetchedCommits = await unfetched(record: record, clone: path, branch: branch)
        }
        return status
    }

    /// Clone commits the host has not fetched: `HEAD` of the clone minus `sandvault/<branch>` of the host (or the
    /// host's own branch, which the clone started from, before the first fetch). The host side is the trusted host
    /// repository; the count runs in the clone, sandboxed.
    private func unfetched(record: HandoffRecord, clone path: String, branch: String) async -> Int? {
        guard FileKind.of(record.hostPath) == .directory else { return nil }
        for ref in ["refs/remotes/sandvault/\(branch)", "refs/heads/\(branch)"] {
            let result = try? await runner.run(CommandInvocation(
                GitSafe.gitPath, ["-C", record.hostPath, "rev-parse", "--verify", "-q", "\(ref)^{commit}"], timeout: Self.timeout
            ))
            guard let result, result.succeeded else { continue }
            let commit = result.trimmedOutput
            guard Text.isHex(commit), let count = await clone(path, ["rev-list", "--count", "\(commit)..HEAD"], limit: 32),
                  let value = Int(count), value >= 0
            else { return nil }
            return value
        }
        return nil
    }

    /// One line of sandboxed git output, or `nil` when the command failed or printed more than `limit` bytes.
    private func clone(_ path: String, _ arguments: [String], limit: Int) async -> String? {
        guard let result = try? await runner.run(SandboxedCommand.git(layout.environment, clone: path, arguments, timeout: Self.timeout)),
              result.succeeded, result.stdout.count <= limit
        else { return nil }
        let text = result.trimmedOutput
        return text.isEmpty || text.contains("\n") || Text.hasControlCharacters(text.replacingOccurrences(of: "\t", with: " ")) ? nil : text
    }

    // MARK: - Parsing

    /// `<sha> <unix seconds>` from `git log -1 --format='%H %ct'`.
    static func parseHead(_ line: String) -> (commit: String, date: Date)? {
        let parts = line.split(separator: " ", omittingEmptySubsequences: false)
        guard parts.count == 2, Text.isHex(String(parts[0])), parts[1].count <= 12, let seconds = Int(parts[1]), seconds >= 0 else { return nil }
        return (String(parts[0]), Date(timeIntervalSince1970: TimeInterval(seconds)))
    }

    /// `<behind>\t<ahead>` from `git rev-list --left-right --count @{upstream}...HEAD`.
    static func parseCounts(_ line: String) -> (behind: Int, ahead: Int)? {
        let parts = line.split(separator: "\t", omittingEmptySubsequences: false)
        guard parts.count == 2, parts.allSatisfy({ $0.count <= 9 }), let behind = Int(parts[0]), let ahead = Int(parts[1]),
              behind >= 0, ahead >= 0
        else { return nil }
        return (behind, ahead)
    }
}
