import Foundation
import SandvaultCore

/// Clones in `$SHARED_WORKSPACE/repos` and the way back (`git fetch sandvault` in the host repository).
///
/// Every clone is sandbox-writable, so git runs there only through `GitSafe`. On top of its hardening, the
/// `log` call turns off signature checks (`gpg.program` would run) and `status` turns off every filter driver
/// the clone's config names (a `clean` filter is a command `git status` runs on files it re-hashes).
public struct SandboxRepositories: RepoService {
    public let layout: SharedLayout
    public let runner: CommandRunner
    public let configStore: ConfigStore

    static let timeout: Double = 15

    public init(environment: SandvaultEnvironment, runner: CommandRunner, configStore: ConfigStore, shared: SharedFiles? = nil) {
        layout = SharedLayout(environment: environment, shared: shared)
        self.runner = runner
        self.configStore = configStore
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

    public func fetchBack(_ record: HandoffRecord) async throws -> RepoStatus {
        guard RepositoryName.isValid(record.repoName) else { throw SandvaultError.invalidInput("bad repository name '\(record.repoName)'") }
        guard FileKind.of(record.hostPath) == .directory else {
            throw SandvaultError.invalidInput("\(record.repoName) has no host repository at \(record.hostPath) (handed off from a URL?)")
        }
        let remote = try await runner.run(CommandInvocation(GitSafe.gitPath, ["-C", record.hostPath, "remote", "get-url", "sandvault"], timeout: Self.timeout))
        guard remote.succeeded else {
            throw SandvaultError.invalidInput("\(record.hostPath) has no 'sandvault' remote (sv-clone adds it on hand-off)")
        }
        // The remote side is sandbox-controlled: hardening applies to the upload-pack git spawns for it too.
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
        // sv-clone makes plain clones; anything else (no `.git`, a gitfile pointing elsewhere) is not asked,
        // so git never searches upward or follows a pointer the sandbox wrote.
        guard FileKind.of(path + "/.git") == .directory else { return status }
        if let branch = try? await clone(path, ["symbolic-ref", "--quiet", "--short", "HEAD"]), Text.isSafeBranch(branch) {
            status.branch = branch
        }
        if let line = try? await clone(path, ["-c", "log.showSignature=false", "log", "-1", "--no-color", "--format=%H %ct", "HEAD"]),
           let head = Self.parseHead(line) {
            status.headCommit = head.commit
            status.lastCommitDate = head.date
        }
        status.dirty = await isDirty(path)
        if let counts = try? await clone(path, ["rev-list", "--left-right", "--count", "@{upstream}...HEAD"]),
           let parsed = Self.parseCounts(counts) {
            status.behindOrigin = parsed.behind
            status.aheadOfOrigin = parsed.ahead
        }
        if let record, let branch = status.branch {
            status.unfetchedCommits = await unfetched(record: record, clone: path, branch: branch)
        }
        let key = layout.deployKeysDir + "/deploy_" + name
        if FileKind.of(key) == .regular { status.deployKey = key }
        return status
    }

    /// Clone commits the host has not fetched: `HEAD` of the clone minus `sandvault/<branch>` of the host
    /// (or the host's own branch, which the clone started from, before the first fetch).
    private func unfetched(record: HandoffRecord, clone: String, branch: String) async -> Int? {
        guard FileKind.of(record.hostPath) == .directory else { return nil }
        for ref in ["refs/remotes/sandvault/\(branch)", "refs/heads/\(branch)"] {
            let result = try? await runner.run(CommandInvocation(
                GitSafe.gitPath, ["-C", record.hostPath, "rev-parse", "--verify", "-q", "\(ref)^{commit}"], timeout: Self.timeout
            ))
            guard let result, result.succeeded else { continue }
            let commit = result.trimmedOutput
            guard Text.isHex(commit), let count = try? await self.clone(clone, ["rev-list", "--count", "\(commit)..HEAD"]) else { return nil }
            return Int(count)
        }
        return nil
    }

    private func isDirty(_ path: String) async -> Bool {
        let drivers = (try? await runner.run(GitSafe.invocation(
            repository: path, ["config", "-z", "--name-only", "--get-regexp", "^filter\\."], timeout: Self.timeout
        ))).map { Self.filterDrivers(Text.records($0.stdout)) } ?? []
        var invocation = GitSafe.invocation(repository: path, [
            "--no-optional-locks", "status", "--porcelain=v1", "-z", "--untracked-files=normal", "--ignore-submodules=all", "--no-renames",
        ], timeout: Self.timeout)
        invocation.environment = (invocation.environment ?? [:]).merging(Self.neutralizing(drivers)) { $1 }
        guard let result = try? await runner.run(invocation), result.succeeded else { return false }
        return !result.stdout.isEmpty
    }

    private func clone(_ path: String, _ arguments: [String]) async throws -> String {
        try await runner.checked(GitSafe.invocation(repository: path, arguments, timeout: Self.timeout)).trimmedOutput
    }

    // MARK: - Parsing

    /// `filter.<driver>.<key>` names (from `git config --name-only`) to driver names. Drivers may contain dots.
    static func filterDrivers(_ names: [String]) -> [String] {
        var drivers: [String] = []
        for name in names where name.hasPrefix("filter.") {
            let rest = name.dropFirst("filter.".count)
            guard let dot = rest.lastIndex(of: ".") else { continue }
            let driver = String(rest[..<dot])
            if !driver.isEmpty, !drivers.contains(driver) { drivers.append(driver) }
        }
        return drivers
    }

    /// `GIT_CONFIG_COUNT` entries that empty every command of `drivers` (works for names with `=` too, unlike `-c`).
    static func neutralizing(_ drivers: [String]) -> [String: String] {
        var environment: [String: String] = [:]
        var index = 0
        for driver in drivers {
            for (key, value) in [("clean", ""), ("smudge", ""), ("process", ""), ("required", "false")] {
                environment["GIT_CONFIG_KEY_\(index)"] = "filter.\(driver).\(key)"
                environment["GIT_CONFIG_VALUE_\(index)"] = value
                index += 1
            }
        }
        if index > 0 { environment["GIT_CONFIG_COUNT"] = String(index) }
        return environment
    }

    /// `<sha> <unix seconds>` from `git log -1 --format='%H %ct'`.
    static func parseHead(_ line: String) -> (commit: String, date: Date)? {
        let parts = line.split(separator: " ")
        guard parts.count == 2, Text.isHex(String(parts[0])), let seconds = TimeInterval(parts[1]) else { return nil }
        return (String(parts[0]), Date(timeIntervalSince1970: seconds))
    }

    /// `<behind>\t<ahead>` from `git rev-list --left-right --count @{upstream}...HEAD`.
    static func parseCounts(_ line: String) -> (behind: Int, ahead: Int)? {
        let parts = line.split(whereSeparator: { $0 == "\t" || $0 == " " })
        guard parts.count == 2, let behind = Int(parts[0]), let ahead = Int(parts[1]) else { return nil }
        return (behind, ahead)
    }
}
