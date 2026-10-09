import Foundation
import SandvaultCore
import Testing
@testable import SandvaultWorkflow

@Suite struct RepositoryStatusTests {
    @Test func gitInACloneRunsAsTheSandboxUserInsideTheProfile() {
        let environment = SandvaultEnvironment(hostUser: "alice", hostHome: "/Users/alice")
        let invocation = SandboxedCommand.git(environment, clone: "/Users/Shared/sv-alice/repos/app", ["symbolic-ref", "--quiet", "--short", "HEAD"])
        #expect(invocation.argv == [
            "/usr/bin/sudo", "-n", "-u", "sandvault-alice", "/usr/bin/env", "-i",
            "HOME=/Users/sandvault-alice", "USER=sandvault-alice", "PATH=/usr/bin:/bin:/usr/sbin:/sbin",
            "/usr/bin/sandbox-exec", "-f", "/var/sandvault/sandbox-sandvault-alice.sb",
            "/usr/bin/git", "-c", "core.fsmonitor=", "-c", "core.sshCommand=", "-c", "core.hooksPath=/dev/null", "-c", "core.pager=cat",
            "-c", "protocol.ext.allow=never", "-c", "safe.directory=*", "-C", "/Users/Shared/sv-alice/repos/app",
            "symbolic-ref", "--quiet", "--short", "HEAD",
        ])
        #expect(invocation.timeout == 15)
    }

    @Test func statusFromGitOutputFixtures() async throws {
        let sandbox = try Sandbox()
        defer { sandbox.cleanup() }
        let clone = sandbox.workspace + "/repos/app"
        try FileManager.default.createDirectory(atPath: clone + "/.git", withIntermediateDirectories: true)
        try sandbox.write("key", to: sandbox.workspace + "/_sandvault/.ssh/deploy_app")
        let fake = FakeCommandRunner()
        func on(_ arguments: [String], _ data: Data) {
            fake.on(SandboxedCommand.git(sandbox.environment, clone: clone, arguments).argv, .result(CommandResult(exitCode: 0, stdout: data)))
        }
        on(["symbolic-ref", "--quiet", "--short", "HEAD"], try fixtureData("git-symbolic-ref.txt"))
        on(["-c", "log.showSignature=false", "log", "-1", "--no-color", "--format=%H %ct", "HEAD"], try fixtureData("git-log-head.txt"))
        on(["rev-list", "--left-right", "--count", "@{upstream}...HEAD"], try fixtureData("git-rev-list-left-right.txt"))
        on(["--no-optional-locks", "status", "--porcelain=v1", "-z", "--untracked-files=normal", "--ignore-submodules=all", "--no-renames"],
           try fixtureData("git-status-dirty.bin"))

        let repos = try await SandboxRepositories(environment: sandbox.environment, runner: fake, configStore: sandbox.configStore,
                                                  shared: sandbox.shared, isMacOS: true).repositories()
        let status = try #require(repos.first)
        #expect(repos.count == 1)
        #expect(status.name == "app" && status.sandboxPath == clone)
        #expect(status.branch == "main")
        #expect(status.headCommit == "c5e22242579d73f94faadaf10a31dfabf48d12d1")
        #expect(status.lastCommitDate == Date(timeIntervalSince1970: 1_791_540_000))
        #expect(status.dirty)
        #expect(status.behindOrigin == 1 && status.aheadOfOrigin == 2)
        #expect(status.unfetchedCommits == nil && status.record == nil)
        #expect(status.deployKey == sandbox.workspace + "/_sandvault/.ssh/deploy_app")
        #expect(fake.invocations.count == 4)
        #expect(fake.invocations.allSatisfy { $0.executable == "/usr/bin/sudo" && $0.arguments.contains("/usr/bin/sandbox-exec") })
    }

    @Test func untrustedOutputIsParsedStrictly() async throws {
        let sandbox = try Sandbox()
        defer { sandbox.cleanup() }
        let clone = sandbox.workspace + "/repos/app"
        try FileManager.default.createDirectory(atPath: clone + "/.git", withIntermediateDirectories: true)
        let fake = FakeCommandRunner()
        fake.on(SandboxedCommand.git(sandbox.environment, clone: clone, ["symbolic-ref"]).argv, stdout: "main\n\u{1B}]0;pwned\u{7}\n")
        fake.on(SandboxedCommand.git(sandbox.environment, clone: clone, ["-c"]).argv, stdout: String(repeating: "a", count: 4096))
        fake.on(SandboxedCommand.git(sandbox.environment, clone: clone, ["rev-list"]).argv, stdout: "-1\t2\n")
        fake.on(SandboxedCommand.git(sandbox.environment, clone: clone, ["--no-optional-locks"]).argv, stdout: "", exitCode: 128)
        let status = try #require(try await SandboxRepositories(environment: sandbox.environment, runner: fake, configStore: sandbox.configStore,
                                                                 shared: sandbox.shared, isMacOS: true).repositories().first)
        #expect(status.branch == nil && status.headCommit == nil && status.behindOrigin == nil && !status.dirty)
    }

    @Test func offMacOSCloneFieldsStayUnknown() async throws {
        let sandbox = try Sandbox()
        defer { sandbox.cleanup() }
        try FileManager.default.createDirectory(atPath: sandbox.workspace + "/repos/app/.git", withIntermediateDirectories: true)
        try sandbox.write("key", to: sandbox.workspace + "/_sandvault/.ssh/deploy_app")
        let fake = FakeCommandRunner()
        let status = try #require(try await SandboxRepositories(environment: sandbox.environment, runner: fake, configStore: sandbox.configStore,
                                                                 shared: sandbox.shared, isMacOS: false).repositories().first)
        #expect(status.branch == nil && status.headCommit == nil && status.lastCommitDate == nil && status.unfetchedCommits == nil)
        #expect(status.aheadOfOrigin == nil && status.behindOrigin == nil && !status.dirty)
        #expect(status.deployKey != nil)
        #expect(fake.invocations.isEmpty)
    }

    @Test func parsers() {
        #expect(SandboxRepositories.parseHead("abc 12") == nil)
        #expect(SandboxRepositories.parseHead("c5e22242579d73f94faadaf10a31dfabf48d12d1 -5") == nil)
        #expect(SandboxRepositories.parseHead("c5e22242579d73f94faadaf10a31dfabf48d12d1  1") == nil)
        let counts = SandboxRepositories.parseCounts("3\t0")
        #expect(counts?.behind == 3 && counts?.ahead == 0)
        #expect(SandboxRepositories.parseCounts("x") == nil && SandboxRepositories.parseCounts("3 0") == nil)
        #expect(SandboxRepositories.parseCounts("99999999999\t0") == nil)
        #expect(Text.isSafeBranch("feature/login-2") && Text.isSafeBranch("main"))
        for bad in ["-x", "a..b", "a b", "a:b", "@{u}", "a~1", "x.lock", "", ".hidden", "a\u{1B}"] {
            #expect(!Text.isSafeBranch(bad), "\(bad)")
        }
    }
}

/// The way back against real repositories: a host repository, its sv-clone style clone, sandbox commits and traps.
/// `SandboxEmulator` stands in for sudo and sandbox-exec, which this platform lacks.
@Suite struct RepositoryWayBackTests {
    struct Setup {
        let sandbox: Sandbox
        let host: String
        let clone: String
        let record: HandoffRecord

        func service(_ runner: CommandRunner) -> SandboxRepositories {
            SandboxRepositories(environment: sandbox.environment, runner: runner, configStore: sandbox.configStore,
                                shared: sandbox.shared, isMacOS: true)
        }
    }

    func setUp() async throws -> Setup {
        let sandbox = try Sandbox()
        let host = sandbox.base + "/src/app"
        let clone = sandbox.workspace + "/repos/app"
        try await TestGit.repository(at: host, files: ["README.md": "hello\n", "notes.txt": "one\n"])
        try FileManager.default.createDirectory(atPath: sandbox.workspace + "/repos", withIntermediateDirectories: true)
        try await TestGit.run(sandbox.workspace + "/repos", ["clone", "-q", host, clone])
        try await TestGit.run(host, ["remote", "add", "sandvault", clone])
        let record = HandoffRecord(hostPath: host, repoName: "app", sandboxPath: clone, agent: .claude)
        var config = AppConfig()
        config.repos = [record]
        try sandbox.configStore.save(config)
        return Setup(sandbox: sandbox, host: host, clone: clone, record: record)
    }

    @Test func countsUnfetchedCommitsAndFetchesBack() async throws {
        let setup = try await setUp()
        defer { setup.sandbox.cleanup() }
        for index in 1...2 {
            try setup.sandbox.write("work \(index)\n", to: setup.clone + "/work.txt")
            try await TestGit.run(setup.clone, ["add", "work.txt"])
            try await TestGit.run(setup.clone, ["commit", "-q", "-m", "work \(index)"])
        }
        try await TestGit.run(setup.clone, ["tag", "v9.9"])
        let runner = SandboxEmulator(environment: setup.sandbox.environment)

        // Before the first fetch the host's own branch is the base.
        let before = try #require(try await setup.service(runner).repositories().first)
        #expect(before.record?.id == setup.record.id)
        #expect(before.branch == "main")
        #expect(before.unfetchedCommits == 2)
        #expect(before.aheadOfOrigin == 2 && before.behindOrigin == 0)
        #expect(!before.dirty)

        let after = try await setup.service(runner).fetchBack(setup.record)
        #expect(after.unfetchedCommits == 0)
        let head = try await TestGit.run(setup.clone, ["rev-parse", "HEAD"])
        #expect(try await TestGit.run(setup.host, ["rev-parse", "refs/remotes/sandvault/main"]) == head)
        // Tags of the sandbox stay out of the host repository.
        #expect(try await TestGit.run(setup.host, ["tag", "--list"]) == "")
    }

    @Test func theHostNeverRunsGitInsideTheClone() async throws {
        let setup = try await setUp()
        defer { setup.sandbox.cleanup() }
        let traps = setup.sandbox.base + "/traps"
        try FileManager.default.createDirectory(atPath: traps, withIntermediateDirectories: true)
        func trap(_ name: String) throws -> String {
            let path = traps + "/" + name
            try setup.sandbox.write("#!/bin/sh\ntouch \(traps)/\(name).ran\ncat\n", to: path, mode: 0o755)
            return path
        }
        // What a sandbox can plant: a clean filter (git status re-hashes files through it), fsmonitor, gpg for log.
        try setup.sandbox.write("*.txt filter=evil\n", to: setup.clone + "/.git/info/attributes")
        try await TestGit.run(setup.clone, ["config", "filter.evil.clean", try trap("filter")])
        try await TestGit.run(setup.clone, ["config", "core.fsmonitor", try trap("fsmonitor")])
        try await TestGit.run(setup.clone, ["config", "log.showSignature", "true"])
        try await TestGit.run(setup.clone, ["config", "gpg.program", try trap("gpg")])
        try await signedLookingCommit(setup.clone)
        // Same size, newer mtime: git has to re-hash the file, which is when it runs a clean filter.
        try setup.sandbox.write("ONE\n", to: setup.clone + "/notes.txt")
        try FileManager.default.setAttributes([.modificationDate: Date().addingTimeInterval(60)], ofItemAtPath: setup.clone + "/notes.txt")

        // Sandboxed calls fail here, so anything that ran would have been the host's own doing.
        let runner = SandboxEmulator(environment: setup.sandbox.environment, runsSandboxed: false)
        let status = try #require(try await setup.service(runner).repositories().first)
        #expect(status.branch == nil && status.headCommit == nil && !status.dirty)
        _ = try await setup.service(runner).fetchBack(setup.record)

        func ran() throws -> Set<String> { Set(try FileManager.default.contentsOfDirectory(atPath: traps).filter { $0.hasSuffix(".ran") }) }
        #expect(try ran().isEmpty)
        let hostGit = runner.invocations.filter { $0.executable == GitSafe.gitPath }
        #expect(!hostGit.isEmpty)
        #expect(!hostGit.contains { $0.arguments.contains { $0.hasPrefix(setup.clone) } })
        let sandboxed = runner.invocations.filter { runner.unwrap($0) != nil }
        #expect(sandboxed.count >= 8)
        #expect(sandboxed.allSatisfy { $0.arguments.contains(setup.clone) })
        // fetchBack ran host-side in the host repository and fetched from the clone.
        #expect(try await TestGit.run(setup.host, ["rev-parse", "refs/remotes/sandvault/main"]) == TestGit.run(setup.clone, ["rev-parse", "HEAD"]))

        // Control: git run by the host inside the clone does trigger them.
        _ = try await ProcessCommandRunner().run(CommandInvocation(GitSafe.gitPath, ["-C", setup.clone, "status", "--porcelain"]))
        _ = try await ProcessCommandRunner().run(CommandInvocation(GitSafe.gitPath, ["-C", setup.clone, "log", "-1"]))
        #expect(try ran().isSuperset(of: ["filter.ran", "gpg.ran"]))
    }

    /// A commit with a `gpgsig` header, so `log --show-signature` calls `gpg.program`.
    func signedLookingCommit(_ repository: String) async throws {
        let tree = try await TestGit.run(repository, ["rev-parse", "HEAD^{tree}"])
        let parent = try await TestGit.run(repository, ["rev-parse", "HEAD"])
        let object = [
            "tree \(tree)", "parent \(parent)",
            "author Test <test@example.com> 1791540000 +0200", "committer Test <test@example.com> 1791540000 +0200",
            "gpgsig -----BEGIN PGP SIGNATURE-----", " ", " iQEzBAABCAAdFiEEAAAAAAAAAAAAAAAAAAAAAAAAAAAFAmZmZmYACgkQAAAAAAAAAAA=",
            " -----END PGP SIGNATURE-----", "", "signed", "",
        ].joined(separator: "\n")
        let file = repository + "/../commit-object"
        try Data(object.utf8).write(to: URL(fileURLWithPath: file))
        let commit = try await TestGit.run(repository, ["hash-object", "-t", "commit", "-w", file])
        try await TestGit.run(repository, ["update-ref", "refs/heads/main", commit])
        try FileManager.default.removeItem(atPath: file)
    }

    @Test func listsOnlyRealDirectories() async throws {
        let setup = try await setUp()
        defer { setup.sandbox.cleanup() }
        let repos = setup.sandbox.workspace + "/repos"
        try FileManager.default.createSymbolicLink(atPath: repos + "/linked", withDestinationPath: setup.host)
        try setup.sandbox.write("x", to: repos + "/file")
        try FileManager.default.createDirectory(atPath: repos + "/.hidden", withIntermediateDirectories: true)
        try FileManager.default.createDirectory(atPath: repos + "/esc\u{1B}[2Jape", withIntermediateDirectories: true)
        try FileManager.default.createDirectory(atPath: repos + "/plain", withIntermediateDirectories: true)

        let runner = SandboxEmulator(environment: setup.sandbox.environment)
        let all = try await setup.service(runner).repositories()
        #expect(all.map(\.name) == ["app", "plain"])
        #expect(all.first?.branch == "main")
        let plain = try #require(all.last)
        #expect(plain.branch == nil && plain.headCommit == nil && plain.record == nil && !plain.dirty)
        #expect(!runner.invocations.contains { $0.arguments.contains(repos + "/plain") })
    }

    @Test func fetchBackNeedsAHostRepository() async throws {
        let sandbox = try Sandbox()
        defer { sandbox.cleanup() }
        let service = SandboxRepositories(environment: sandbox.environment, runner: ProcessCommandRunner(), configStore: sandbox.configStore,
                                          shared: sandbox.shared, isMacOS: true)
        let remote = HandoffRecord(hostPath: "https://github.com/org/app.git", repoName: "app", sandboxPath: sandbox.workspace + "/repos/app", agent: .claude)
        await #expect(throws: SandvaultError.self) { try await service.fetchBack(remote) }
        let plain = sandbox.base + "/plain"
        try await TestGit.repository(at: plain)
        let noRemote = HandoffRecord(hostPath: plain, repoName: "plain", sandboxPath: sandbox.workspace + "/repos/plain", agent: .claude)
        await #expect(throws: SandvaultError.self) { try await service.fetchBack(noRemote) }
    }

    @Test func missingWorkspaceIsReported() async throws {
        let sandbox = try Sandbox()
        defer { sandbox.cleanup() }
        try FileManager.default.removeItem(atPath: sandbox.workspace)
        let service = SandboxRepositories(environment: sandbox.environment, runner: FakeCommandRunner(), configStore: sandbox.configStore, shared: sandbox.shared)
        await #expect(throws: SandvaultError.self) { try await service.repositories() }
    }
}
