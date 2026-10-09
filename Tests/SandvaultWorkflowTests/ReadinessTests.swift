import Foundation
import SandvaultCore
import Testing
@testable import SandvaultWorkflow

/// The readiness check against real repositories built with git.
@Suite struct ReadinessTests {
    func check(_ sandbox: Sandbox, _ source: String) async throws -> ReadinessReport {
        try await RepositoryHandoff(environment: sandbox.environment, runner: ProcessCommandRunner(), configStore: sandbox.configStore,
                                    shared: sandbox.shared).readiness(of: source)
    }

    func kinds(_ report: ReadinessReport, _ severity: FindingSeverity) -> [ReadinessKind] {
        report.findings.filter { $0.severity == severity }.map(\.kind)
    }

    @Test func cleanRepositoryIsReady() async throws {
        let sandbox = try Sandbox()
        defer { sandbox.cleanup() }
        let repo = sandbox.base + "/src/app"
        try await TestGit.repository(at: repo)
        let report = try await check(sandbox, repo)
        #expect(report.findings.isEmpty, "\(report.findings)")
        #expect(report.repositoryName == "app")
        #expect(report.repositoryPath == HostPath.resolved(repo))
        #expect(report.canProceed)
    }

    @Test func blockers() async throws {
        let sandbox = try Sandbox()
        defer { sandbox.cleanup() }
        let plain = sandbox.base + "/plain"
        try FileManager.default.createDirectory(atPath: plain, withIntermediateDirectories: true)
        #expect(try await check(sandbox, plain).findings.map(\.kind) == [.notGitRepository])

        let empty = sandbox.base + "/empty"
        try FileManager.default.createDirectory(atPath: empty, withIntermediateDirectories: true)
        try await TestGit.run(empty, ["init", "-q"])
        try await TestGit.run(empty, ["remote", "add", "origin", "https://example.com/o/empty.git"])
        let noCommits = try await check(sandbox, empty)
        #expect(kinds(noCommits, .blocker) == [.noCommits])
        #expect(!noCommits.canProceed)

        let local = sandbox.base + "/local"
        try await TestGit.repository(at: local, origin: nil)
        let noOrigin = try await check(sandbox, local)
        #expect(kinds(noOrigin, .blocker) == [.noOriginRemote])
        #expect(noOrigin.findings.first?.message.contains("origin") == true)

        let sub = sandbox.base + "/src/app"
        try await TestGit.repository(at: sub, files: ["lib/a.swift": "a"])
        let inside = try await check(sandbox, sub + "/lib")
        #expect(kinds(inside, .blocker) == [.notGitRepository])
        #expect(inside.findings.first?.message.contains("hand off its root") == true)

        #expect(try await check(sandbox, "no such thing").findings.map(\.kind) == [.notGitRepository])
        #expect(try await check(sandbox, "ext::sh -c touch% /tmp/pwned").findings.map(\.kind) == [.notGitRepository])
    }

    @Test func refusesTheSandboxesOwnFiles() async throws {
        let sandbox = try Sandbox()
        defer { sandbox.cleanup() }
        let clone = sandbox.workspace + "/repos/app"
        try await TestGit.repository(at: clone)
        let report = try await check(sandbox, clone)
        #expect(kinds(report, .blocker) == [.notGitRepository])
        #expect(report.findings.first?.message.contains("sandbox's own files") == true)
    }

    @Test func findingsMatchWhatTheCloneWillLookLike() async throws {
        let sandbox = try Sandbox()
        defer { sandbox.cleanup() }
        let repo = sandbox.base + "/src/app"
        try await TestGit.repository(at: repo, files: [
            "README.md": "hello\n", ".gitignore": ".venv/\n.env\n", ".env.production": "TOKEN=x\n", ".env.example": "TOKEN=\n",
            ".envrc": "use flake\n", "docs/guide.md": "guide\n",
            ".gitmodules": """
            [submodule "vendor/lib"]
            \tpath = vendor/lib
            \turl = /Users/alice/src/lib
            [submodule "vendor/remote"]
            \tpath = vendor/remote
            \turl = https://github.com/org/remote.git
            [submodule "vendor/sibling"]
            \tpath = vendor/sibling
            \turl = ../sibling.git

            """,
        ])
        let manager = FileManager.default
        try manager.createSymbolicLink(atPath: repo + "/outside", withDestinationPath: "../../secrets")
        try manager.createSymbolicLink(atPath: repo + "/home-link", withDestinationPath: "/Users/alice/notes")
        try manager.createSymbolicLink(atPath: repo + "/docs/inside", withDestinationPath: "../README.md")
        try manager.createSymbolicLink(atPath: repo + "/system", withDestinationPath: "/usr/bin/env")
        try await TestGit.run(repo, ["add", "outside", "home-link", "docs/inside", "system"])
        try await TestGit.run(repo, ["commit", "-q", "-m", "links"])
        try sandbox.write("changed\n", to: repo + "/README.md")
        try sandbox.write("new\n", to: repo + "/notes.txt")
        try sandbox.write("SECRET=1\n", to: repo + "/.env")
        try sandbox.write("SECRET=2\n", to: repo + "/config/.env.local")
        try sandbox.write("home = /opt/homebrew/opt/python@3.12/bin\nversion = 3.12.4\n", to: repo + "/.venv/pyvenv.cfg")

        let report = try await check(sandbox, repo)
        let byKind = Dictionary(grouping: report.findings, by: \.kind)
        #expect(report.canProceed)
        #expect(byKind[.uncommittedChanges]?.map(\.severity) == [.warning])
        #expect(byKind[.untrackedFiles]?.first?.message.hasPrefix("2 untracked files") == true)
        #expect(Set(byKind[.symlinkOutside]?.compactMap(\.path) ?? []) == ["outside", "home-link"])
        #expect(byKind[.symlinkOutside]?.allSatisfy { $0.severity == .warning } == true)
        let dotenv = Dictionary(uniqueKeysWithValues: (byKind[.dotenvFile] ?? []).map { ($0.path ?? "", $0.severity) })
        #expect(dotenv == [".env.production": .warning, ".env": .info, "config/.env.local": .info])
        #expect(byKind[.envrc]?.map(\.severity) == [.info])
        #expect(byKind[.virtualenvHostInterpreter]?.first?.path == ".venv")
        #expect(byKind[.localSubmodule]?.compactMap(\.path) == ["vendor/lib"])
        #expect(byKind[.localSubmodule]?.first?.severity == .warning)
        // Order: warnings before info.
        #expect(report.findings.map(\.severity) == report.findings.map(\.severity).sorted(by: >))
    }

    @Test func relativeSubmodulesAreLocalWhenOriginIs() async throws {
        let sandbox = try Sandbox()
        defer { sandbox.cleanup() }
        let repo = sandbox.base + "/app"
        try await TestGit.repository(at: repo, files: [".gitmodules": "[submodule \"s\"]\n\tpath = s\n\turl = ../s.git\n"], origin: "/Users/alice/bare/app.git")
        #expect(try await check(sandbox, repo).findings.filter { $0.kind == .localSubmodule }.count == 1)
    }

    @Test func worktreeAndExistingClone() async throws {
        let sandbox = try Sandbox()
        defer { sandbox.cleanup() }
        let repo = sandbox.base + "/src/app"
        try await TestGit.repository(at: repo)
        let worktree = sandbox.base + "/src/feature"
        try await TestGit.run(repo, ["worktree", "add", "-q", "-b", "feature", worktree])
        try FileManager.default.createDirectory(atPath: sandbox.workspace + "/repos/feature/.git", withIntermediateDirectories: true)

        let report = try await check(sandbox, worktree)
        #expect(report.repositoryName == "feature")
        #expect(report.findings.map(\.kind) == [.gitFileIndirection, .alreadyHandedOff])
        #expect(report.findings.allSatisfy { $0.severity == .info })

        try FileManager.default.removeItem(atPath: sandbox.workspace + "/repos/feature/.git")
        try sandbox.write("x", to: sandbox.workspace + "/repos/feature/stray")
        let stray = try #require(try await check(sandbox, worktree).findings.first { $0.kind == .alreadyHandedOff })
        #expect(stray.severity == .warning)
    }

    @Test func remoteURLsGetShapeValidationOnly() async throws {
        let sandbox = try Sandbox()
        defer { sandbox.cleanup() }
        for url in ["https://github.com/org/app.git", "git@github.com:org/app.git", "ssh://git@host:2222/org/app", "git://host/app"] {
            let report = try await check(sandbox, url)
            #expect(report.findings.isEmpty, "\(url)")
            #expect(report.repositoryName == "app")
        }
        try FileManager.default.createDirectory(atPath: sandbox.workspace + "/repos/app/.git", withIntermediateDirectories: true)
        #expect(try await check(sandbox, "https://github.com/org/app.git").findings.map(\.kind) == [.alreadyHandedOff])
        for bad in ["file:///Users/alice/app", "ext::sh", "https://host/a b", "-oProxyCommand=x@host:repo", "http://-host/x"] {
            #expect(try await check(sandbox, bad).findings.map(\.severity) == [.blocker], "\(bad)")
        }
    }

    @Test func manyFindingsAreSummarized() async throws {
        let sandbox = try Sandbox()
        defer { sandbox.cleanup() }
        let repo = sandbox.base + "/app"
        try await TestGit.repository(at: repo)
        for index in 0..<25 { try FileManager.default.createSymbolicLink(atPath: repo + "/l\(index)", withDestinationPath: "../x\(index)") }
        try await TestGit.run(repo, ["add", "-A"])
        try await TestGit.run(repo, ["commit", "-q", "-m", "links"])
        let links = try await check(sandbox, repo).findings.filter { $0.kind == .symlinkOutside }
        #expect(links.count == ReadinessCheck.findingLimit + 1)
        #expect(links.last?.message == "... and 5 more like this")
    }

    @Test func parsers() {
        #expect(ReadinessCheck.objectBytes(countObjects: "count: 4\nsize: 16\nin-pack: 9\npacks: 1\nsize-pack: 2000000\n") == 2_000_016 * 1024)
        #expect(ReadinessCheck.pyvenvHome("home = /usr/local/bin\ninclude-system-site-packages = false\n") == "/usr/local/bin")
        #expect(ReadinessCheck.isDotenv(".env") && ReadinessCheck.isDotenv(".env.local"))
        #expect(!ReadinessCheck.isDotenv(".envrc") && !ReadinessCheck.isDotenv(".env.example") && !ReadinessCheck.isDotenv("env"))
        #expect(RepositoryName.derive(from: "https://github.com/org/app.git") == "app")
        #expect(RepositoryName.derive(from: "git@github.com:org/app.git") == "app")
        #expect(RepositoryName.derive(from: "git@host:app") == "app")
        #expect(RepositoryName.derive(from: "/Users/alice/src/my.app/") == "my.app")
        #expect(RepositoryName.derive(from: "/Users/alice/src/tool.git") == "tool")
        #expect(!RepositoryName.isValid("..") && !RepositoryName.isValid("") && !RepositoryName.isValid("a\u{1B}[2J"))
        #expect(RepositorySource.isLocalURL("/srv/repo.git") && RepositorySource.isLocalURL("file:///srv/repo") && RepositorySource.isLocalURL("relative/dir"))
        #expect(!RepositorySource.isLocalURL("git@github.com:org/a.git") && !RepositorySource.isLocalURL("https://h/a"))
    }
}
