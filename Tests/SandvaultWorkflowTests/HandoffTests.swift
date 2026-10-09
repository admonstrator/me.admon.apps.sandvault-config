import Foundation
import SandvaultCore
import Testing
@testable import SandvaultWorkflow

@Suite struct HandoffTests {
    func service(_ sandbox: Sandbox, _ runner: CommandRunner, macOS: Bool = false) -> RepositoryHandoff {
        RepositoryHandoff(environment: sandbox.environment, runner: runner, configStore: sandbox.configStore, shared: sandbox.shared, isMacOS: macOS)
    }

    @Test func writesBriefingAndPatchThroughSharedFiles() async throws {
        let sandbox = try Sandbox()
        defer { sandbox.cleanup() }
        let repo = sandbox.base + "/src/app"
        try await TestGit.repository(at: repo, files: ["README.md": "hello\n", "logo.bin": "\u{0}\u{1}\u{2}"])
        try sandbox.write("hello, changed\n", to: repo + "/README.md")
        try Data([0, 9, 9, 0xFF]).write(to: URL(fileURLWithPath: repo + "/logo.bin"))
        let runner = MixedRunner()
        let task = "Fix the \"login\" bug; don't touch $HOME or `id`."

        let result = try await service(sandbox, runner).handOff(
            HandoffRequest(source: repo, agent: .claude, task: task, includeUncommitted: true)
        )
        let briefing = sandbox.workspace + "/tmp/handoff-app.md"
        let patch = sandbox.workspace + "/tmp/handoff-app.patch"
        #expect(result.briefingPath == briefing)
        #expect(!result.launched)
        #expect(result.command == ["sv-clone", repo, "--", "claude", "--", "Read \(briefing) and continue the task described there."])
        #expect(!runner.invocations.contains { $0.executable != GitSafe.gitPath })

        let text = try sandbox.read(briefing)
        #expect(text.contains(task))
        #expect(text.contains("- Branch: main"))
        #expect(text.contains("    git apply \(patch)"))
        #expect(text.contains("- Clone in the sandbox: \(sandbox.workspace)/repos/app"))
        #expect(FileKind.mode(briefing) == 0o640 && FileKind.mode(patch) == 0o640)

        // The patch carries both changes, binary included, onto a fresh clone.
        let clone = sandbox.base + "/clone"
        try await TestGit.run(sandbox.base, ["clone", "-q", repo, clone])
        try await TestGit.run(clone, ["apply", patch])
        #expect(try sandbox.read(clone + "/README.md") == "hello, changed\n")
        #expect(try Data(contentsOf: URL(fileURLWithPath: clone + "/logo.bin")) == Data([0, 9, 9, 0xFF]))

        let config = try sandbox.configStore.load()
        #expect(config.repos.map(\.repoName) == ["app"])
        #expect(config.repos.first?.hostPath == repo)
        #expect(config.repos.first?.sandboxPath == sandbox.workspace + "/repos/app")

        // A later hand-off without uncommitted changes removes the stale patch and replaces the record.
        _ = try await service(sandbox, runner).handOff(HandoffRequest(source: repo, agent: .codex, task: "Next step"))
        #expect(FileKind.of(patch) == .missing)
        #expect(try sandbox.configStore.load().repos.map(\.agent) == [.codex])
    }

    @Test(arguments: TerminalApp.allCases)
    func launchesTheChosenTerminal(terminal: TerminalApp) async throws {
        let sandbox = try Sandbox()
        defer { sandbox.cleanup() }
        let repo = sandbox.base + "/my app"
        try await TestGit.repository(at: repo)
        let runner = MixedRunner()
        runner.fake.on(["/usr/bin/osascript"], stdout: "")
        runner.fake.on(["/usr/bin/open"], stdout: "")

        let result = try await service(sandbox, runner, macOS: true).handOff(
            HandoffRequest(source: repo, agent: .gemini, task: "Go", terminal: terminal, svOptions: ["--browser"], deployKey: .readWrite)
        )
        #expect(result.launched)
        #expect(result.command.prefix(5) == ["sv-clone", "-w", repo, "--", "--browser"])
        #expect(result.command.suffix(3).first == "--")
        #expect(result.command.suffix(2).first == "--prompt-interactive")
        let launch = try #require(runner.invocations.last)
        #expect(launch == TerminalLaunch.invocation(terminal, command: ShellQuoting.join(result.command)))
    }

    @Test func failedLaunchRecordsNothing() async throws {
        let sandbox = try Sandbox()
        defer { sandbox.cleanup() }
        let repo = sandbox.base + "/app"
        try await TestGit.repository(at: repo)
        let runner = MixedRunner()
        runner.fake.on(["/usr/bin/osascript"], stdout: "", exitCode: 1, stderr: "Not authorized to send Apple events to Terminal. (-1743)")
        await #expect(throws: SandvaultError.self) {
            try await service(sandbox, runner, macOS: true).handOff(HandoffRequest(source: repo, agent: .claude))
        }
        #expect(try sandbox.configStore.load().repos.isEmpty)
    }

    @Test func refusesAPlantedSymlink() async throws {
        let sandbox = try Sandbox()
        defer { sandbox.cleanup() }
        let repo = sandbox.base + "/app"
        try await TestGit.repository(at: repo)
        let hostDirectory = sandbox.home + "/Documents"
        try FileManager.default.createDirectory(atPath: hostDirectory, withIntermediateDirectories: true)
        try FileManager.default.createSymbolicLink(atPath: sandbox.workspace + "/tmp", withDestinationPath: hostDirectory)

        await #expect(throws: SandvaultError.self) {
            try await service(sandbox, MixedRunner()).handOff(HandoffRequest(source: repo, agent: .claude, task: "x"))
        }
        #expect(try FileManager.default.contentsOfDirectory(atPath: hostDirectory).isEmpty)

        // A symlinked file is replaced, never written through.
        try FileManager.default.removeItem(atPath: sandbox.workspace + "/tmp")
        try FileManager.default.createDirectory(atPath: sandbox.workspace + "/tmp", withIntermediateDirectories: true)
        try sandbox.write("host secret", to: hostDirectory + "/notes.md")
        try FileManager.default.createSymbolicLink(atPath: sandbox.workspace + "/tmp/handoff-app.md", withDestinationPath: hostDirectory + "/notes.md")
        _ = try await service(sandbox, MixedRunner()).handOff(HandoffRequest(source: repo, agent: .claude, task: "x"))
        #expect(try sandbox.read(hostDirectory + "/notes.md") == "host secret")
        #expect(FileKind.of(sandbox.workspace + "/tmp/handoff-app.md") == .regular)
    }

    @Test func refusesBlockersAndBadOptions() async throws {
        let sandbox = try Sandbox()
        defer { sandbox.cleanup() }
        let repo = sandbox.base + "/app"
        try await TestGit.repository(at: repo, origin: nil)
        await #expect(throws: SandvaultError.self) {
            try await service(sandbox, MixedRunner()).handOff(HandoffRequest(source: repo, agent: .claude))
        }
        try await TestGit.run(repo, ["remote", "add", "origin", "https://example.com/o/app.git"])
        for options in [["--no-sandbox"], ["-x"], ["--rebuild"], ["--bogus"], ["--browser", "-e"]] {
            await #expect(throws: SandvaultError.self, "\(options)") {
                try await service(sandbox, MixedRunner()).handOff(HandoffRequest(source: repo, agent: .claude, svOptions: options))
            }
        }
        #expect(try sandbox.configStore.load().repos.isEmpty)
    }

    @Test func remoteSources() async throws {
        let sandbox = try Sandbox()
        defer { sandbox.cleanup() }
        let url = "git@github.com:org/app.git"
        let result = try await service(sandbox, MixedRunner()).handOff(HandoffRequest(source: url, agent: .claude, task: "Read the docs"))
        #expect(result.command.prefix(3) == ["sv-clone", url, "--"])
        #expect(try sandbox.read(sandbox.workspace + "/tmp/handoff-app.md").contains("Source on the host: \(url)"))
        await #expect(throws: SandvaultError.self) {
            try await service(sandbox, MixedRunner()).handOff(HandoffRequest(source: url, agent: .claude, includeUncommitted: true))
        }
    }

    @Test func withoutTaskThereIsNoBriefing() async throws {
        let sandbox = try Sandbox()
        defer { sandbox.cleanup() }
        let repo = sandbox.base + "/app"
        try await TestGit.repository(at: repo)
        try FileManager.default.removeItem(atPath: sandbox.workspace)
        let result = try await service(sandbox, MixedRunner()).handOff(HandoffRequest(source: repo, agent: .claude, task: "  \n"))
        #expect(result.briefingPath == nil)
        #expect(result.command == ["sv-clone", repo, "--", "claude"])
    }

    @Test func briefingWithoutChanges() {
        let text = HandoffBriefing.markdown(name: "app", source: "/s", branch: nil, clonePath: "/c", task: nil, patch: .noChanges,
                                            date: Date(timeIntervalSince1970: 0))
        #expect(text.contains("The host had no uncommitted changes in tracked files."))
        #expect(!text.contains("## Task"))
        #expect(text.contains("- Handed off: 1970-01-01T00:00:00Z"))
    }
}
