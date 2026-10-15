import Foundation
import SandvaultCore
import Testing
@testable import SandvaultWorkflow

@Suite struct DockerSandboxTests {
    static let sbx = "/opt/homebrew/bin/sbx"

    func docker(_ runner: CommandRunner, installed: Bool = true, macOS: Bool = false) -> DockerSandboxes {
        DockerSandboxes(runner: runner, isMacOS: macOS, candidates: [Self.sbx], exists: { _ in installed })
    }

    func service(_ sandbox: Sandbox, _ runner: CommandRunner, installed: Bool = true, macOS: Bool = false) -> RepositoryHandoff {
        RepositoryHandoff(
            environment: sandbox.environment, runner: runner, configStore: sandbox.configStore, shared: sandbox.shared, isMacOS: macOS,
            docker: docker(runner, installed: installed, macOS: macOS)
        )
    }

    // MARK: - sbx output

    @Test func parsesTheListAndIgnoresUnknownFields() throws {
        let json = #"{"sandboxes":[{"id":"9b6d","name":"sv-app","status":"running","workspaces":["/Users/alice/git/app"],"agent":"claude","extra":true},"#
            + #"{"name":"a-shell","status":"stopped","agent":"shell"}]}"#
        let list = try #require(DockerSandboxes.parseList(Data(json.utf8)))
        #expect(list == [
            DockerSandbox(name: "a-shell", status: "stopped", agent: "shell"),
            DockerSandbox(name: "sv-app", status: "running", agent: "claude", workspaces: ["/Users/alice/git/app"]),
        ])
        #expect(DockerSandboxes.parseList(Data("not json".utf8)) == nil)

        // sbx on macOS 27 (Aaron's Mac, 2026-10-15): a bare array.
        let bare = """
        [
          {
            "name": "claude-admon",
            "id": "78e63276-130d-4482-b23d-ca9a61b634ef",
            "agent": "claude",
            "status": "running",
            "last_used_at": "2026-10-15T13:06:02.297315Z",
            "workspaces": [
              "/Users/admon"
            ],
            "created_at": "2026-10-15T13:06:00Z"
          }
        ]
        """
        let mac = try #require(DockerSandboxes.parseList(Data(bare.utf8)))
        #expect(mac == [DockerSandbox(name: "claude-admon", status: "running", agent: "claude", workspaces: ["/Users/admon"])])
        #expect(mac[0].mountsHome("/Users/admon"))
        #expect(!DockerSandbox(name: "a", status: "running", workspaces: ["/Users/admon/git/app"]).mountsHome("/Users/admon"))
        #expect(DockerSandbox(name: "a", status: "running", workspaces: ["/Users/"]).mountsHome("/Users/admon"))
        #expect(DockerSandboxes.parseList(Data(#"{"sandboxes":[]}"#.utf8)) == [])
    }

    @Test func readsTheStateWithSSHForwarding() async {
        let runner = FakeCommandRunner()
        runner.on([Self.sbx, "ls", "--json"], stdout: #"{"sandboxes":[{"name":"sv-app","status":"running"}]}"#)
        runner.on([Self.sbx, "settings", "get", "ssh.agentForwardingEnabled"], stdout: "true\n")
        let state = await docker(runner).state()
        #expect(state.executable == Self.sbx)
        #expect(state.sandboxes.map(\.name) == ["sv-app"])
        #expect(state.sshAgentForwarding == true)
        #expect(state.problem == nil)

        #expect(await docker(runner, installed: false).state() == .notInstalled)
    }

    @Test func reportsAFailingList() async {
        let runner = FakeCommandRunner()
        runner.on([Self.sbx, "ls", "--json"], stdout: "", exitCode: 1, stderr: "not signed in, run sbx login")
        let state = await docker(runner).state()
        #expect(state.problem == "not signed in, run sbx login")
        #expect(state.sshAgentForwarding == nil)
    }

    @Test func namesAreDerivedAndMadeUnique() {
        #expect(DockerSandboxName.make(for: "me.admon.apps.Sandvault_Config", taken: []) == "sv-me-admon-apps-sandvault-config")
        #expect(DockerSandboxName.make(for: "app", taken: ["sv-app", "sv-app-2"]) == "sv-app-3")
        #expect(DockerSandboxName.make(for: "--x--", taken: []) == "sv-x")
    }

    @Test func runArgumentsPassTheTaskAsFirstPrompt() throws {
        #expect(try DockerSandboxes.runArguments(sbx: "sbx", name: "sv-app", agent: .claude, folder: "/r/app", prompt: "Fix it")
            == ["sbx", "run", "--name", "sv-app", "--clone", "claude", "/r/app", "--", "Fix it"])
        #expect(try DockerSandboxes.runArguments(sbx: "sbx", name: "sv-app", agent: .shell, folder: "/r/app", prompt: "Fix it")
            == ["sbx", "run", "--name", "sv-app", "--clone", "shell", "/r/app"])
        #expect(throws: SandvaultError.self) {
            try DockerSandboxes.runArguments(sbx: "sbx", name: "sv-app", agent: .pi, folder: "/r/app", prompt: nil)
        }
        #expect(throws: SandvaultError.self) { try DockerSandboxes.attachArguments(sbx: "sbx", name: "--rm") }
    }

    // MARK: - Hand-off

    @Test func readinessDropsWhatOnlySvNeeds() async throws {
        let sandbox = try Sandbox()
        defer { sandbox.cleanup() }
        let repo = sandbox.base + "/src/app"
        try await TestGit.repository(at: repo, origin: nil)
        let runner = MixedRunner()

        let sv = try await service(sandbox, runner).readiness(of: repo, target: .sandvault)
        #expect(sv.findings.contains { $0.kind == .noOriginRemote })
        let docker = try await service(sandbox, runner).readiness(of: repo, target: .dockerSandbox)
        #expect(docker.canProceed)
        #expect(!docker.findings.contains { $0.kind == .noOriginRemote })

        let missing = try await service(sandbox, runner, installed: false).readiness(of: repo, target: .dockerSandbox)
        #expect(missing.findings.first?.kind == .targetMissing)
        #expect(!missing.canProceed)
    }

    @Test func handsOffALocalFolder() async throws {
        let sandbox = try Sandbox()
        defer { sandbox.cleanup() }
        let repo = sandbox.base + "/src/app"
        try await TestGit.repository(at: repo)
        let runner = MixedRunner()
        runner.fake.on([Self.sbx, "ls", "--json"], stdout: #"{"sandboxes":[{"name":"sv-app","status":"stopped"}]}"#)
        runner.fake.on(["/usr/bin/osascript"], stdout: "")
        // An sv hand-off of the same repository keeps its record.
        _ = try await service(sandbox, runner).handOff(HandoffRequest(source: repo, agent: .claude))

        let result = try await service(sandbox, runner, macOS: true).handOff(
            HandoffRequest(source: repo, agent: .codex, task: "Add tests", terminal: .ghostty, target: .dockerSandbox)
        )
        #expect(result.prepare == nil)
        #expect(result.command == [Self.sbx, "run", "--name", "sv-app-2", "--clone", "codex", repo, "--", "Add tests"])
        #expect(result.launched)
        #expect(result.briefingPath == nil)
        #expect(runner.invocations.last == TerminalLaunch.invocation(.ghostty, command: result.shellLine))

        let repos = try sandbox.configStore.load().repos
        #expect(repos.count == 2)
        let record = try #require(repos.last)
        #expect(record.dockerSandbox == "sv-app-2" && record.hostPath == repo && record.sandboxPath == "sbx:sv-app-2")
        #expect(record.target == .dockerSandbox)
        #expect(repos.first?.dockerSandbox == nil)
    }

    @Test func clonesAURLIntoTheCloneFolderFirst() async throws {
        let sandbox = try Sandbox()
        defer { sandbox.cleanup() }
        var config = try sandbox.configStore.load()
        config.handoff.cloneDirectory = "~/git/"
        try sandbox.configStore.save(config)
        let runner = MixedRunner()
        runner.fake.on([Self.sbx, "ls", "--json"], stdout: #"{"sandboxes":[]}"#)
        let url = "git@github.com:org/My.App.git"

        let report = try await service(sandbox, runner).readiness(of: url, target: .dockerSandbox)
        #expect(report.repositoryPath == sandbox.home + "/git/My.App")
        #expect(report.findings.map(\.kind) == [.cloneFirst])
        #expect(report.canProceed)

        let result = try await service(sandbox, runner).handOff(HandoffRequest(source: url, agent: .claude, target: .dockerSandbox))
        let folder = sandbox.home + "/git/My.App"
        #expect(result.prepare == ["git", "clone", "--", url, folder])
        #expect(result.command == [Self.sbx, "run", "--name", "sv-my-app", "--clone", "claude", folder])
        #expect(result.shellLine == "git clone -- git@github.com:org/My.App.git \(folder) && \(Self.sbx) run --name sv-my-app --clone claude \(folder)")
        #expect(!result.launched)

        // A folder that exists but is no repository blocks; an existing clone is used as it is.
        try FileManager.default.createDirectory(atPath: folder, withIntermediateDirectories: true)
        let blocked = try await service(sandbox, runner).readiness(of: url, target: .dockerSandbox)
        #expect(!blocked.canProceed)
        try FileManager.default.removeItem(atPath: folder)
        try await TestGit.repository(at: folder)
        let existing = try await service(sandbox, runner).readiness(of: url, target: .dockerSandbox)
        #expect(existing.canProceed && existing.findings.first?.kind == .cloneFirst)
        let again = try await service(sandbox, runner).handOff(HandoffRequest(source: url, agent: .claude, target: .dockerSandbox))
        #expect(again.prepare == nil)
    }

    @Test func refusesWhatDockerSandboxesCannotDo() async throws {
        let sandbox = try Sandbox()
        defer { sandbox.cleanup() }
        let repo = sandbox.base + "/src/app"
        try await TestGit.repository(at: repo)
        let runner = MixedRunner()
        await #expect(throws: SandvaultError.self) {
            _ = try await service(sandbox, runner).handOff(HandoffRequest(source: repo, agent: .muse, target: .dockerSandbox))
        }
        await #expect(throws: SandvaultError.self) {
            _ = try await service(sandbox, runner).handOff(HandoffRequest(source: repo, agent: .claude, includeUncommitted: true, target: .dockerSandbox))
        }
        await #expect(throws: SandvaultError.self) {
            _ = try await service(sandbox, runner, installed: false).handOff(HandoffRequest(source: repo, agent: .claude, target: .dockerSandbox))
        }
        #expect(try sandbox.configStore.load().repos.isEmpty)
    }

    @Test func fetchBackUsesTheSandboxRemote() async throws {
        let sandbox = try Sandbox()
        defer { sandbox.cleanup() }
        let host = sandbox.base + "/src/app"
        let vm = sandbox.base + "/vm/app"
        try await TestGit.repository(at: host)
        try await TestGit.run(sandbox.base, ["clone", "-q", host, vm])
        try sandbox.write("more\n", to: vm + "/more.txt")
        try await TestGit.run(vm, ["add", "-A"])
        try await TestGit.run(vm, ["commit", "-q", "-m", "agent work"])
        try await TestGit.run(host, ["remote", "add", "sandbox-sv-app", vm])
        let record = HandoffRecord(hostPath: host, repoName: "app", sandboxPath: "sbx:sv-app", agent: .claude, dockerSandbox: "sv-app")
        var config = try sandbox.configStore.load()
        config.repos = [record]
        try sandbox.configStore.save(config)

        let repos = SandboxRepositories(environment: sandbox.environment, runner: MixedRunner(), configStore: sandbox.configStore, shared: sandbox.shared)
        #expect(try await repos.repositories().map(\.sandboxPath) == ["sbx:sv-app"])
        let status = try await repos.fetchBack(record)
        #expect(status.record == record)
        let fetched = try await TestGit.run(host, ["log", "-1", "--format=%s", "sandbox-sv-app/main"])
        #expect(fetched == "agent work")
    }
}
