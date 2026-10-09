import Foundation
import SandvaultCore
import Testing
@testable import SandvaultWorkflow

@Suite struct SandboxLifecycleTests {
    @Test func commandLinesQuoteEveryWordAndChainFollowUps() throws {
        #expect(try SandboxLifecycle.commandLine(.open(.claude, directory: "/Users/Shared/sv-alice/repos/my app"), svOptions: ["--browser"])
            == "sv --browser claude '/Users/Shared/sv-alice/repos/my app'")
        #expect(try SandboxLifecycle.commandLine(.open(.shell, directory: nil), svOptions: []) == "sv shell")
        #expect(try SandboxLifecycle.commandLine(.build, svOptions: ["--browser"], followUp: [
            ["/Applications/Sandvault Config.app/Contents/MacOS/svctl", "rules", "apply", "--yes"],
        ]) == "sv build && '/Applications/Sandvault Config.app/Contents/MacOS/svctl' rules apply --yes")
        #expect(try SandboxLifecycle.commandLine(.rebuild, svOptions: []) == "sv --rebuild build")
        #expect(try SandboxLifecycle.commandLine(.uninstall, svOptions: []) == "sv uninstall")
    }

    @Test func sessionsRefuseOptionsThatWeakenTheSandbox() {
        #expect(throws: SandvaultError.self) { try SandboxLifecycle.commandLine(.open(.claude, directory: nil), svOptions: ["--no-sandbox"]) }
        #expect(throws: SandvaultError.self) { try SandboxLifecycle.commandLine(.open(.claude, directory: nil), svOptions: ["--rebuild"]) }
        #expect(throws: SandvaultError.self) { try SandboxLifecycle.commandLine(.open(.shell, directory: "/tmp/a\nrm -rf ~"), svOptions: []) }
    }

    @Test func stateComesFromTheFilesSvWrites() async {
        let environment = SandvaultEnvironment(hostUser: "alice", hostHome: "/Users/alice")
        let present: Set<String> = [environment.sandboxProfilePath, environment.sandvaultHome]
        let service = SandboxLifecycle(environment: environment, runner: ProcessCommandRunner(), isMacOS: false, exists: { present.contains($0) })
        let state = await service.state()
        #expect(state == SandboxState(installed: false, profile: true, home: true, workspace: false))
        #expect(state.incomplete)
    }

    @Test func offMacOSTheLineComesBackUnlaunched() async throws {
        let service = SandboxLifecycle(
            environment: SandvaultEnvironment(hostUser: "alice", hostHome: "/Users/alice"), runner: ProcessCommandRunner(), isMacOS: false
        )
        let launch = try await service.run(.open(.codex, directory: nil), terminal: .terminal, svOptions: [], followUp: [])
        #expect(launch == SandboxLaunch(command: "sv codex", launched: false))
    }

    @Test func onMacOSTheTerminalGetsTheLineAsOneArgument() async throws {
        let runner = MixedRunner()
        runner.fake.on(["/usr/bin/osascript"], stdout: "")
        let service = SandboxLifecycle(environment: SandvaultEnvironment(hostUser: "alice", hostHome: "/Users/alice"), runner: runner, isMacOS: true)
        let launch = try await service.run(.uninstall, terminal: .terminal, svOptions: [], followUp: [])
        #expect(launch.launched)
        let invocation = try #require(runner.invocations.last)
        #expect(invocation.executable == "/usr/bin/osascript" && invocation.arguments.last == "sv uninstall")
    }
}
