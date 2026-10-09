import Foundation
import SandvaultCore
import Testing
@testable import SandvaultAppModel

@MainActor
@Suite struct SettingsModelTests {
    @Test func administratorScriptQuotesBothLayers() {
        #expect(AdministratorScript.shellQuote("/Applications/Sandvault Config.app") == "'/Applications/Sandvault Config.app'")
        #expect(AdministratorScript.shellQuote("it's") == #"'it'\''s'"#)
        #expect(AdministratorScript.appleScriptLiteral(#"a "b" \c"#) == #""a \"b\" \\c""#)

        let script = AdministratorScript.script(["/Apps/My \"Odd\" App's\\dir/svctl-helper", "install", "--user", "alice"])
        #expect(script == #"do shell script "'/Apps/My \"Odd\" App'\\''s\\dir/svctl-helper' 'install' '--user' 'alice'" with administrator privileges"#)
    }

    @Test func helperInstallRunsTheBundledHelperThroughOsascript() async throws {
        let runner = FakeCommandRunner()
        let source = "/Applications/Sandvault Config.app/Contents/MacOS/svctl-helper"
        let argv = AdministratorHelperInstaller.installArguments(source: source, user: "alice")
        #expect(argv == [source, "install", "--source", source, "--user", "alice", "--json"])
        let invocation = AdministratorScript.invocation(argv)
        #expect(invocation.executable == "/usr/bin/osascript")
        #expect(invocation.arguments.count == 2)
        runner.on(invocation.argv, stdout: #"{"details":{},"message":"installed the helper","ok":true}"# + "\r")

        let installer = AdministratorHelperInstaller(runner: runner, isMacOS: true)
        let result = try await installer.install(source: source, user: "alice")
        #expect(result == HelperResult(ok: true, message: "installed the helper"))
        #expect(runner.invocations.map(\.argv) == [invocation.argv])

        runner.on(AdministratorScript.invocation(AdministratorHelperInstaller.uninstallArguments(binary: AppPaths.helperPath, user: "alice")).argv,
                  stdout: "", exitCode: 1, stderr: "0:62: execution error: User canceled. (-128)")
        await #expect(throws: AdministratorScript.Cancelled.byUser) {
            try await installer.uninstall(binary: AppPaths.helperPath, user: "alice")
        }

        let linux = AdministratorHelperInstaller(runner: runner, isMacOS: false)
        await #expect(throws: SandvaultError.self) { try await linux.install(source: source, user: "alice") }
    }

    @Test func settingsUseTheBundledExecutables() async throws {
        let world = TestWorld()
        defer { world.cleanUp() }
        let model = world.model()
        let settings = model.settings

        await settings.installHelper()
        #expect(world.helperSetup.calls.get() == ["install /Applications/Sandvault Config.app/Contents/MacOS/svctl-helper alice"])
        #expect(settings.helperInstalled)
        #expect(settings.message?.title == "installed")

        await settings.uninstallHelper()
        #expect(world.helperSetup.calls.get().last == "uninstall \(AppPaths.helperPath) alice")

        await settings.installNetd()
        #expect(world.agent.calls.get() == ["install /Applications/Sandvault Config.app/Contents/MacOS/sandvault-netd"])
        #expect(settings.netdAgent?.installed == true)
        await settings.restartNetd()
        await settings.uninstallNetd()
        #expect(world.agent.calls.get().suffix(2) == ["restart", "uninstall"])

        #expect(settings.svctlLinkCommand == "sudo ln -sf '/Applications/Sandvault Config.app/Contents/MacOS/svctl' /usr/local/bin/svctl")
    }

    @Test func preferencesAndHandoffDefaults() async throws {
        let world = TestWorld()
        defer { world.cleanUp() }
        let settings = world.model().settings
        settings.setRefreshInterval(0.2)
        #expect(world.preferences.stored.get().refreshInterval == 1)
        settings.setRefreshInterval(5)
        #expect(settings.preferences.refreshInterval == 5)

        await settings.setDefaultAgent(.gemini)
        await settings.setTerminal(.iterm2)
        let handoff = try world.store.load().handoff
        #expect(handoff.defaultAgent == .gemini)
        #expect(handoff.terminal == .iterm2)
        #expect(settings.handoff == handoff)
    }

    @Test func missingBundledToolsAreReported() async {
        var world = TestWorld()
        defer { world.cleanUp() }
        world.checks = []
        var environment = world.appEnvironment
        environment.bundled = BundledTools()
        let model = AppModel(environment: environment)
        await model.settings.installHelper()
        #expect(model.settings.message?.kind == .warning)
        await model.settings.installNetd()
        #expect(model.settings.message?.detail == "Not installed: sandvault-netd inside the app bundle")
        #expect(world.helperSetup.calls.get().isEmpty)
        #expect(world.agent.calls.get().isEmpty)
    }
}
