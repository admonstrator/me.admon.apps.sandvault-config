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

    @Test func startNetdInstallsOnceThenRestarts() async throws {
        let world = TestWorld()
        defer { world.cleanUp() }
        let settings = world.model().settings
        world.agent.loadsOnInstall.set(true)

        await settings.startNetd()
        #expect(world.agent.calls.get() == ["install /Applications/Sandvault Config.app/Contents/MacOS/sandvault-netd"])
        await settings.startNetd()
        #expect(world.agent.calls.get().last == "restart")
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

    @Test func connectionRequestSettingsRoundTripAndReloadNetd() async throws {
        let world = TestWorld()
        defer { world.cleanUp() }
        let settings = world.model().settings
        #expect(settings.askDetails == AskDetailSettings())

        await settings.setAskDetail(.reverseDNS, false)
        await settings.setAskDetail(.program, false)
        await settings.setAskDetail(.saferDefault, false)
        await settings.setNetworkLookup(.online)
        await settings.setMarkedCountries("ru, kp  IR,ru")
        #expect(settings.message == nil)

        let saved = try world.store.load().network.askDetails
        #expect(!saved.reverseDNS)
        #expect(!saved.program)
        #expect(!saved.saferDefault)
        #expect(saved.name && saved.port && saved.history && saved.assessment)
        #expect(saved.network == .online)
        #expect(saved.markedCountries == ["RU", "KP", "IR"])
        #expect(settings.askDetails == saved)
        #expect(settings.markedCountriesText == "RU, KP, IR")
        #expect(settings.isOn(.name) && !settings.isOn(.reverseDNS) && !settings.isOn(.saferDefault))
        #expect(Set(AskDetailSwitch.lookupsBeforeNetwork + AskDetailSwitch.lookupsAfterNetwork + AskDetailSwitch.judgement) == Set(AskDetailSwitch.allCases))
        #expect(world.netd.reloads.get() == 5)

        await settings.setMarkedCountries("")
        #expect(try world.store.load().network.askDetails.markedCountries.isEmpty)
    }

    @Test func invalidCountryCodesSaveNothing() async throws {
        let world = TestWorld()
        defer { world.cleanUp() }
        let settings = world.model().settings
        await settings.setMarkedCountries("RU")
        await settings.setMarkedCountries("RU, Russia")
        #expect(settings.message?.kind == .warning)
        #expect(settings.message?.detail == "Russia is not a two-letter ISO country code (e.g. RU, KP)")
        #expect(try world.store.load().network.askDetails.markedCountries == ["RU"])

        #expect(throws: SandvaultError.self) { try SettingsModel.countryCodes("R1") }
        #expect(throws: SandvaultError.self) { try SettingsModel.countryCodes("ZZ") }
        #expect(try SettingsModel.countryCodes(" de;CH\nat ") == ["DE", "CH", "AT"])
    }

    @Test func savingWhileNetdIsDownSaysSo() async throws {
        let world = TestWorld()
        defer { world.cleanUp() }
        world.netd.running.set(false)
        let settings = world.model().settings
        await settings.setNetworkLookup(.off)
        #expect(try world.store.load().network.askDetails.network == .off)
        #expect(settings.message?.kind == .info)
        #expect(settings.message?.detail == "netd is not running; the change applies when it starts")
    }

    @Test func networkDatabaseDownloadAndFailure() async {
        let world = TestWorld()
        defer { world.cleanUp() }
        let settings = world.model().settings
        #expect(settings.networkDatabaseSummary == "Unknown")
        await settings.refreshNetworkDatabase()
        #expect(settings.networkDatabaseSummary == "Not installed")
        #expect(settings.networkDatabaseActionTitle == "Download")

        await settings.updateNetworkDatabase()
        #expect(world.networkDatabase.updates.get() == 1)
        #expect(!settings.isUpdatingDatabase)
        #expect(settings.networkDatabase?.installed == true)
        #expect(settings.networkDatabaseSummary == "Installed · \(Format.day(Date(timeIntervalSince1970: 1_800_000_000))) · 512,034 ranges")
        #expect(settings.networkDatabaseActionTitle == "Update")
        #expect(settings.message?.kind == .success)
        #expect(settings.message?.title == "Network database updated")
        #expect(settings.message?.detail == "512,034 address ranges")

        world.networkDatabase.failure.set(.commandFailed("curl", 6, "Could not resolve host: iptoasn.com"))
        await settings.updateNetworkDatabase()
        #expect(settings.message?.kind == .error)
        #expect(settings.message?.title == "Update the network database failed")
        #expect(settings.networkDatabase?.installed == true)

        world.networkDatabase.failure.set(.notImplemented("network database download"))
        await settings.updateNetworkDatabase()
        #expect(settings.message?.kind == .notAvailable)
    }
}
