import Foundation
import SandvaultCore
import Testing
@testable import SandvaultAppModel

@MainActor
@Suite struct SandboxModelTests {
    @Test func sessionsStartInTheSharedWorkspaceWithTheHandoffTerminalAndOptions() async throws {
        let world = TestWorld()
        defer { world.cleanUp() }
        try world.store.save(AppConfig(handoff: HandoffSettings(terminal: .ghostty, svOptions: ["--browser"])))
        let model = world.model()
        await model.sandbox.refresh()

        await model.sandbox.open(.claude)
        model.sandbox.startDirectory = "/Users/Shared/sv-alice/repos/app"
        await model.sandbox.open(.shell)

        let runs = world.sandbox.runs.get()
        #expect(runs.map(\.command) == [
            .open(.claude, directory: "/Users/Shared/sv-alice"), .open(.shell, directory: "/Users/Shared/sv-alice/repos/app"),
        ])
        #expect(runs.allSatisfy { $0.terminal == .ghostty && $0.svOptions == ["--browser"] && $0.followUp.isEmpty })
        #expect(model.sandbox.message?.title == "Shell opens in Ghostty")
    }

    @Test func createSavesThePresetAndAppliesItAfterTheBuild() async throws {
        let world = TestWorld()
        defer { world.cleanUp() }
        world.helperSetup.installed.set(true)
        world.sandbox.current.set(SandboxState(installed: false, profile: false, home: false, workspace: false))
        let model = world.model()
        await model.sandbox.refresh()
        #expect(model.sandbox.summary == "No sandbox yet")

        model.sandbox.setup = .careful
        await model.sandbox.create()

        let config = try world.store.load()
        #expect(config.sandbox.preset == .hardened)
        #expect(config.network.mode == .proxyOnly && config.network.defaultAction == .ask)
        let svctl = "/Applications/Sandvault Config.app/Contents/MacOS/svctl"
        let run = try #require(world.sandbox.runs.get().last)
        #expect(run.command == .build)
        #expect(run.followUp == [[svctl, "rules", "apply", "--yes"], [svctl, "firewall", "apply", "--yes"]])
    }

    @Test func withoutTheHelperOnlySvRunsAndUnrestrictedNeedsNoApply() async throws {
        let world = TestWorld()
        defer { world.cleanUp() }
        let model = world.model()
        model.sandbox.setup = .careful
        await model.sandbox.create()
        #expect(world.sandbox.runs.get().last?.followUp == [])

        world.helperSetup.installed.set(true)
        model.sandbox.setup = .unrestricted
        await model.sandbox.create()
        #expect(world.sandbox.runs.get().last?.followUp == [])
        #expect(try world.store.load().network.mode == .off)
    }

    @Test func rebuildAndDeleteRunSvAndReportFailures() async throws {
        let world = TestWorld()
        defer { world.cleanUp() }
        let model = world.model()
        await model.sandbox.rebuild()
        await model.sandbox.delete()
        #expect(world.sandbox.runs.get().map(\.command) == [.rebuild, .uninstall])
        #expect(model.sandbox.deleteExplanation.contains("/Users/Shared/sv-alice/user"))

        world.sandbox.failure.set(SandvaultError.io("osascript: not authorized to send Apple events to Terminal"))
        await model.sandbox.delete()
        #expect(model.sandbox.message?.kind == .error)
    }

    @Test func incompleteSandboxesSayHowToRepair() async {
        let world = TestWorld()
        defer { world.cleanUp() }
        world.sandbox.current.set(SandboxState(installed: false, profile: true, home: true, workspace: true))
        let model = world.model()
        await model.sandbox.refresh()
        #expect(model.sandbox.summary.hasPrefix("Incomplete"))
        #expect(!model.sandbox.installed)
    }

    @Test func dockPreferenceIsSavedAndDefaultsOn() throws {
        let world = TestWorld()
        defer { world.cleanUp() }
        let model = world.model()
        #expect(model.settings.preferences.showInDock)
        model.setShowInDock(false)
        #expect(!world.preferences.stored.get().showInDock)
        let older = try JSONDecoder().decode(AppPreferences.self, from: Data(#"{"refreshInterval":3,"expertMode":true}"#.utf8))
        #expect(older.showInDock)
    }
}
