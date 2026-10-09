#if !os(macOS)
import Foundation
import SandvaultCore
import Testing
@testable import SandvaultAppModel

/// The real composition root off macOS: everything that needs the Mac fails with a message, nothing crashes or hangs.
/// Linux only, so CI on macOS never reaches osascript, launchctl or sudo.
@MainActor
@Suite struct LiveEnvironmentTests {
    @Test func liveServicesFailCleanlyOffMacOS() async throws {
        let home = FileManager.default.temporaryDirectory.appendingPathComponent("appmodel-live-\(UUID().uuidString)")
        defer { try? FileManager.default.removeItem(at: home) }
        let environment = SandvaultEnvironment(hostUser: "alice", hostHome: home.path)
        let model = AppModel(environment: .live(
            environment: environment, bundled: BundledTools(helper: "/nonexistent/svctl-helper", netd: "/nonexistent/sandvault-netd"),
            preferences: MemoryPreferences()
        ))

        await model.settings.installHelper()
        #expect(model.settings.message?.kind == .warning)
        #expect(model.settings.message?.title == "Install the helper is not supported here")

        await model.settings.installNetd()
        #expect(model.settings.message?.title == "Install netd is not supported here")

        await model.firewall.turnOff()
        #expect(model.firewall.message?.title == "Turn the firewall off is not supported here")
        #expect(try ConfigStore(path: AppPaths(environment: environment).configFile).load().network.mode == .off)

        await model.rules.apply()
        #expect(model.rules.message?.kind == .warning)
        model.rules.refreshPlan()
        #expect(model.rules.plan?.drift == .profileMissing)

        // No netd: the link waits and says why.
        model.netd.start()
        defer { model.netd.stop() }
        #expect(await eventually {
            if case .waiting = model.netd.state { return true } else { return false }
        })
        #expect(model.netd.summary.contains("sandvault-netd is not running"))

        // Whatever the workflow factories return here (a stub or the real service), the check finishes.
        await model.handoff.select(home.path)
        #expect(!model.handoff.isChecking)
        #expect(!model.handoff.canHandOff)
    }
}
#endif
