import Foundation
import SandvaultCore
import SandvaultNet
import Testing
@testable import SandvaultAppModel

@MainActor
@Suite struct ConfigEditorTests {
    @Test func editKeepsChangesOtherProcessesSavedInBetween() async throws {
        let world = TestWorld()
        defer { world.cleanUp() }
        let editor = ConfigEditor(store: world.store, netd: world.netd)
        editor.reload()

        // svctl (another process) adds a domain rule after the app read the file.
        var external = try world.store.load()
        try external.network.upsertDomainRule(pattern: "github.com", action: .allow)
        try world.store.save(external)

        try await editor.edit { $0.sandbox.preset = .hardened }

        let saved = try world.store.load()
        #expect(saved.sandbox.preset == .hardened)
        #expect(saved.network.domainRules.map(\.pattern) == ["github.com"])
        #expect(editor.config == saved)
    }

    @Test func reloadIsSentOnlyWhenRequestedAndReportsAMissingNetd() async throws {
        let world = TestWorld()
        defer { world.cleanUp() }
        let editor = ConfigEditor(store: world.store, netd: world.netd)

        let network = try await editor.edit { $0.network.blockLAN = false }
        #expect(network.netdReloaded == true)
        #expect(world.netd.reloads.get() == 1)
        #expect(world.netd.clients.get().allSatisfy { $0.closed.get() })

        let sandbox = try await editor.edit(reloadNetd: false) { $0.sandbox.autoReapply = true }
        #expect(sandbox.netdReloaded == nil)
        #expect(world.netd.reloads.get() == 1)

        world.netd.running.set(false)
        let offline = try await editor.edit { $0.network.blockLAN = true }
        #expect(offline.netdReloaded == false)
        #expect(netdReloadNote(offline.netdReloaded) == "netd is not running; the change applies when it starts")
    }

    @Test func aDamagedFileIsNeverOverwritten() async throws {
        let world = TestWorld()
        defer { world.cleanUp() }
        try Data("{ not json".utf8).write(to: world.store.url)
        let editor = ConfigEditor(store: world.store, netd: world.netd)
        editor.reload()
        #expect(editor.loadError != nil)

        var failed = false
        do {
            try await editor.edit { $0.network.mode = .open }
        } catch {
            failed = true
        }
        #expect(failed)
        #expect(try String(contentsOf: world.store.url, encoding: .utf8) == "{ not json")
    }

    @Test func reloadIfChangedPicksUpExternalEdits() async throws {
        let world = TestWorld()
        defer { world.cleanUp() }
        let editor = ConfigEditor(store: world.store, netd: world.netd)
        try await editor.edit { $0.network.mode = .open }

        var external = try world.store.load()
        external.network.mode = .proxyOnly
        try world.store.save(external)
        // Make the change visible even on file systems with coarse timestamps.
        try FileManager.default.setAttributes([.modificationDate: Date().addingTimeInterval(5)], ofItemAtPath: world.store.url.path)

        editor.reloadIfChanged()
        #expect(editor.config.network.mode == .proxyOnly)
    }
}
