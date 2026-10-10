import Foundation
import SandvaultCore
import Testing
@testable import SandvaultAppModel

@MainActor
@Suite struct RecordingModelTests {
    @Test func switchesAreSavedAndWebOnesReloadNetd() async throws {
        let world = TestWorld()
        defer { world.cleanUp() }
        let model = world.model()
        let recording = model.recording
        #expect(recording.web.requests && !recording.web.contents)

        await recording.setKeepContents(true)
        await recording.setRecordRequests(false)
        var saved = try world.store.load()
        #expect(saved.network.recording.contents && !saved.network.recording.requests)
        #expect(world.netd.reloads.get() == 2)

        await recording.setHideSystemFiles(false)
        await recording.setOpenAndClose(true)
        saved = try world.store.load()
        #expect(!saved.activity.hideSystemFiles && saved.activity.openAndClose)
        #expect(world.netd.reloads.get() == 2)

        await recording.setRetention(30)
        saved = try world.store.load()
        #expect(saved.network.recording.retentionDays == 30 && saved.activity.retentionDays == 30)
        #expect(recording.retentionDays == 30)
        #expect(RecordingModel.retentionTitle(1) == "1 day")

        await recording.setInspection(true)
        #expect(try world.store.load().network.inspection.enabled)
        #expect(world.ca.synced.get() == [true])
        #expect(recording.message?.title == "Inspection on")

        await recording.setRecordActivity(true)
        #expect(try world.store.load().activity.enabled)
        #expect(model.files.isRecording)
        await recording.setRecordActivity(false)
        #expect(try !world.store.load().activity.enabled)
    }

    @Test func spaceUsedAndClear() async throws {
        let world = TestWorld()
        defer { world.cleanUp() }
        let client = FakeNetdClient()
        client.storedBytes.set(38_000_000)
        client.stored.set([UUID(): (StoredContent(contentType: nil, size: 1, storedBytes: 1, binary: false), Data([1]))])
        world.netd.queue.set([.client(client)])
        world.activity.bytes.set(12_000_000)
        world.activity.storedEvents.set([FileActivitySummaryTests.event(.create, "/tmp/a")])
        let model = world.model()
        model.netd.start()
        defer { model.netd.stop() }
        #expect(await eventually { model.netd.isConnected })
        await model.files.launch()
        #expect(model.files.events.count == 1)

        let recording = model.recording
        await recording.refreshStorage()
        #expect(recording.spaceText == "Web 38.0 MB · Files 12.0 MB")

        recording.confirmingClear = true
        await recording.clear()
        #expect(!recording.confirmingClear)
        #expect(client.clears.get() == 1 && world.activity.clears.get() == 1)
        #expect(model.files.events.isEmpty)
        #expect(recording.spaceText == "Web 0 B · Files 0 B")
        #expect(recording.message?.kind == .success)
    }

    @Test func clearWithoutNetdStillClearsFilesAndSaysWhatFailed() async throws {
        let world = TestWorld()
        defer { world.cleanUp() }
        let recording = world.model().recording
        #expect(recording.spaceText == "Web unknown, netd is not running · Files 0 B")
        await recording.clear()
        #expect(world.activity.clears.get() == 1)
        #expect(recording.message?.kind == .warning)
        #expect(recording.message?.detail == "Web contents: sandvault-netd is not running.")
    }
}
