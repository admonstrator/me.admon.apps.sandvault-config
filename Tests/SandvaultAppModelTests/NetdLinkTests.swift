import Foundation
import SandvaultCore
import Testing
@testable import SandvaultAppModel

@MainActor
@Suite struct NetdLinkTests {
    @Test func backoffDoublesUpToTheMaximumAndResets() {
        var backoff = Backoff()
        #expect((0..<7).map { _ in backoff.next() } == [0.5, 1, 2, 4, 8, 15, 15])
        backoff.reset()
        #expect(backoff.next() == 0.5)
    }

    @Test func reconnectsWithBackoffAndSubscribesAgainAfterANetdRestart() async throws {
        let world = TestWorld()
        defer { world.cleanUp() }
        let first = FakeNetdClient()
        let second = FakeNetdClient()
        world.netd.queue.set([.refuse, .refuse, .client(first), .client(second)])
        let link = NetdLink(connector: world.netd, clock: world.clock.clock)

        link.start()
        #expect(await eventually { link.connectCount == 1 })
        #expect(link.isConnected)
        #expect(first.subscriptions.get() == [NetdLink.topics])
        #expect(Set(NetdLink.topics) == Set(ControlTopic.allCases))

        // netd restarts: its connection closes; the link waits, reconnects and subscribes again.
        first.close()
        #expect(await eventually { link.connectCount == 2 })
        #expect(second.subscriptions.get() == [NetdLink.topics])
        #expect(world.clock.sleeps.get() == [0.5, 1, 0.5])
        #expect(world.netd.connects.get() == 4)

        link.stop()
        #expect(link.state == .stopped)
        #expect(second.closed.get())
    }

    @Test func eventsUpdateStatusRecordsAndAsks() async throws {
        let world = TestWorld()
        defer { world.cleanUp() }
        let now = world.clock.current.get()
        let earlier = record("old.example", .allowed, at: now.addingTimeInterval(-60))
        let pendingAsk = AskRequest(host: "pending.example", port: 443, kind: .transparentTLS, createdAt: now, expiresAt: now.addingTimeInterval(30))
        let client = FakeNetdClient(pending: [pendingAsk], recent: [earlier])
        world.netd.queue.set([.client(client)])
        let link = NetdLink(connector: world.netd, clock: world.clock.clock)
        link.start()
        defer { link.stop() }
        #expect(await eventually { link.isConnected })
        #expect(link.records == [earlier])
        #expect(link.pendingAsks == [pendingAsk])
        #expect(link.status?.mode == .proxyOnly)

        let ask = AskRequest(host: "new.example", port: 443, kind: .transparentTLS, createdAt: now, expiresAt: now.addingTimeInterval(30))
        let fresh = record("new.example", .denied, at: now)
        client.push(.ask(ask))
        client.push(.connection(fresh))
        client.push(.askResolved(id: pendingAsk.id, decision: .timedOut))
        #expect(await eventually { link.records.count == 2 && link.pendingAsks == [ask] })

        try await link.answer(AskAnswer(id: ask.id, decision: .allowOnce))
        #expect(client.answers.get() == [AskAnswer(id: ask.id, decision: .allowOnce)])
        #expect(link.pendingAsks.isEmpty)
    }

    @Test func aRestartedNetdForgetsItsAsks() async throws {
        let world = TestWorld()
        defer { world.cleanUp() }
        let now = world.clock.current.get()
        let ask = AskRequest(host: "a.example", port: 443, kind: .transparentTLS, createdAt: now, expiresAt: now.addingTimeInterval(30))
        let client = FakeNetdClient(pending: [ask])
        world.netd.queue.set([.client(client)])
        world.netd.running.set(false)
        let link = NetdLink(connector: world.netd, clock: world.clock.clock)
        link.start()
        defer { link.stop() }
        #expect(await eventually { link.pendingAsks == [ask] })

        client.close()
        #expect(await eventually {
            if case .waiting = link.state { return true } else { return false }
        })
        #expect(link.pendingAsks.isEmpty)
        #expect(link.status == nil)
    }

    @Test func recordsAreCapped() {
        let world = TestWorld()
        defer { world.cleanUp() }
        let link = NetdLink(connector: world.netd, clock: world.clock.clock)
        let now = Date()
        for index in 0..<(NetdLink.recordLimit + 5) {
            link.handle(.connection(record("h\(index).example", .allowed, at: now)))
        }
        #expect(link.records.count == NetdLink.recordLimit)
        #expect(link.records.first?.host == "h5.example")
    }

    @Test func answeringWithoutNetdFails() async {
        let world = TestWorld()
        defer { world.cleanUp() }
        let link = NetdLink(connector: world.netd, clock: world.clock.clock)
        await #expect(throws: SandvaultError.self) { try await link.answer(AskAnswer(id: UUID(), decision: .denyOnce)) }
    }
}
