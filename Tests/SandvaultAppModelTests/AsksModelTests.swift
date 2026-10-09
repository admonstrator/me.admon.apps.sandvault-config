import Foundation
import SandvaultCore
import Testing
@testable import SandvaultAppModel

@MainActor
@Suite struct AsksModelTests {
    @Test func countdownToExpiry() {
        let world = TestWorld()
        defer { world.cleanUp() }
        let model = world.model()
        let start = world.clock.current.get()
        let ask = AskRequest(host: "api.example.com", port: 443, kind: .transparentTLS, pid: 42, process: "node", createdAt: start, expiresAt: start.addingTimeInterval(30))

        #expect(model.asks.remainingSeconds(ask, at: start) == 30)
        #expect(model.asks.remainingSeconds(ask, at: start.addingTimeInterval(12.3)) == 18)
        #expect(model.asks.remainingSeconds(ask, at: start.addingTimeInterval(45)) == 0)
        #expect(model.asks.fractionRemaining(ask, at: start.addingTimeInterval(15)) == 0.5)
        #expect(model.asks.fractionRemaining(ask, at: start.addingTimeInterval(99)) == 0)
        #expect(Format.countdown(model.asks.remainingSeconds(ask, at: start.addingTimeInterval(12.3))) == "0:18")
        #expect(model.asks.detail(for: ask) == "node (42) · port 443 · tls")
    }

    @Test func answerSendsDecisionAndScopeThroughNetd() async throws {
        let world = TestWorld()
        defer { world.cleanUp() }
        let now = world.clock.current.get()
        let first = AskRequest(host: "cdn.jsdelivr.net", port: 443, kind: .transparentTLS, createdAt: now, expiresAt: now.addingTimeInterval(30))
        let second = AskRequest(host: "registry.npmjs.org", port: nil, kind: .dns, createdAt: now.addingTimeInterval(1), expiresAt: now.addingTimeInterval(31))
        let client = FakeNetdClient(pending: [second, first])
        world.netd.queue.set([.client(client)])
        let model = world.model()
        model.netd.start()
        defer { model.netd.stop() }
        #expect(await eventually { model.asks.pending.count == 2 })
        #expect(model.asks.isListening)
        #expect(model.asks.pending.map(\.host) == ["cdn.jsdelivr.net", "registry.npmjs.org"])
        #expect(model.asks.detail(for: second) == "DNS lookup · dns")

        model.asks.setScope(.domain, for: first)
        #expect(model.asks.rulePattern(for: first, scope: model.asks.scope(for: first)) == "*.jsdelivr.net")
        await model.asks.answer(first, .allowAlways)
        #expect(client.answers.get() == [AskAnswer(id: first.id, decision: .allowAlways, scope: .domain)])
        #expect(model.asks.message?.title == "Allow always: cdn.jsdelivr.net (rule *.jsdelivr.net)")
        #expect(model.asks.pending.map(\.host) == ["registry.npmjs.org"])

        await model.asks.answer(second, .denyOnce)
        #expect(client.answers.get().last == AskAnswer(id: second.id, decision: .denyOnce, scope: .host))
        #expect(model.asks.pending.isEmpty)
        #expect(model.menuBar.pendingAsks == 0)
    }

    @Test func answeringWhileNetdIsDownIsAnError() async {
        let world = TestWorld()
        defer { world.cleanUp() }
        let model = world.model()
        let now = world.clock.current.get()
        let ask = AskRequest(host: "x.example", port: 443, kind: .transparentTLS, createdAt: now, expiresAt: now.addingTimeInterval(30))
        await model.asks.answer(ask, .allowOnce)
        #expect(model.asks.message?.kind == .warning)
        #expect(model.asks.message?.suggestedCommand == "svctl netd install")
    }
}
