import Foundation
import SandvaultCore
import Testing
@testable import SandvaultNet

@Suite(.timeLimit(.minutes(1))) struct AskEnrichmentTests {
    struct FixedEnricher: AskEnriching {
        var delay: Double = 0
        func details(for input: AskEnrichmentInput, settings: AskDetailSettings) async -> AskDetails? {
            if delay > 0 { try? await Task.sleep(nanoseconds: UInt64(delay * 1_000_000_000)) }
            return AskDetails(address: input.hint.address, service: KnownService(port: input.port ?? 0, name: "Test"))
        }
    }

    func coordinator(_ enricher: AskEnriching) -> AskCoordinator {
        let hub = ControlHub()
        let id = UUID()
        hub.add(id) { _ in }
        hub.subscribe(id, topics: [.asks])
        return AskCoordinator(hub: hub, persist: { pattern, action in DomainRule(pattern: pattern, action: action) }, log: { _ in }, enricher: enricher)
    }

    func firstPending(_ asks: AskCoordinator) async throws -> AskRequest? {
        for _ in 0..<400 {
            if let request = await asks.pendingRequests().first { return request }
            try await Task.sleep(nanoseconds: 5_000_000)
        }
        return nil
    }

    @Test func publishedAsksCarryTheEnrichersDetails() async throws {
        let asks = coordinator(FixedEnricher())
        let hint = ConnectionHint(address: "185.142.236.41", encryption: .unknown)
        async let result = asks.decide(host: "185.142.236.41", port: 8947, kind: .transparentTLS, owner: nil, policy: NetworkPolicy(), hint: hint)
        let request = try #require(try await firstPending(asks))
        #expect(request.details?.address == "185.142.236.41")
        #expect(request.details?.service == KnownService(port: 8947, name: "Test"))
        try await asks.answer(AskAnswer(id: request.id, decision: .denyOnce))
        #expect(await result.decision == .askedDenied)
    }

    @Test func aSlowEnricherDoesNotHoldTheAskBack() async throws {
        var policy = NetworkPolicy()
        policy.askDetails.budgetSeconds = 0.2
        let asks = coordinator(FixedEnricher(delay: 5))
        let started = Date()
        async let result = asks.decide(host: "slow.test", port: 443, kind: .explicitProxy, owner: nil, policy: policy)
        let request = try #require(try await firstPending(asks))
        #expect(request.details == nil)
        #expect(Date().timeIntervalSince(started) < 2)
        try await asks.answer(AskAnswer(id: request.id, decision: .allowOnce))
        #expect(await result.allowed)
    }
}
