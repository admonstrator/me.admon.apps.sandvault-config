import Foundation
import SandvaultCore
import Testing
@testable import SandvaultNet

@Suite(.timeLimit(.minutes(1))) struct EnrichmentTests {
    struct FakeReverse: ReverseResolving {
        var delay: Double = 0
        var name: String?
        var fails = false
        func reverseName(of address: String) async throws -> String? {
            if delay > 0 { try await Task.sleep(nanoseconds: UInt64(delay * 1_000_000_000)) }
            if fails { throw SandvaultError.timedOut("PTR") }
            return name
        }
    }

    struct FakeNetworks: NetworkLooking {
        var delay: Double = 0
        var network: AskNetwork?
        func network(for address: String, mode: NetworkLookupMode) async -> AskNetwork? {
            if delay > 0 { try? await Task.sleep(nanoseconds: UInt64(delay * 1_000_000_000)) }
            return network
        }
    }

    /// Ignores cancellation, like a process that keeps running.
    struct StubbornPrograms: ProgramInspecting {
        var delay: Double
        var program: AskProgram?
        func program(pid: Int32) async -> AskProgram? {
            let until = Date().addingTimeInterval(delay)
            while Date() < until { try? await Task.sleep(nanoseconds: 20_000_000) }
            return program
        }
    }

    static let vps = AskNetwork(asn: 48282, owner: "VDSINA-AS", country: "RU", kind: .hosting, source: .offline)
    static let python = AskProgram(path: "/tmp/build-x/.venv/bin/python3", signature: .unsigned, inTemporaryFolder: true)

    func enricher(
        reverse: ReverseResolving = FakeReverse(name: nil), networks: NetworkLooking = FakeNetworks(network: vps),
        programs: ProgramInspecting = StubbornPrograms(delay: 0, program: python), names: DNSNameCache = DNSNameCache(),
        history: ConnectionHistoryIndex = ConnectionHistoryIndex()
    ) -> LiveAskEnricher {
        LiveAskEnricher(names: names, reverse: reverse, networks: networks, programs: programs, history: history)
    }

    static let oddInput = AskEnrichmentInput(
        host: "185.142.236.41", port: 8947, kind: .transparentTLS, owner: ProcessOwner(pid: 4242, name: "python3"),
        hint: ConnectionHint(address: "185.142.236.41", encryption: .unknown)
    )

    @Test func allPartsTogetherGiveTheMockupsSuspiciousRequest() async throws {
        let settings = AskDetailSettings(markedCountries: ["RU"])
        let details = try #require(await enricher().details(for: Self.oddInput, settings: settings))
        #expect(details.address == "185.142.236.41")
        #expect(details.name == AskName(name: nil, source: .none))
        #expect(details.reverseName == AskDetails.noReverseName)
        #expect(details.service == KnownService(port: 8947, name: nil))
        #expect(details.network == Self.vps)
        #expect(details.encryption == .unknown)
        #expect(details.history == AskHistory(allowed: 0, denied: 0, lastSeen: nil))
        #expect(details.program == Self.python)
        #expect(details.assessment?.level == .suspicious)
        #expect(details.assessment?.score == 9)  // the mockup's 8 plus the missing PTR name
    }

    @Test func slowPartsAreLeftOutWithinTheBudget() async throws {
        var settings = AskDetailSettings()
        settings.budgetSeconds = 0.4
        let slow = enricher(
            reverse: FakeReverse(delay: 5, name: "late.example"), networks: FakeNetworks(delay: 5, network: Self.vps),
            programs: StubbornPrograms(delay: 3, program: Self.python)
        )
        let started = Date()
        let details = try #require(await slow.details(for: Self.oddInput, settings: settings))
        let elapsed = Date().timeIntervalSince(started)
        // 80 % of the budget, plus scheduling slack when the suite runs in parallel.
        #expect(elapsed >= 0.3)
        #expect(elapsed < 1)
        #expect(details.reverseName == nil)
        #expect(details.network == nil)
        #expect(details.program == nil)
        #expect(details.service == KnownService(port: 8947, name: nil))
        #expect(details.assessment != nil)
    }

    @Test func theDeadlineLeavesTheCoordinatorAMargin() {
        let live = enricher()
        #expect(abs(live.deadline(1.5) - 1.2) < 0.001)
        #expect(abs(live.deadline(0.4) - 0.3) < 0.001)
        #expect(live.deadline(0) == 0.05)
    }

    @Test func fastPartsReturnWithoutWaitingForTheDeadline() async throws {
        var settings = AskDetailSettings()
        settings.budgetSeconds = 5
        let started = Date()
        let details = try #require(await enricher().details(for: Self.oddInput, settings: settings))
        #expect(Date().timeIntervalSince(started) < 1)
        #expect(details.program == Self.python)
    }

    @Test func theCoordinatorGetsTheDetailsInsideItsBudget() async throws {
        let hub = ControlHub()
        let client = UUID()
        hub.add(client) { _ in }
        hub.subscribe(client, topics: [.asks])
        let slow = enricher(reverse: FakeReverse(delay: 5, name: nil), programs: StubbornPrograms(delay: 3, program: nil))
        let asks = AskCoordinator(hub: hub, persist: { DomainRule(pattern: $0, action: $2, port: $1) }, log: { _ in }, enricher: slow)
        var policy = NetworkPolicy()
        // The enricher stops its parts at 80 % of the budget; 3 s leaves 0.6 s for its answer to reach the
        // coordinator while the whole suite runs in parallel (1 s left 0.2 s and failed on a busy macOS runner).
        policy.askDetails.budgetSeconds = 3
        async let result = asks.decide(
            host: "185.142.236.41", port: 8947, kind: .transparentTLS, owner: ProcessOwner(pid: 1, name: "python3"), policy: policy,
            hint: Self.oddInput.hint
        )
        var request: AskRequest?
        for _ in 0..<1000 where request == nil {
            request = await asks.pendingRequests().first
            if request == nil { try await Task.sleep(nanoseconds: 5_000_000) }
        }
        let ask = try #require(request)
        #expect(ask.details != nil)
        #expect(ask.details?.network == Self.vps)
        #expect(ask.details?.reverseName == nil)
        try await asks.answer(AskAnswer(id: ask.id, decision: .denyOnce))
        #expect(await result.decision == .askedDenied)
    }

    @Test func turnedOffLookupsDoNotRun() async throws {
        let settings = AskDetailSettings(
            name: false, reverseDNS: false, port: false, network: .off, program: false, history: false, assessment: false
        )
        let failing = enricher(
            reverse: FakeReverse(delay: 5, name: "x"), networks: FakeNetworks(delay: 5, network: Self.vps),
            programs: StubbornPrograms(delay: 5, program: Self.python)
        )
        let started = Date()
        let details = try #require(await failing.details(for: Self.oddInput, settings: settings))
        #expect(Date().timeIntervalSince(started) < 0.5)
        #expect(details == AskDetails(address: "185.142.236.41", encryption: .unknown))
    }

    @Test func aFailedReverseLookupIsNotAMissingName() async throws {
        let details = try #require(await enricher(reverse: FakeReverse(fails: true)).details(for: Self.oddInput, settings: AskDetailSettings()))
        #expect(details.reverseName == nil)
        let found = try #require(await enricher(reverse: FakeReverse(name: "vps-41.example-host.ru")).details(
            for: Self.oddInput, settings: AskDetailSettings()
        ))
        #expect(found.reverseName == "vps-41.example-host.ru")
    }

    @Test func namesComeFromHintsHostsAndRecentDNSAnswers() {
        let names = DNSNameCache()
        names.record(name: "registry.npmjs.org", addresses: ["104.16.27.35"])
        let live = enricher(names: names)
        func name(_ host: String, _ kind: ConnectionKind, _ hint: ConnectionHint = ConnectionHint()) -> AskName {
            live.name(for: AskEnrichmentInput(host: host, port: 443, kind: kind, owner: nil, hint: hint))
        }
        #expect(name("registry.npmjs.org", .dns) == AskName(name: "registry.npmjs.org", source: .dns))
        #expect(name("104.16.27.35", .transparentTLS, ConnectionHint(serverName: "registry.npmjs.org", nameSource: .tls))
            == AskName(name: "registry.npmjs.org", source: .tls))
        #expect(name("example.com", .explicitProxy) == AskName(name: "example.com", source: .http))
        #expect(name("example.com", .transparentTLS) == AskName(name: "example.com", source: .tls))
        #expect(name("104.16.27.35", .transparentTLS) == AskName(name: "registry.npmjs.org", source: .dns))
        #expect(name("185.142.236.41", .transparentTLS) == AskName(name: nil, source: .none))
    }

    @Test func dnsAsksAreAboutTheQueriedName() async throws {
        let history = ConnectionHistoryIndex()
        history.add(ConnectionRecord(kind: .dns, host: "registry.npmjs.org", decision: .allowed))
        let input = AskEnrichmentInput(host: "registry.npmjs.org", port: nil, kind: .dns, owner: nil, hint: ConnectionHint())
        let details = try #require(await enricher(history: history).details(for: input, settings: AskDetailSettings()))
        #expect(details.name == AskName(name: "registry.npmjs.org", source: .dns))
        #expect(details.service == KnownService(port: 53, name: "DNS"))
        #expect(details.encryption == .plain)
        #expect(details.history?.allowed == 1)
        #expect(details.address == nil)
        #expect(details.network == nil)
        #expect(details.assessment?.level == .normal)
    }

    @Test func aNameHostGetsItsAddressFromRecentDNSAnswers() async throws {
        let names = DNSNameCache()
        names.record(name: "registry.npmjs.org", addresses: ["104.16.27.35"])
        let input = AskEnrichmentInput(host: "registry.npmjs.org", port: 443, kind: .explicitProxy, owner: nil, hint: ConnectionHint())
        let details = try #require(await enricher(names: names).details(for: input, settings: AskDetailSettings()))
        #expect(details.address == "104.16.27.35")
    }

    @Test func netdFeedsTheNameCacheTheHistoryAndReverseLookups() async throws {
        let resolver = try await FakeResolver.start()
        let netd = try await TestNetd.start(AppConfig.testing([("*.allowed.test", .allow)]), upstreamDNS: resolver.address)
        try await withCleanup({ await resolver.stop(); await netd.stop() }) {
            let answer = try await DNSClient.query(port: Int(netd.ports.dns), name: "www.allowed.test")
            #expect(answer.answerAddresses == ["192.0.2.10"])
            let enricher = netd.daemon.enricher
            #expect(enricher.names.name(for: "192.0.2.10") == "www.allowed.test")
            _ = try await netd.record { $0.host == "www.allowed.test" }
            #expect(enricher.history.history(host: "www.allowed.test", port: nil).allowed == 1)
            // The fake upstream has no PTR records: an answer without a name, not an error.
            let reverse = try #require(enricher.reverse as? UpstreamReverseResolver)
            #expect(try await reverse.reverseName(of: "192.0.2.10") == nil)
            #expect(resolver.queries.all.contains("10.2.0.192.in-addr.arpa"))
        }
    }
}
