import Foundation
import SandvaultCore
import Testing
@testable import SandvaultNet

@Suite struct PortRuleTests {
    static func engine(
        _ rules: [DomainRule], mode: FirewallMode = .proxyOnly, routeAllTCP: Bool = true, default action: DomainAction = .ask
    ) -> PolicyEngine {
        PolicyEngine(policy: NetworkPolicy(mode: mode, defaultAction: action, domainRules: rules, routeAllTCP: routeAllTCP))
    }

    static func rule(_ pattern: String, _ action: DomainAction, port: UInt16? = nil) -> DomainRule {
        DomainRule(pattern: pattern, action: action, port: port)
    }

    struct Case: CustomStringConvertible, Sendable {
        var rules: [DomainRule]
        var host: String
        var port: UInt16?
        var action: DomainAction
        /// `displayPattern` of the deciding rule.
        var decidedBy: String?
        var routeAllTCP = true
        var description: String { "\(host):\(port.map(String.init) ?? "dns") route-all \(routeAllTCP) -> \(action)" }
    }

    static let ip = "185.142.236.41"
    static let cases: [Case] = [
        // Route-all TCP: other ports follow the rules and the default action like web ports, so `ask` applies.
        Case(rules: [], host: ip, port: 8947, action: .ask, decidedBy: nil),
        Case(rules: [rule(ip, .ask)], host: ip, port: 8947, action: .ask, decidedBy: ip),
        Case(rules: [rule(ip, .deny)], host: ip, port: 22, action: .deny, decidedBy: ip),
        Case(rules: [rule(ip, .allow)], host: ip, port: 8947, action: .allow, decidedBy: ip),
        // A port rule matches only its port.
        Case(rules: [rule(ip, .allow, port: 22)], host: ip, port: 22, action: .allow, decidedBy: "\(ip):22"),
        Case(rules: [rule(ip, .allow, port: 22)], host: ip, port: 8947, action: .ask, decidedBy: nil),
        Case(rules: [rule("example.com", .deny, port: 443)], host: "example.com", port: 80, action: .ask, decidedBy: nil),
        // At equal specificity a port rule beats a portless one, whatever the actions.
        Case(rules: [rule(ip, .deny), rule(ip, .allow, port: 22)], host: ip, port: 22, action: .allow, decidedBy: "\(ip):22"),
        Case(rules: [rule(ip, .deny), rule(ip, .allow, port: 22)], host: ip, port: 23, action: .deny, decidedBy: ip),
        Case(
            rules: [rule("example.com", .allow), rule("example.com", .deny, port: 443)], host: "example.com", port: 443,
            action: .deny, decidedBy: "example.com:443"
        ),
        Case(rules: [rule("*", .allow), rule("*", .ask, port: 25)], host: "mail.test", port: 25, action: .ask, decidedBy: "*:25"),
        // Specificity of the pattern still comes first.
        Case(
            rules: [rule("*.example.com", .allow, port: 22), rule("code.example.com", .deny)], host: "code.example.com", port: 22,
            action: .deny, decidedBy: "code.example.com"
        ),
        // Same pattern and port: deny beats allow.
        Case(rules: [rule(ip, .allow, port: 22), rule(ip, .deny, port: 22)], host: ip, port: 22, action: .deny, decidedBy: "\(ip):22"),
        // DNS has no port: port rules never decide it.
        Case(rules: [rule("example.com", .deny, port: 22)], host: "example.com", port: nil, action: .ask, decidedBy: nil),
        // Without route-all TCP: other ports need an explicit allow, as before.
        Case(rules: [], host: ip, port: 8947, action: .deny, decidedBy: nil, routeAllTCP: false),
        Case(rules: [rule(ip, .ask)], host: ip, port: 8947, action: .deny, decidedBy: ip, routeAllTCP: false),
        Case(rules: [rule(ip, .allow, port: 22)], host: ip, port: 22, action: .allow, decidedBy: "\(ip):22", routeAllTCP: false),
        Case(rules: [rule(ip, .allow, port: 22)], host: ip, port: 23, action: .deny, decidedBy: nil, routeAllTCP: false),
        Case(rules: [rule(ip, .allow)], host: ip, port: 23, action: .allow, decidedBy: ip, routeAllTCP: false),
    ]

    @Test(arguments: cases)
    func decides(_ testCase: Case) {
        let verdict = Self.engine(testCase.rules, routeAllTCP: testCase.routeAllTCP).evaluate(host: testCase.host, port: testCase.port)
        #expect(verdict.action == testCase.action, "\(verdict.reason)")
        #expect(verdict.rule?.displayPattern == testCase.decidedBy)
    }

    @Test func defaultActionCoversOtherPortsOnlyWithRouteAllTCP() {
        #expect(Self.engine([], default: .allow).evaluate(host: "a.test", port: 8080).action == .allow)
        #expect(Self.engine([], default: .deny).evaluate(host: "a.test", port: 8080).action == .deny)
        #expect(Self.engine([], routeAllTCP: false, default: .allow).evaluate(host: "a.test", port: 8080).action == .deny)
        // Outside proxy-only the flag changes nothing.
        #expect(Self.engine([], mode: .open, default: .allow).evaluate(host: "a.test", port: 8080).action == .deny)
        #expect(Self.engine([], mode: .off).evaluate(host: "a.test", port: 22).reason == "port 22 needs an explicit allow rule")
    }

    @Test func watchHonoursPortDenyRules() {
        let engine = Self.engine([Self.rule("tracker.example", .deny, port: 22)], mode: .watch)
        #expect(engine.evaluate(host: "tracker.example", port: 22).action == .deny)
        #expect(engine.evaluate(host: "tracker.example", port: 443).action == .allow)
    }

    @Test func reasonsNameThePort() {
        let engine = Self.engine([Self.rule(Self.ip, .deny, port: 8947), Self.rule("::1", .allow, port: 22)])
        #expect(engine.evaluate(host: Self.ip, port: 8947).reason == "rule \(Self.ip):8947 (deny)")
        #expect(engine.evaluate(host: "::1", port: 22).reason == "rule [::1]:22 (allow)")
    }
}

@Suite struct PortRuleEditsTests {
    @Test func upsertKeysByPatternAndPort() throws {
        var policy = NetworkPolicy()
        let any = try policy.upsertDomainRule(pattern: "Example.com", action: .allow)
        let ssh = try policy.upsertDomainRule(pattern: "example.com.", action: .deny, port: 22)
        #expect(any.id != ssh.id && policy.domainRules.count == 2)
        let again = try policy.upsertDomainRule(pattern: "example.com", action: .ask, port: 22)
        #expect(again.id == ssh.id && again.action == .ask && again.port == 22)
        #expect(policy.domainRules.first { $0.port == nil }?.action == .allow, "the portless rule is untouched")
        #expect(throws: SandvaultError.self) { try policy.upsertDomainRule(pattern: "example.com", action: .allow, port: 0) }
    }

    @Test func removeTellsPortRulesApart() throws {
        var policy = NetworkPolicy()
        let any = try policy.upsertDomainRule(pattern: "example.com", action: .allow)
        let ssh = try policy.upsertDomainRule(pattern: "example.com", action: .deny, port: 22)
        let v6 = try policy.upsertDomainRule(pattern: "2001:db8::1", action: .allow, port: 8080)
        #expect(try policy.removeDomainRule(selector: "EXAMPLE.com:22").id == ssh.id)
        #expect(throws: SandvaultError.self) { try policy.removeDomainRule(selector: "example.com:22") }
        #expect(try policy.removeDomainRule(selector: "[2001:db8::1]:8080").id == v6.id)
        #expect(try policy.removeDomainRule(selector: "example.com").id == any.id)
        #expect(policy.domainRules.isEmpty)

        _ = try policy.upsertDomainRule(pattern: "example.com", action: .deny, port: 22)
        #expect(throws: SandvaultError.self, "a bare pattern names the rule without a port") {
            try policy.removeDomainRule(selector: "example.com")
        }
    }

    @Test func displayPatternAndKey() throws {
        #expect(DomainRule(pattern: "*.example.com", action: .allow, port: 22).displayPattern == "*.example.com:22")
        #expect(DomainRule(pattern: "::1", action: .allow, port: 22).displayPattern == "[::1]:22")
        #expect(DomainRule(pattern: "example.com", action: .allow).displayPattern == "example.com")
        let wildcard = try #require(DomainRule.key("*.Example.com:22"))
        #expect(wildcard.pattern == "*.example.com" && wildcard.port == 22)
        let v6 = try #require(DomainRule.key("[::1]:8080"))
        #expect(v6.pattern == "::1" && v6.port == 8080)
        let bare = try #require(DomainRule.key("::1"))
        #expect(bare.pattern == "::1" && bare.port == nil)
        #expect(DomainRule.key("example.com:0") == nil && DomainRule.key("bad host:22") == nil)
    }

    @Test func persistRuleSavesThePort() throws {
        let layout = try TempLayout()
        defer { layout.cleanup() }
        let configStore = ConfigStore(paths: layout.paths)
        try configStore.save(AppConfig())
        let store = try PolicyStore(store: configStore)
        let rule = try store.persistRule(pattern: "185.142.236.41", port: 8947, action: .deny)
        #expect(rule.port == 8947 && rule.note == "added from an ask")
        #expect(try configStore.load().network.domainRules.map { [$0.displayPattern, $0.action.rawValue] } == [["185.142.236.41:8947", "deny"]])
        #expect(store.snapshot.engine.evaluate(host: "185.142.236.41", port: 8947).action == .deny)
    }
}

@Suite(.timeLimit(.minutes(1))) struct AskKeyTests {
    final class Saved: @unchecked Sendable {
        let lock = NSLock()
        var rules: [DomainRule] = []
    }

    func coordinator(_ saved: Saved) -> AskCoordinator {
        let hub = ControlHub()
        let id = UUID()
        hub.add(id) { _ in }
        hub.subscribe(id, topics: [.asks])
        return AskCoordinator(
            hub: hub,
            persist: { pattern, port, action in
                let rule = DomainRule(pattern: pattern, action: action, port: port)
                saved.lock.withLock { saved.rules.append(rule) }
                return rule
            },
            log: { _ in }
        )
    }

    func pending(_ asks: AskCoordinator, count: Int) async throws -> [AskRequest] {
        for _ in 0..<400 {
            let requests = await asks.pendingRequests()
            if requests.count >= count { return requests }
            try await Task.sleep(nanoseconds: 5_000_000)
        }
        return await asks.pendingRequests()
    }

    @Test func keysWebPortsByHostAndOtherPortsByHostAndPort() {
        #expect(AskKey(host: "a.test", port: 443) == AskKey(host: "a.test", port: 80))
        #expect(AskKey(host: "a.test", port: 443) == AskKey(host: "a.test", port: nil))
        #expect(AskKey(host: "a.test", port: 8947) != AskKey(host: "a.test", port: 22))
        #expect(AskKey(host: "a.test", port: 22) != AskKey(host: "a.test", port: nil))
    }

    @Test func twoPortsOnOneAddressAreTwoAsks() async throws {
        let saved = Saved()
        let asks = coordinator(saved)
        let policy = NetworkPolicy(askTimeoutSeconds: 30)
        let ip = "185.142.236.41"
        async let high = asks.decide(host: ip, port: 8947, kind: .transparentTCP, owner: nil, policy: policy)
        async let ssh = asks.decide(host: ip, port: 22, kind: .transparentTCP, owner: nil, policy: policy)
        let requests = try await pending(asks, count: 2)
        #expect(Set(requests.compactMap(\.port)) == [8947, 22])

        let highAsk = try #require(requests.first { $0.port == 8947 })
        let sshAsk = try #require(requests.first { $0.port == 22 })
        try await asks.answer(AskAnswer(id: highAsk.id, decision: .denyAlways, scope: .hostAndPort))
        try await asks.answer(AskAnswer(id: sshAsk.id, decision: .allowAlways, scope: .host))
        #expect(await high.decision == .askedDenied)
        #expect(await ssh.decision == .askedAllowed)
        #expect(saved.rules.map(\.displayPattern) == ["\(ip):8947", ip], ".hostAndPort keeps the port, .host does not")

        // Remembered answers are per key too: port 8947 stays denied, 22 allowed, a third port asks again.
        #expect(await asks.decide(host: ip, port: 8947, kind: .transparentTCP, owner: nil, policy: policy).decision == .askedDenied)
        #expect(await asks.decide(host: ip, port: 22, kind: .transparentTCP, owner: nil, policy: policy).decision == .askedAllowed)
        async let third = asks.decide(host: ip, port: 5432, kind: .transparentTCP, owner: nil, policy: policy)
        let next = try #require(try await pending(asks, count: 1).first)
        #expect(next.port == 5432)
        try await asks.answer(AskAnswer(id: next.id, decision: .denyOnce))
        #expect(await third.decision == .askedDenied)
    }

    @Test func webPortsShareOneAskPerHost() async throws {
        let saved = Saved()
        let asks = coordinator(saved)
        let policy = NetworkPolicy(askTimeoutSeconds: 30)
        async let tls = asks.decide(host: "api.test", port: 443, kind: .transparentTLS, owner: nil, policy: policy)
        let request = try #require(try await pending(asks, count: 1).first)
        async let http = asks.decide(host: "api.test", port: 80, kind: .transparentHTTP, owner: nil, policy: policy)
        try await Task.sleep(nanoseconds: 50_000_000)
        #expect(await asks.pendingRequests().count == 1)
        try await asks.answer(AskAnswer(id: request.id, decision: .allowAlways, scope: .hostAndPort))
        let results = await [tls, http]
        #expect(results.allSatisfy { $0.allowed })
        #expect(saved.rules.map(\.displayPattern) == ["api.test:443"])
    }
}
