import Foundation
import SandvaultCore
import Testing
@testable import SandvaultNet

@Suite struct PolicyEngineTests {
    static func engine(_ rules: [(String, DomainAction)], default action: DomainAction = .ask, inspect: Set<String> = [], inspection: Bool = false) -> PolicyEngine {
        var policy = NetworkPolicy(defaultAction: action)
        policy.domainRules = rules.map { DomainRule(pattern: $0.0, action: $0.1, inspect: inspect.contains($0.0)) }
        policy.inspection.enabled = inspection
        return PolicyEngine(policy: policy)
    }

    struct Case: CustomStringConvertible, Sendable {
        var rules: [(String, DomainAction)]
        var host: String
        var port: UInt16?
        var action: DomainAction
        var pattern: String?
        var description: String { "\(host):\(port.map(String.init) ?? "dns") -> \(action)" }
    }

    static let cases: [Case] = [
        // Exact beats wildcard; the wildcard also covers the apex.
        Case(rules: [("*.example.com", .deny), ("api.example.com", .allow)], host: "api.example.com", port: 443, action: .allow, pattern: "api.example.com"),
        Case(rules: [("*.example.com", .deny), ("api.example.com", .allow)], host: "www.example.com", port: 443, action: .deny, pattern: "*.example.com"),
        Case(rules: [("*.example.com", .allow)], host: "example.com", port: 443, action: .allow, pattern: "*.example.com"),
        Case(rules: [("*.example.com", .allow)], host: "badexample.com", port: 443, action: .ask, pattern: nil),
        // Longer suffix beats shorter, `*` comes last.
        Case(rules: [("*", .deny), ("*.com", .ask), ("*.example.com", .allow)], host: "a.b.example.com", port: 80, action: .allow, pattern: "*.example.com"),
        Case(rules: [("*", .deny), ("*.com", .allow), ("*.b.example.com", .ask)], host: "a.b.example.com", port: 443, action: .ask, pattern: "*.b.example.com"),
        Case(rules: [("*", .allow), ("*.com", .deny)], host: "github.com", port: 443, action: .deny, pattern: "*.com"),
        Case(rules: [("*", .allow)], host: "anything.org", port: 443, action: .allow, pattern: "*"),
        // Equal specificity: deny beats allow beats ask.
        Case(rules: [("x.test", .allow), ("x.test", .deny)], host: "x.test", port: 443, action: .deny, pattern: "x.test"),
        Case(rules: [("*.x.test", .ask), ("*.x.test", .allow)], host: "a.x.test", port: 443, action: .allow, pattern: "*.x.test"),
        Case(rules: [("*", .ask), ("*", .allow), ("*", .deny)], host: "a.test", port: 443, action: .deny, pattern: "*"),
        // Normalization: case and trailing dot; rule patterns too.
        Case(rules: [("API.Example.COM.", .allow)], host: "api.EXAMPLE.com.", port: 443, action: .allow, pattern: "API.Example.COM."),
        // No match: default action.
        Case(rules: [], host: "new.test", port: 443, action: .ask, pattern: nil),
        Case(rules: [], host: "new.test", port: nil, action: .ask, pattern: nil),
        // Other ports need an explicit allow; ask never applies.
        Case(rules: [], host: "ssh.test", port: 22, action: .deny, pattern: nil),
        Case(rules: [("ssh.test", .ask)], host: "ssh.test", port: 22, action: .deny, pattern: "ssh.test"),
        Case(rules: [("ssh.test", .allow)], host: "ssh.test", port: 22, action: .allow, pattern: "ssh.test"),
        Case(rules: [("*", .allow)], host: "ssh.test", port: 2222, action: .allow, pattern: "*"),
        Case(rules: [("ssh.test", .deny)], host: "ssh.test", port: 22, action: .deny, pattern: "ssh.test"),
        // IP literals are matched directly; wildcards never match them except `*`.
        Case(rules: [("140.82.112.3", .allow)], host: "140.82.112.3", port: 443, action: .allow, pattern: "140.82.112.3"),
        Case(rules: [("*", .deny), ("::1", .allow)], host: "[::1]", port: 443, action: .allow, pattern: "::1"),
        // Invalid host names are denied without consulting rules.
        Case(rules: [("*", .allow)], host: "bad host", port: 443, action: .deny, pattern: nil),
    ]

    @Test(arguments: cases)
    func decides(_ testCase: Case) {
        let verdict = Self.engine(testCase.rules).evaluate(host: testCase.host, port: testCase.port)
        #expect(verdict.action == testCase.action, "\(verdict.reason)")
        #expect(verdict.rule?.pattern == testCase.pattern)
    }

    @Test func defaultActionApplies() {
        #expect(Self.engine([], default: .deny).evaluate(host: "a.test", port: 443).action == .deny)
        #expect(Self.engine([], default: .allow).evaluate(host: "a.test", port: 80).action == .allow)
        // The default never opens other ports.
        #expect(Self.engine([], default: .allow).evaluate(host: "a.test", port: 8080).action == .deny)
    }

    @Test func watchRefusesOnlyDenyRules() {
        var policy = NetworkPolicy(mode: .watch, defaultAction: .deny)
        policy.domainRules = [DomainRule(pattern: "tracker.example", action: .deny), DomainRule(pattern: "*.ask.example", action: .ask)]
        let engine = PolicyEngine(policy: policy)
        #expect(engine.evaluate(host: "tracker.example", port: 443).action == .deny)
        #expect(engine.evaluate(host: "tracker.example", port: 22).action == .deny)
        #expect(engine.evaluate(host: "a.ask.example", port: 443).action == .allow)
        #expect(engine.evaluate(host: "github.com", port: 22).action == .allow)
        #expect(engine.evaluate(host: "github.com", port: nil).reason == "watch mode (allow)")
        #expect(engine.evaluate(host: "bad host", port: 443).action == .deny)
    }

    @Test func reasonsNameTheCause() {
        let engine = Self.engine([("*.blocked.test", .deny)])
        #expect(engine.evaluate(host: "a.blocked.test", port: 443).reason == "rule *.blocked.test (deny)")
        #expect(engine.evaluate(host: "other.test", port: 443).reason == "default action (ask)")
        #expect(engine.evaluate(host: "other.test", port: 25).reason == "port 25 needs an explicit allow rule")
    }

    @Test func inspectionNeedsTheMasterSwitch() {
        let off = Self.engine([("api.test", .allow)], inspect: ["api.test"], inspection: false)
        #expect(off.evaluate(host: "api.test", port: 443).inspect == false)
        let on = Self.engine([("api.test", .allow), ("deny.test", .deny)], inspect: ["api.test", "deny.test"], inspection: true)
        #expect(on.evaluate(host: "api.test", port: 443).inspect)
        #expect(on.evaluate(host: "deny.test", port: 443).inspect == false)
    }

    @Test func overridesPickTheMostSpecificPattern() {
        var policy = NetworkPolicy()
        policy.dnsOverrides = [
            DnsOverride(pattern: "*.internal.test", address: "10.0.0.1"),
            DnsOverride(pattern: "db.internal.test", address: "10.0.0.2"),
            DnsOverride(pattern: "broken.test", address: "not-an-ip"),
        ]
        let engine = PolicyEngine(policy: policy)
        #expect(engine.override(for: "db.internal.test")?.address == "10.0.0.2")
        #expect(engine.override(for: "web.internal.test")?.address == "10.0.0.1")
        #expect(engine.override(for: "internal.test")?.address == "10.0.0.1")
        #expect(engine.override(for: "broken.test") == nil)
        #expect(engine.override(for: "other.test") == nil)
    }

    @Test func privateDestinationsFollowTheSwitch() {
        var policy = NetworkPolicy()
        let engine = PolicyEngine(policy: policy)
        for address in ["127.0.0.1", "10.1.2.3", "192.168.1.1", "169.254.169.254", "::1", "fe80::1", "fd00::1", "100.64.0.1", "0.0.0.0"] {
            #expect(engine.refusesDestination(address), "\(address)")
        }
        #expect(!engine.refusesDestination("140.82.112.3"))
        #expect(!engine.refusesDestination("2606:4700::1111"))
        policy.blockPrivateDestinations = false
        #expect(!PolicyEngine(policy: policy).refusesDestination("10.1.2.3"))
    }
}

@Suite struct DomainPatternTests {
    @Test func parsesAndNormalizes() throws {
        #expect(try DomainPattern("*") == .any)
        #expect(try DomainPattern(" *.Example.COM. ") == .suffix("example.com"))
        #expect(try DomainPattern("API.github.com") == .exact("api.github.com"))
        #expect(try DomainPattern("[::1]") == .exact("::1"))
        #expect(try DomainPattern("xn--bcher-kva.example") == .exact("xn--bcher-kva.example"))
        #expect(try DomainPattern("*.example.com").description == "*.example.com")
    }

    @Test func rejectsInvalidPatterns() {
        for bad in ["", "*.a b", "**.example.com", "a..b", "exa mple.com", "*.10.0.0.1", "foo/bar", "*example.com", "a.*.com"] {
            #expect(throws: SandvaultError.self, "\(bad)") { try DomainPattern(bad) }
        }
    }

    @Test func registrableDomains() {
        #expect(RegistrableDomain.of("api.github.com") == "github.com")
        #expect(RegistrableDomain.of("github.com") == "github.com")
        #expect(RegistrableDomain.of("www.bbc.co.uk") == "bbc.co.uk")
        #expect(RegistrableDomain.of("a.b.example.com.au") == "example.com.au")
        #expect(RegistrableDomain.of("localhost") == "localhost")
        #expect(RegistrableDomain.of("140.82.112.3") == "140.82.112.3")
        #expect(RegistrableDomain.rulePattern(for: "Raw.GitHubUserContent.com", scope: .host) == "raw.githubusercontent.com")
        #expect(RegistrableDomain.rulePattern(for: "raw.githubusercontent.com", scope: .domain) == "*.githubusercontent.com")
        #expect(RegistrableDomain.rulePattern(for: "news.bbc.co.uk", scope: .domain) == "*.bbc.co.uk")
        #expect(RegistrableDomain.rulePattern(for: "10.0.0.1", scope: .domain) == "10.0.0.1")
    }

    @Test func splitsHostAndPort() {
        #expect(HostName.splitHostPort("example.com")! == ("example.com", nil))
        #expect(HostName.splitHostPort("example.com:8443")! == ("example.com", 8443))
        #expect(HostName.splitHostPort("[::1]:443")! == ("::1", 443))
        #expect(HostName.splitHostPort("[::1]")! == ("::1", nil))
        #expect(HostName.splitHostPort("::1")! == ("::1", nil))
        #expect(HostName.splitHostPort("example.com:http") == nil)
        #expect(HostName.splitHostPort("example.com:0") == nil)
        #expect(HostName.splitHostPort("example.com:70000") == nil)
        #expect(HostName.splitHostPort("[::1]x") == nil)
    }
}

@Suite struct PolicyEditsTests {
    @Test func upsertsByNormalizedPattern() throws {
        var policy = NetworkPolicy()
        let first = try policy.upsertDomainRule(pattern: "*.GitHub.com", action: .allow, inspect: true)
        #expect(first.pattern == "*.github.com")
        let second = try policy.upsertDomainRule(pattern: "*.github.com.", action: .deny)
        #expect(second.id == first.id)
        #expect(second.action == .deny)
        #expect(second.inspect, "nil keeps the inspect flag")
        #expect(policy.domainRules.count == 1)
        _ = try policy.upsertDomainRule(pattern: "*.github.com", action: .allow, inspect: false)
        #expect(policy.domainRules[0].inspect == false)
        #expect(throws: SandvaultError.self) { try policy.upsertDomainRule(pattern: "bad pattern", action: .allow) }
    }

    @Test func removesByIdPrefixOrPattern() throws {
        var policy = NetworkPolicy()
        let a = try policy.upsertDomainRule(pattern: "a.test", action: .allow)
        _ = try policy.upsertDomainRule(pattern: "b.test", action: .deny)
        #expect(try policy.removeDomainRule(selector: "B.TEST").pattern == "b.test")
        #expect(try policy.removeDomainRule(selector: String(a.id.uuidString.prefix(6)).lowercased()).id == a.id)
        #expect(throws: SandvaultError.self) { try policy.removeDomainRule(selector: "c.test") }
        #expect(policy.domainRules.isEmpty)
    }

    @Test func ambiguousPrefixIsRefused() throws {
        var policy = NetworkPolicy()
        policy.domainRules = [
            DomainRule(id: UUID(uuidString: "AAAA0000-0000-0000-0000-000000000001")!, pattern: "a.test", action: .allow),
            DomainRule(id: UUID(uuidString: "AAAA0000-0000-0000-0000-000000000002")!, pattern: "b.test", action: .allow),
        ]
        #expect(throws: SandvaultError.self) { try policy.removeDomainRule(selector: "aaaa") }
        #expect(try policy.removeDomainRule(selector: "aaaa0000-0000-0000-0000-000000000002").pattern == "b.test")
    }

    @Test func overridesValidateAddresses() throws {
        var policy = NetworkPolicy()
        let entry = try policy.upsertDnsOverride(pattern: "db.test", address: "10.0.0.5")
        #expect(try policy.upsertDnsOverride(pattern: "DB.test", address: "FD00::5").id == entry.id)
        #expect(policy.dnsOverrides[0].address == "fd00::5")
        #expect(throws: SandvaultError.self) { try policy.upsertDnsOverride(pattern: "x.test", address: "example.com") }
        #expect(try policy.removeDnsOverride(selector: "db.test").id == entry.id)
    }
}
