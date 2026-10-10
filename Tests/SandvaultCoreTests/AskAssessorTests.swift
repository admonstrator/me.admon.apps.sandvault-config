import Foundation
import Testing
@testable import SandvaultCore

@Suite struct AskAssessorTests {
    // The three scenarios of the approved panel mockup.

    /// mDNSResponder asks Google's resolver for registry.npmjs.org.
    static let dnsToGoogle = AskDetails(
        address: "8.8.8.8", name: AskName(name: "registry.npmjs.org", source: .dns), reverseName: "dns.google",
        service: KnownService(port: 53, name: "DNS"),
        network: AskNetwork(asn: 15169, owner: "Google Public DNS", country: "US", kind: .knownService, source: .offline),
        encryption: .plain, history: AskHistory(allowed: 214, denied: 0, lastSeen: Date()),
        program: AskProgram(path: "/usr/sbin/mDNSResponder", signature: .apple, inTemporaryFolder: false)
    )

    /// node fetches from the npm registry behind Cloudflare, for the first time.
    static let npmOverTLS = AskDetails(
        address: "104.16.27.35", name: AskName(name: "registry.npmjs.org", source: .tls), reverseName: AskDetails.noReverseName,
        service: KnownService(port: 443, name: "HTTPS"),
        network: AskNetwork(asn: 13335, owner: "CLOUDFLARENET", country: "US", kind: .cdn, source: .offline),
        encryption: .tls, history: AskHistory(allowed: 0, denied: 0, lastSeen: nil),
        program: AskProgram(path: "/opt/homebrew/bin/node", signature: .developer(team: nil), inTemporaryFolder: false)
    )

    /// python3 from a temporary folder connects to a bare address on an unknown port at a Russian VPS host.
    static let oddPort = AskDetails(
        address: "185.142.236.41", name: AskName(name: nil, source: .none), reverseName: "vps-41.example-host.ru",
        service: KnownService(port: 8947, name: nil),
        network: AskNetwork(asn: 48282, owner: "VDSINA-AS", country: "RU", kind: .hosting, source: .offline),
        encryption: .unknown, history: AskHistory(allowed: 0, denied: 0, lastSeen: nil),
        program: AskProgram(path: "/tmp/build-x/.venv/bin/python3", signature: .unsigned, inTemporaryFolder: true)
    )

    static let marked = AskDetailSettings(markedCountries: ["ru"])

    func points(_ assessment: AskAssessment, _ kind: AskDetailKind) -> Int {
        assessment.signals.filter { $0.detail == kind }.reduce(0) { $0 + $1.points }
    }

    @Test func dnsToAKnownResolverLooksNormal() {
        let result = AskAssessor.assess(details: Self.dnsToGoogle, port: 53, settings: Self.marked)
        #expect(result.level == .normal)
        #expect(result.score == -6)
        #expect(result.signals.contains { $0.text == "Port 53 carries DNS, as expected." && $0.points == -2 })
        #expect(result.signals.contains { $0.text == "Allowed 214 times before." })
        #expect(result.signals.contains { $0.detail == .encryption && $0.effect == .info })
    }

    @Test func npmBehindACDNLooksNormal() {
        let result = AskAssessor.assess(details: Self.npmOverTLS, port: 443, settings: Self.marked)
        #expect(result.level == .normal)
        // 443 with TLS (-2), and the missing PTR name (+1).
        #expect(result.score == -1)
        #expect(result.signals.contains { $0.detail == .network && $0.effect == .info && $0.text.contains("Many services share it") })
        #expect(result.signals.contains { $0.detail == .history && $0.text == "The sandbox has not reached this host before." })
    }

    @Test func anUnknownPortAtAMarkedVPSIsSuspicious() {
        let result = AskAssessor.assess(details: Self.oddPort, port: 8947, settings: Self.marked)
        #expect(result.level == .suspicious)
        #expect(result.score == 8)
        #expect(points(result, .name) == 2)
        #expect(points(result, .port) == 2)
        #expect(points(result, .network) == 3)
        #expect(points(result, .program) == 1)
        #expect(result.signals.contains { $0.text == "Port 8947 is in no list of known services." })
        #expect(result.signals.contains { $0.text == "The program never looked up a name for this address." })
        #expect(result.signals.contains { $0.text.hasPrefix("Rented servers in a country you marked (RU)") })
        #expect(result.signals.contains { $0.detail == .encryption && $0.text == "netd cannot tell what protocol this is." })
        #expect(result.signals.filter { $0.effect == .info }.allSatisfy { $0.points == 0 })
    }

    @Test func turningDetailsOffLowersTheEvidence() {
        var settings = Self.marked
        settings.program = false
        settings.name = false
        let fewer = AskAssessor.assess(details: Self.oddPort, port: 8947, settings: settings)
        #expect(fewer.score == 5)
        #expect(fewer.level == .unusual)
        #expect(!fewer.signals.contains { $0.detail == .name || $0.detail == .program })

        settings.port = false
        settings.network = .off
        let none = AskAssessor.assess(details: Self.oddPort, port: 8947, settings: settings)
        #expect(none.score == 0)
        #expect(none.level == .normal)
    }

    @Test func missingDetailsCountNothing() {
        let result = AskAssessor.assess(details: AskDetails(), port: 8947, settings: Self.marked)
        #expect(result.score == 0)
        #expect(result.signals.isEmpty)
    }

    @Test func aMarkedCountryNeverCountsAlone() {
        var details = Self.npmOverTLS
        details.reverseName = "example.ru"
        details.network?.country = "RU"
        let alone = AskAssessor.assess(details: details, port: 443, settings: Self.marked)
        #expect(!alone.signals.contains { $0.text.contains("country you marked") })

        details.service = KnownService(port: 8947, name: nil)
        details.encryption = .unknown
        let withOther = AskAssessor.assess(details: details, port: 8947, settings: Self.marked)
        #expect(withOther.signals.contains { $0.points == 2 && $0.text == "The network is in a country you marked (RU)." })

        let unmarked = AskAssessor.assess(details: details, port: 8947, settings: AskDetailSettings())
        #expect(!unmarked.signals.contains { $0.text.contains("country you marked") })
    }

    @Test func theReverseNameCountsOnlyWhenTheLookupRan() {
        var details = Self.oddPort
        details.reverseName = nil
        #expect(!AskAssessor.assess(details: details, port: 8947, settings: Self.marked).signals.contains { $0.detail == .reverseName })
        details.reverseName = AskDetails.noReverseName
        #expect(AskAssessor.assess(details: details, port: 8947, settings: Self.marked).signals.contains { $0.detail == .reverseName && $0.points == 1 })
    }

    @Test func protocolMatchesNeedTheRightProtocol() {
        #expect(AskAssessor.matchesProtocol(port: 443, encryption: .tls))
        #expect(!AskAssessor.matchesProtocol(port: 443, encryption: .plain))
        #expect(AskAssessor.matchesProtocol(port: 80, encryption: .plain))
        #expect(AskAssessor.matchesProtocol(port: 53, encryption: .plain))
        #expect(!AskAssessor.matchesProtocol(port: 8443, encryption: .tls))
        #expect(!AskAssessor.matchesProtocol(port: 443, encryption: nil))
    }

    @Test func signalsAreOrderedByDetail() {
        let result = AskAssessor.assess(details: Self.oddPort, port: 8947, settings: Self.marked)
        let order = result.signals.map { AskDetailKind.allCases.firstIndex(of: $0.detail)! }
        #expect(order == order.sorted())
    }
}
