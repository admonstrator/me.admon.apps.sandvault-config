import Foundation
import Testing
@testable import SandvaultCore
@testable import SandvaultEnforce

@Suite struct PFAnchorTests {
    static let uid: UInt32 = 601
    static let exceptions = [
        PortException(id: fixedID(11), proto: .tcp, destination: "140.82.112.0/20", port: 22, note: "ssh to github"),
        PortException(id: fixedID(12), proto: .udp, destination: "any", port: 123, note: "ntp"),
        PortException(id: fixedID(13), proto: .tcp, destination: "2001:db8::10", port: nil),
    ]

    static func state(
        _ mode: FirewallMode, lan: Bool = true, localhost: LocalhostPolicy = .sandboxAndHelpers,
        exceptions: [PortException] = [], ports: [UInt16] = [9222, 3000, 18080, 3000]
    ) -> AppliedState {
        AppliedState(
            sandbox: SandboxSettings(),
            network: NetworkPolicy(mode: mode, portExceptions: exceptions, blockLAN: lan, localhost: localhost),
            dynamicLocalPorts: ports,
            generatedAt: Date(timeIntervalSince1970: 0)
        )
    }

    func rules(_ state: AppliedState) throws -> String {
        try #require(try PFAnchorGenerator.rules(for: state, uid: Self.uid))
    }

    @Test func offMeansNoAnchor() throws {
        #expect(try PFAnchorGenerator.rules(for: Self.state(.off), uid: Self.uid) == nil)
    }

    @Test func goldenFiles() throws {
        try Fixture.expectGolden(try rules(Self.state(.blocked)), "pf-blocked.conf")
        try Fixture.expectGolden(try rules(Self.state(.open)), "pf-open.conf")
        try Fixture.expectGolden(try rules(Self.state(.open, lan: false, localhost: .allowAll, exceptions: Self.exceptions)), "pf-open-nolan-allowall-exceptions.conf")
        try Fixture.expectGolden(try rules(Self.state(.watch, exceptions: Self.exceptions)), "pf-watch.conf")
        try Fixture.expectGolden(try rules(Self.state(.proxyOnly, exceptions: Self.exceptions)), "pf-proxy-only.conf")
        try Fixture.expectGolden(try rules(Self.state(.proxyOnly, localhost: .blockAll)), "pf-proxy-only-blockall.conf")
        try Fixture.expectGolden(try rules(Self.state(.proxyOnly, localhost: .allowAll, ports: [])), "pf-proxy-only-allowall.conf")
    }

    @Test(arguments: [FirewallMode.open, .watch, .proxyOnly, .blocked])
    func everyRuleNamesTheUIDAndNeverTheAccount(_ mode: FirewallMode) throws {
        for policy in LocalhostPolicy.allCases {
            let text = try rules(Self.state(mode, localhost: policy, exceptions: Self.exceptions))
            let ruleLines = text.split(separator: "\n").filter { !$0.hasPrefix("#") }
            for line in ruleLines where !line.hasPrefix("rdr ") {
                #expect(line.hasSuffix("user 601") || line.hasSuffix("user 601 keep state"), "\(line)")
            }
            #expect(!text.contains("user sandvault") && !text.contains("alice"))
        }
    }

    @Test func proxyOnlyOrderAndTheRerouteSubtlety() throws {
        for policy in LocalhostPolicy.allCases {
            let lines = try rules(Self.state(.proxyOnly, localhost: policy, exceptions: Self.exceptions))
                .split(separator: "\n").filter { !$0.hasPrefix("#") }.map(String.init)
            let firstFilter = try #require(lines.firstIndex { !$0.hasPrefix("rdr ") })
            #expect(lines[..<firstFilter].count == 3)
            #expect(lines[firstFilter...].allSatisfy { !$0.hasPrefix("rdr ") }, "translation rules must precede filter rules")
            #expect(lines.last == "block return out log quick proto { tcp udp } from any to any user 601")
            // Before the catch-all, only loopback destinations are blocked: the re-routed flow (out on lo0, original
            // destination) must never meet a block rule.
            for line in lines.dropLast() where line.hasPrefix("block") {
                #expect(line.contains("to { 127.0.0.0/8 ::1 }"), "\(line)")
            }
            let reroute = try #require(lines.firstIndex { $0.contains("route-to") })
            let rerouted = try #require(lines.firstIndex { $0.hasPrefix("pass out quick on lo0 inet proto tcp from any to ! 127.0.0.0/8") })
            let firstBlock = try #require(lines.firstIndex { $0.hasPrefix("block") })
            #expect(reroute < rerouted && rerouted < firstBlock)
        }
    }

    @Test func watchReroutesWebAndDNSAndPassesTheRest() throws {
        let lines = try rules(Self.state(.watch, exceptions: Self.exceptions))
            .split(separator: "\n").filter { !$0.hasPrefix("#") }.map(String.init)
        let firstFilter = try #require(lines.firstIndex { !$0.hasPrefix("rdr ") })
        #expect(lines[..<firstFilter].count == 3)
        #expect(lines.last == "pass out quick proto { tcp udp } from any to any user 601 keep state")
        // Web and DNS are re-routed before the LAN guard, so netd sees (and may refuse) LAN web hosts by name.
        let reroute = try #require(lines.firstIndex { $0.contains("route-to") })
        let rerouted = try #require(lines.firstIndex { $0.hasPrefix("pass out quick on lo0 inet proto tcp from any to ! 127.0.0.0/8") })
        let lanGuard = try #require(lines.firstIndex { $0.contains("10.0.0.0/8") })
        #expect(reroute < rerouted && rerouted < lanGuard)
        // IPv6 web and DNS cannot be re-routed: refused, so clients fall back to IPv4.
        #expect(lines.contains("block return out log quick inet6 proto tcp from any to ! ::1 port { 53 80 443 } user 601"))
    }

    @Test func openModeExceptionsPrecedeTheLANGuard() throws {
        let lines = try rules(Self.state(.open, exceptions: Self.exceptions)).split(separator: "\n").map(String.init)
        let exception = try #require(lines.firstIndex { $0.contains("140.82.112.0/20 port 22") })
        let guardLine = try #require(lines.firstIndex { $0.contains("10.0.0.0/8") })
        #expect(exception < guardLine)
        #expect(lines[guardLine].contains("fc00::/7 fe80::/10 ff00::/8"))
    }

    @Test func dynamicPortsAreDeduplicatedAndSkipNetdPorts() throws {
        let text = try rules(Self.state(.open, ports: [9222, 3000, 18080, 3000]))
        #expect(text.contains("to { 127.0.0.0/8 ::1 } port { 3000 9222 } user 601"))
        let none = try rules(Self.state(.open, ports: []))
        #expect(!none.contains("to { 127.0.0.0/8 ::1 } port"))
    }

    @Test(arguments: ["1.2.3.4; pass all", "example.com", "10.0.0.0/33", "", "any\n", "::1%lo0"])
    func rejectsBadExceptionDestinations(_ destination: String) {
        let state = Self.state(.open, exceptions: [PortException(proto: .tcp, destination: destination, port: 22)])
        #expect(throws: SandvaultError.self) { try PFAnchorGenerator.rules(for: state, uid: Self.uid) }
    }

    @Test func rejectsZeroPortsAndImplausibleUIDs() {
        #expect(throws: SandvaultError.self) {
            try PFAnchorGenerator.rules(for: Self.state(.open, exceptions: [PortException(proto: .tcp, destination: "any", port: 0)]), uid: Self.uid)
        }
        #expect(throws: SandvaultError.self) { try PFAnchorGenerator.rules(for: Self.state(.open, ports: [0]), uid: Self.uid) }
        var badPorts = Self.state(.proxyOnly)
        badPorts.network.ports.dns = 0
        #expect(throws: SandvaultError.self) { try PFAnchorGenerator.rules(for: badPorts, uid: Self.uid) }
        for uid: UInt32 in [0, 1, 65, 499, 0x7FFF_FFFF, 4_294_967_294] {
            #expect(throws: SandvaultError.self) { try PFAnchorGenerator.rules(for: Self.state(.blocked), uid: uid) }
        }
    }

    @Test func addressFormatting() throws {
        func format(_ text: String) throws -> String { PFAnchorGenerator.format(try #require(AddressRange(text))) }
        #expect(try format("fc00::/7") == "fc00::/7")
        #expect(try format("::1") == "::1")
        #expect(try format("2001:db8:0:0:1:0:0:1") == "2001:db8::1:0:0:1")
        #expect(try format("2001:db8:1:2:3:4:5:6") == "2001:db8:1:2:3:4:5:6")
        #expect(try format("10.1.2.3/8") == "10.0.0.0/8")
        #expect(try format("192.168.1.10") == "192.168.1.10")
        #expect(try format("0.0.0.0/0") == "0.0.0.0/0")
    }
}
