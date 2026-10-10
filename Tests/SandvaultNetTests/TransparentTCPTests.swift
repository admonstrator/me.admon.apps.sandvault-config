import Foundation
import NIOCore
import SandvaultCore
import Testing
@testable import SandvaultNet

@Suite struct TCPPeekTests {
    @Test func tlsClientHelloGivesTheServerName() throws {
        let hello = [UInt8](try Fixture.data("clienthello-sni-example.com.bin"))
        #expect(TCPPeek.classify(hello, final: false) == TCPPeek(encryption: .tls, serverName: "example.com", nameSource: .tls))
        #expect(TCPPeek.classify([UInt8](try Fixture.data("clienthello-no-sni.bin")), final: false) == TCPPeek(encryption: .tls))
        // Half a ClientHello: wait for more, or call it TLS without a name when nothing more comes.
        let half = Array(hello.prefix(hello.count / 2))
        #expect(TCPPeek.classify(half, final: false) == nil)
        #expect(TCPPeek.classify(half, final: true) == TCPPeek(encryption: .tls))
    }

    @Test func httpRequestLineGivesTheHostHeader() {
        let request = Array("GET /x HTTP/1.1\r\nUser-Agent: t\r\nHost: Example.COM:8080\r\n\r\n".utf8)
        #expect(TCPPeek.classify(request, final: false) == TCPPeek(encryption: .plain, serverName: "example.com", nameSource: .http))
        let unfinished = Array("POST /x HTTP/1.1\r\nHost: a.test\r\n".utf8)
        #expect(TCPPeek.classify(unfinished, final: false) == nil)
        #expect(TCPPeek.classify(unfinished, final: true) == TCPPeek(encryption: .plain, serverName: "a.test", nameSource: .http))
        #expect(TCPPeek.classify(Array("GET / HTTP/1.0\r\n\r\n".utf8), final: false) == TCPPeek(encryption: .plain))
        #expect(TCPPeek.classify(Array("GE".utf8), final: false) == nil, "a method prefix may still become a request")
        #expect(TCPPeek.classify(Array("GE".utf8), final: true) == .unknown)
    }

    @Test func anythingElseIsUnknownAtOnce() {
        #expect(TCPPeek.classify(Array("SSH-2.0-OpenSSH_9.8\r\n".utf8), final: false) == .unknown)
        #expect(TCPPeek.classify([0x00, 0x01], final: false) == .unknown)
        #expect(TCPPeek.classify([], final: false) == nil)
        #expect(TCPPeek.classify([], final: true) == .unknown)
    }

    @Test func hintCarriesTheAddressAndWhatWasSeen() {
        let hint = TCPPeek(encryption: .tls, serverName: "example.com", nameSource: .tls).hint(address: "203.0.113.9")
        #expect(hint == ConnectionHint(address: "203.0.113.9", serverName: "example.com", nameSource: .tls, encryption: .tls))
        #expect(TCPPeek.unknown.hint(address: "203.0.113.9") == ConnectionHint(address: "203.0.113.9", encryption: .unknown))
        #expect(TCPRouter.kind(TCPPeek(encryption: .tls)) == .transparentTLS)
        #expect(TCPRouter.kind(TCPPeek(encryption: .plain)) == .transparentTCP)
    }
}

/// The transparent TCP listener (D37): the attributor names the original destination 203.0.113.9 (what lsof would
/// say), the policy judges that address and port, and the connection goes to a loopback origin in its place.
@Suite(.timeLimit(.minutes(1))) struct TransparentTCPTests {
    static let address = "203.0.113.9"

    func start(_ config: AppConfig, origin: TCPOrigin, port: UInt16 = 8947) async throws -> (TestNetd, SwitchableAttributor) {
        let attributor = SwitchableAttributor(process: (31, "nc"), destination: (Self.address, port))
        let netd = try await TestNetd.start(config, attributor: attributor, transparentTCPUpstream: origin.address)
        return (netd, attributor)
    }

    func exchange(_ netd: TestNetd, _ text: String) async throws -> String {
        try await RawClient.exchange(port: Int(netd.ports.transparentTCP), text)
    }

    func nextAsk(_ client: ControlClient) async throws -> AskRequest {
        for await event in client.events {
            if case .ask(let ask) = event { return ask }
        }
        throw SandvaultError.io("control connection closed")
    }

    @Test func allowedConnectionsAreSplicedToTheOriginalPort() async throws {
        let origin = try await TCPOrigin.start(.echo)
        var config = AppConfig.testing(defaultAction: .deny)
        config.network.domainRules = [DomainRule(pattern: Self.address, action: .allow, port: 8947)]
        let (netd, _) = try await start(config, origin: origin)
        try await withCleanup({ await origin.stop(); await netd.stop() }) {
            #expect(try await exchange(netd, "ping 8947\n") == "ping 8947\n")
            let record = try await netd.record { $0.kind == .transparentTCP && $0.host == Self.address }
            #expect(record.decision == .allowed && record.port == 8947 && record.process == "nc")
            #expect(record.ruleID == config.network.domainRules[0].id)
            #expect(record.bytesIn == 10 && record.bytesOut == 10)
            #expect(origin.received.all.joined().elementsEqual("ping 8947\n".utf8), "the peeked bytes are replayed once")
        }
    }

    @Test func deniedConnectionsAreClosedAndRecorded() async throws {
        let origin = try await TCPOrigin.start(.echo)
        var config = AppConfig.testing([(Self.address, .allow)])
        config.network.domainRules.append(DomainRule(pattern: Self.address, action: .deny, port: 8947))
        let (netd, attributor) = try await start(config, origin: origin)
        try await withCleanup({ await origin.stop(); await netd.stop() }) {
            #expect(try await exchange(netd, "ping\n").isEmpty)
            let record = try await netd.record { $0.host == Self.address }
            #expect(record.decision == .denied && record.kind == .transparentTCP && record.port == 8947)
            #expect(origin.received.all.isEmpty)
            // The portless allow still covers the other ports.
            attributor.set((Self.address, 2222))
            #expect(try await exchange(netd, "ping\n") == "ping\n")
            #expect(try await netd.record { $0.port == 2222 }.decision == .allowed)
        }
    }

    @Test func unknownAndLoopbackDestinationsAreRefused() async throws {
        let origin = try await TCPOrigin.start(.echo)
        let (netd, attributor) = try await start(.testing([("*", .allow)]), origin: origin)
        try await withCleanup({ await origin.stop(); await netd.stop() }) {
            attributor.set(nil)
            #expect(try await exchange(netd, "ping\n").isEmpty)
            #expect(try await netd.record { $0.host == "(unknown destination)" }.decision == .denied)
            attributor.set(("127.0.0.1", netd.ports.transparentTCP))
            #expect(try await exchange(netd, "ping\n").isEmpty)
            let loop = try await netd.record { $0.host == "127.0.0.1" }
            #expect(loop.decision == .denied && loop.kind == .transparentTCP)
            #expect(origin.received.all.isEmpty)
        }
    }

    @Test func serverSpeaksFirstWorks() async throws {
        let origin = try await TCPOrigin.start(.banner("SSH-2.0-sandvault-test\r\n"))
        let (netd, _) = try await start(.testing([(Self.address, .allow)]), origin: origin, port: 22)
        try await withCleanup({ await origin.stop(); await netd.stop() }) {
            let started = Date()
            let reply = try await RawClient.exchange(port: Int(netd.ports.transparentTCP), send: [])
            #expect(reply == "SSH-2.0-sandvault-test\r\n")
            #expect(Date().timeIntervalSince(started) >= 0.25, "netd waits for the client's first bytes before deciding")
            let record = try await netd.record { $0.host == Self.address }
            #expect(record.decision == .allowed && record.port == 22 && record.kind == .transparentTCP)
        }
    }

    @Test func asksPerHostAndPortAndSavesAPortRule() async throws {
        let origin = try await TCPOrigin.start(.echo)
        let (netd, attributor) = try await start(.testing(), origin: origin)
        try await withCleanup({ await origin.stop(); await netd.stop() }) {
            let client = try await ControlClient.connect(socketPath: netd.socketPath)
            defer { client.close() }
            try await client.subscribe([.asks])

            let port = Int(netd.ports.transparentTCP)
            let first = Task { try await RawClient.exchange(port: port, "hello\n") }
            let ask = try await nextAsk(client)
            #expect(ask.host == Self.address && ask.port == 8947 && ask.kind == .transparentTCP && ask.process == "nc")
            try await client.answer(AskAnswer(id: ask.id, decision: .allowAlways, scope: .hostAndPort))
            #expect(try await first.value == "hello\n")
            let rules = try netd.store.load().network.domainRules
            #expect(rules.map(\.displayPattern) == ["\(Self.address):8947"] && rules.first?.action == .allow)
            #expect(try await netd.record { $0.host == Self.address }.decision == .askedAllowed)

            // Another port on the same address is its own ask; the answer above does not cover it.
            attributor.set((Self.address, 22))
            let second = Task { try await RawClient.exchange(port: port, "hello\n") }
            let other = try await nextAsk(client)
            #expect(other.host == Self.address && other.port == 22 && other.id != ask.id)
            try await client.answer(AskAnswer(id: other.id, decision: .denyOnce))
            #expect(try await second.value.isEmpty)
            #expect(try await netd.record { $0.port == 22 }.decision == .askedDenied)
        }
    }

    @Test func tlsClientHelloNamesTheAsk() async throws {
        let hello = [UInt8](try Fixture.data("clienthello-sni-example.com.bin"))
        let origin = try await TCPOrigin.start(.sink(hello.count))
        let (netd, _) = try await start(.testing(), origin: origin, port: 8443)
        try await withCleanup({ await origin.stop(); await netd.stop() }) {
            let client = try await ControlClient.connect(socketPath: netd.socketPath)
            defer { client.close() }
            try await client.subscribe([.asks])

            let port = Int(netd.ports.transparentTCP)
            let pending = Task { try await RawClient.exchange(port: port, send: hello) }
            let ask = try await nextAsk(client)
            #expect(ask.host == "example.com" && ask.port == 8443 && ask.kind == .transparentTLS)
            try await client.answer(AskAnswer(id: ask.id, decision: .allowOnce))
            _ = try await pending.value
            let record = try await netd.record { $0.host == "example.com" }
            #expect(record.decision == .askedAllowed && record.kind == .transparentTLS && record.port == 8443)
            // The bytes went to the original address (the origin stands in for it), not to a resolution of the SNI.
            #expect(origin.received.all.joined().elementsEqual(hello))
        }
    }
}
