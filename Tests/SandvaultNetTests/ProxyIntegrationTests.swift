import Foundation
import NIOCore
import NIOSSL
import SandvaultCore
import Testing
@testable import SandvaultNet

@Suite struct ProxyIntegrationTests {
    @Test func connectTunnelReachesTheOrigin() async throws {
        let origin = try await TestOrigin.start(name: "origin")
        let netd = try await TestNetd.start(.testing([("127.0.0.1", .allow)]))
        try await withCleanup({ await origin.stop(); await netd.stop() }) {
            // The tunnelled request is sent right behind the CONNECT head, before the 200 arrives.
            let response = try await RawClient.exchange(
                port: Int(netd.ports.explicitProxy),
                "CONNECT 127.0.0.1:\(origin.port) HTTP/1.1\r\nHost: 127.0.0.1:\(origin.port)\r\n\r\nGET /tunnel HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n"
            )
            #expect(response.hasPrefix("HTTP/1.1 200 Connection established\r\n\r\nHTTP/1.1 200 OK\r\n"))
            #expect(response.hasSuffix("origin saw GET /tunnel"))
            let record = try await netd.record { $0.kind == .explicitProxy && $0.host == "127.0.0.1" }
            #expect(record.decision == .allowed)
            #expect(record.port == UInt16(origin.port))
            #expect(record.bytesIn > 0 && record.bytesOut > 0)
            #expect(record.ruleID != nil)
        }
    }

    @Test func connectDeniedAnswers403WithTheAllowCommand() async throws {
        let netd = try await TestNetd.start(.testing([("*.blocked.test", .deny)]))
        try await withCleanup({ await netd.stop() }) {
            let response = try await RawClient.exchange(port: Int(netd.ports.explicitProxy), "CONNECT api.blocked.test:443 HTTP/1.1\r\nHost: api.blocked.test:443\r\n\r\n")
            #expect(response.hasPrefix("HTTP/1.1 403 Forbidden\r\n"))
            #expect(response.hasSuffix(
                "\r\n\r\nsandvault-config blocked api.blocked.test:443: rule *.blocked.test (deny). To allow it: svctl proxy allow api.blocked.test\n"
            ))
            let record = try await netd.record { $0.host == "api.blocked.test" }
            #expect(record.decision == .denied && record.kind == .explicitProxy)
        }
    }

    @Test func absoluteFormIsForwardedInOriginForm() async throws {
        let origin = try await TestOrigin.start(name: "origin")
        let netd = try await TestNetd.start(.testing([("127.0.0.1", .allow)]))
        try await withCleanup({ await origin.stop(); await netd.stop() }) {
            let authority = "127.0.0.1:\(origin.port)"
            // Two pipelined requests on one connection; each gets its own decision, record and upstream connection.
            let response = try await RawClient.exchange(
                port: Int(netd.ports.explicitProxy),
                "GET http://\(authority)/one?q=1 HTTP/1.1\r\nHost: \(authority)\r\nProxy-Connection: keep-alive\r\nProxy-Authorization: Basic eDp5\r\nAuthorization: Bearer secret\r\n\r\n"
                    + "GET http://\(authority)/two HTTP/1.1\r\nHost: \(authority)\r\nConnection: close\r\n\r\n"
            )
            let first = try #require(response.range(of: "origin saw GET /one?q=1"))
            let second = try #require(response.range(of: "origin saw GET /two"))
            #expect(first.upperBound <= second.lowerBound)
            #expect(response.components(separatedBy: "HTTP/1.1 200 OK").count == 3)

            let heads = origin.heads.all
            #expect(heads.count == 2)
            #expect(heads[0].hasPrefix("GET /one?q=1 HTTP/1.1\r\n"))
            #expect(!heads[0].lowercased().contains("proxy-"))
            #expect(heads[0].contains("Host: \(authority)"))
            #expect(heads[0].contains("Authorization: Bearer secret"), "end-to-end headers stay")

            let record = try await netd.record { $0.http.first?.url == "http://\(authority)/one?q=1" }
            #expect(record.decision == .allowed && record.http.first?.status == 200)
            #expect(record.http.first?.requestHeaders.contains(["Authorization", "<redacted>"]) == true)
            #expect(record.http.first?.responseHeaders.contains(["Set-Cookie", "<redacted>"]) == true)
        }
    }

    @Test func plainRequestsNeedAbsoluteForm() async throws {
        let netd = try await TestNetd.start(.testing())
        try await withCleanup({ await netd.stop() }) {
            let response = try await RawClient.exchange(port: Int(netd.ports.explicitProxy), "GET / HTTP/1.1\r\nHost: x.test\r\n\r\n")
            #expect(response.hasPrefix("HTTP/1.1 400 Bad Request\r\n"))
        }
    }

    @Test func transparentHTTPUsesTheHostHeader() async throws {
        let origin = try await TestOrigin.start(name: "web")
        let config = AppConfig.testing([("web.test", .allow)], overrides: ["web.test": "127.0.0.1"], blockPrivate: true)
        let netd = try await TestNetd.start(config, transparentHTTPPort: origin.port)
        try await withCleanup({ await origin.stop(); await netd.stop() }) {
            let response = try await RawClient.exchange(port: Int(netd.ports.transparentHTTP), "GET /t HTTP/1.1\r\nHost: web.test\r\nConnection: close\r\n\r\n")
            #expect(response.hasPrefix("HTTP/1.1 200 OK\r\n"))
            #expect(response.hasSuffix("web saw GET /t"))
            #expect(origin.heads.all.first?.contains("Host: web.test") == true)
            let record = try await netd.record { $0.kind == .transparentHTTP }
            #expect(record.host == "web.test" && record.port == 80 && record.decision == .allowed)
            #expect(record.http.first?.url == "http://web.test/t")
        }
    }

    @Test func privateDestinationsAreRefused() async throws {
        let resolver = StaticHostResolver(["intranet.test": ["10.0.0.7"], "mixed.test": ["192.168.0.2"]])
        let netd = try await TestNetd.start(.testing([("*", .allow)], blockPrivate: true), resolver: resolver)
        try await withCleanup({ await netd.stop() }) {
            let port = Int(netd.ports.explicitProxy)

            let literal = try await RawClient.exchange(port: port, "GET http://192.168.1.1/admin HTTP/1.1\r\nHost: 192.168.1.1\r\n\r\n")
            #expect(literal.hasPrefix("HTTP/1.1 403 Forbidden\r\n"))
            #expect(literal.contains("192.168.1.1 is a private destination"))

            let named = try await RawClient.exchange(port: port, "CONNECT intranet.test:443 HTTP/1.1\r\n\r\n")
            #expect(named.hasPrefix("HTTP/1.1 403 Forbidden\r\n"))
            #expect(named.contains("intranet.test resolves only to private addresses (10.0.0.7)"))

            let loopback = try await RawClient.exchange(port: port, "CONNECT 127.0.0.1:\(netd.ports.explicitProxy) HTTP/1.1\r\n\r\n")
            #expect(loopback.hasPrefix("HTTP/1.1 403 Forbidden\r\n"), "the proxy must not reach host services")
        }
    }

    @Test func transparentTLSRoutesBySNI() async throws {
        let tls = try OriginTLS()
        let origin = try await TestOrigin.start(name: "secure", tls: try tls.serverContext(for: "secure.test"))
        let config = AppConfig.testing([("secure.test", .allow)], overrides: ["secure.test": "127.0.0.1"], blockPrivate: true)
        let netd = try await TestNetd.start(config, transparentTLSPort: origin.port)
        try await withCleanup({ await origin.stop(); await netd.stop() }) {
            // End-to-end TLS: the client verifies the origin's certificate through the tunnel.
            let response = try await RawClient.exchange(
                port: Int(netd.ports.transparentTLS), "GET /sni HTTP/1.1\r\nHost: secure.test\r\nConnection: close\r\n\r\n",
                tls: try tls.clientContext(), serverName: "secure.test"
            )
            #expect(response.hasSuffix("secure saw GET /sni"))
            let record = try await netd.record { $0.kind == .transparentTLS && $0.host == "secure.test" }
            #expect(record.decision == .allowed && record.port == 443 && !record.inspected)
        }
    }

    @Test func transparentTLSDeniesByRuleAndWithoutSNI() async throws {
        let netd = try await TestNetd.start(.testing([("example.com", .deny)]))
        try await withCleanup({ await netd.stop() }) {
            let port = Int(netd.ports.transparentTLS)

            let withSNI = try await RawClient.exchange(port: port, send: [UInt8](try Fixture.data("clienthello-sni-example.com.bin")))
            #expect(withSNI.isEmpty)
            #expect(try await netd.record { $0.host == "example.com" }.decision == .denied)

            let withoutSNI = try await RawClient.exchange(port: port, send: [UInt8](try Fixture.data("clienthello-no-sni.bin")))
            #expect(withoutSNI.isEmpty)
            #expect(try await netd.record { $0.host == "(no SNI)" }.decision == .denied)
        }
    }

    @Test func statusAndReloadThroughTheControlSocket() async throws {
        let origin = try await TestOrigin.start(name: "origin")
        let netd = try await TestNetd.start(.testing([("127.0.0.1", .allow)]))
        try await withCleanup({ await origin.stop(); await netd.stop() }) {
            let client = try await ControlClient.connect(socketPath: netd.socketPath)
            defer { client.close() }

            let request = "GET http://127.0.0.1:\(origin.port)/ HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n"
            #expect(try await RawClient.exchange(port: Int(netd.ports.explicitProxy), request).hasPrefix("HTTP/1.1 200 OK"))
            _ = try await netd.record { $0.host == "127.0.0.1" }

            let status = try await client.status()
            #expect(status.ports == netd.ports)
            #expect(status.mode == .proxyOnly)
            #expect(status.allowedCount == 1 && status.deniedCount == 0)
            #expect(try await client.recent(limit: 10).count == 1)

            var config = try netd.store.load()
            try config.network.upsertDomainRule(pattern: "127.0.0.1", action: .deny)
            try netd.store.save(config)
            try await client.reloadConfig()
            #expect(try await RawClient.exchange(port: Int(netd.ports.explicitProxy), request).hasPrefix("HTTP/1.1 403"))

            let mode = try FileManager.default.attributesOfItem(atPath: netd.socketPath)[.posixPermissions] as? NSNumber
            #expect(mode?.intValue == 0o600)
        }
    }
}

@Suite struct AskIntegrationTests {
    /// Sends a request through the transparent HTTP listener in the background.
    func request(_ netd: TestNetd, host: String) -> Task<String, Error> {
        let port = Int(netd.ports.transparentHTTP)
        return Task { try await RawClient.exchange(port: port, "GET /asked HTTP/1.1\r\nHost: \(host)\r\nConnection: close\r\n\r\n") }
    }

    func nextAsk(_ client: ControlClient) async throws -> AskRequest {
        for await event in client.events {
            if case .ask(let ask) = event { return ask }
        }
        throw SandvaultError.io("control connection closed")
    }

    @Test func askAnsweredThroughAControlClient() async throws {
        let origin = try await TestOrigin.start(name: "origin")
        let netd = try await TestNetd.start(.testing(overrides: ["*.ask.test": "127.0.0.1"]), transparentHTTPPort: origin.port)
        try await withCleanup({ await origin.stop(); await netd.stop() }) {
            let client = try await ControlClient.connect(socketPath: netd.socketPath)
            defer { client.close() }
            try await client.subscribe([.asks, .connections])

            let pending = request(netd, host: "www.ask.test")
            let ask = try await nextAsk(client)
            #expect(ask.host == "www.ask.test" && ask.port == 80 && ask.kind == .transparentHTTP)
            #expect(ask.expiresAt.timeIntervalSince(ask.createdAt) == 30)
            #expect(try await client.pendingAsks().map(\.id) == [ask.id])
            try await client.answer(AskAnswer(id: ask.id, decision: .allowOnce))

            #expect(try await pending.value.hasSuffix("origin saw GET /asked"))
            let record = try await netd.record { $0.host == "www.ask.test" }
            #expect(record.decision == .askedAllowed)
            #expect(try netd.store.load().network.domainRules.isEmpty, "allow-once saves nothing")
        }
    }

    @Test func askTimesOutToTheFallback() async throws {
        let netd = try await TestNetd.start(.testing(overrides: ["*.ask.test": "127.0.0.1"], askTimeout: 1))
        try await withCleanup({ await netd.stop() }) {
            let client = try await ControlClient.connect(socketPath: netd.socketPath)
            defer { client.close() }
            try await client.subscribe([.asks])

            let response = try await request(netd, host: "slow.ask.test").value
            #expect(response.hasPrefix("HTTP/1.1 403 Forbidden"))
            #expect(response.contains("ask timed out, fallback deny"))
            #expect(try await netd.record { $0.host == "slow.ask.test" }.decision == .timedOut)
        }
    }

    @Test func withoutAClientTheFallbackAppliesAtOnce() async throws {
        let netd = try await TestNetd.start(.testing(overrides: ["*.ask.test": "127.0.0.1"]))
        try await withCleanup({ await netd.stop() }) {
            let response = try await request(netd, host: "nobody.ask.test").value
            #expect(response.contains("no client is answering asks, fallback deny"))
        }
    }

    @Test func allowAlwaysPersistsADomainRule() async throws {
        let origin = try await TestOrigin.start(name: "origin")
        let netd = try await TestNetd.start(.testing(overrides: ["*.ask.test": "127.0.0.1"]), transparentHTTPPort: origin.port)
        try await withCleanup({ await origin.stop(); await netd.stop() }) {
            let client = try await ControlClient.connect(socketPath: netd.socketPath)
            defer { client.close() }
            try await client.subscribe([.asks])

            let pending = request(netd, host: "api.ask.test")
            let ask = try await nextAsk(client)
            try await client.answer(AskAnswer(id: ask.id, decision: .allowAlways, scope: .domain))
            #expect(try await pending.value.hasPrefix("HTTP/1.1 200 OK"))

            let rules = try netd.store.load().network.domainRules
            #expect(rules.map(\.pattern) == ["*.ask.test"])
            #expect(rules.first?.action == .allow)
            // The live policy already uses it.
            #expect(netd.daemon.runtime.policy.snapshot.engine.evaluate(host: "other.ask.test", port: 443).action == .allow)
            await #expect(throws: SandvaultError.self) { try await client.answer(AskAnswer(id: ask.id, decision: .denyOnce)) }
        }
    }
}

@Suite(.enabled(if: Curl.available, "needs /usr/bin/curl")) struct InspectionIntegrationTests {
    @Test func curlThroughTheProxyIsDecryptedAndLogged() async throws {
        let tls = try OriginTLS()
        let origin = try await TestOrigin.start(name: "secure", tls: try tls.serverContext(for: "secure.test"))
        let config = AppConfig.testing(
            [("secure.test", .allow)], inspect: ["secure.test"], overrides: ["secure.test": "127.0.0.1"], blockPrivate: true, inspection: true
        )
        let netd = try await TestNetd.start(config, trustRoots: try tls.trustRoots, createCA: true)
        try await withCleanup({ await origin.stop(); await netd.stop() }) {
            let caFile = CAStore(paths: netd.layout.paths).certificatePath

            let result = try await Curl.run([
                "-x", "http://127.0.0.1:\(netd.ports.explicitProxy)", "--cacert", caFile,
                "-H", "Authorization: Bearer topsecret", "https://secure.test:\(origin.port)/inspected?x=1",
            ])
            #expect(result.exitCode == 0, "\(result.stderrString)")
            #expect(result.stdoutString == "secure saw GET /inspected?x=1")

            let record = try await netd.record { $0.host == "secure.test" && !$0.http.isEmpty }
            #expect(record.inspected && record.decision == .allowed && record.kind == .explicitProxy)
            let summary = try #require(record.http.first)
            #expect(summary.method == "GET" && summary.status == 200)
            #expect(summary.url == "https://secure.test:\(origin.port)/inspected?x=1")
            #expect(summary.requestHeaders.contains(["Authorization", "<redacted>"]))
            #expect(summary.responseHeaders.contains(["Set-Cookie", "<redacted>"]))
            #expect(!(try String(contentsOfFile: netd.layout.paths.connectionLog, encoding: .utf8)).contains("topsecret"))
            #expect(try await ControlClient.connect(socketPath: netd.socketPath).status().caFingerprint == (try CAStore(paths: netd.layout.paths).load()?.fingerprint))

            // Without the CA, curl refuses the leaf: the connection really was intercepted.
            let untrusted = try await Curl.run(["-x", "http://127.0.0.1:\(netd.ports.explicitProxy)", "https://secure.test:\(origin.port)/"])
            #expect(untrusted.exitCode == 60)
        }
    }

    @Test func transparentTLSIsDecryptedForInspectedRules() async throws {
        let tls = try OriginTLS()
        let origin = try await TestOrigin.start(name: "secure", tls: try tls.serverContext(for: "secure.test"))
        let config = AppConfig.testing(
            [("secure.test", .allow)], inspect: ["secure.test"], overrides: ["secure.test": "127.0.0.1"], blockPrivate: true, inspection: true
        )
        let netd = try await TestNetd.start(config, transparentTLSPort: origin.port, trustRoots: try tls.trustRoots, createCA: true)
        try await withCleanup({ await origin.stop(); await netd.stop() }) {
            let caFile = CAStore(paths: netd.layout.paths).certificatePath

            let result = try await Curl.run([
                "--cacert", caFile, "--resolve", "secure.test:\(netd.ports.transparentTLS):127.0.0.1",
                "https://secure.test:\(netd.ports.transparentTLS)/transparent",
            ])
            #expect(result.exitCode == 0, "\(result.stderrString)")
            #expect(result.stdoutString == "secure saw GET /transparent")
            let record = try await netd.record { $0.kind == .transparentTLS && !$0.http.isEmpty }
            #expect(record.inspected && record.http.first?.url == "https://secure.test:\(origin.port)/transparent")
        }
    }
}

@Suite struct DNSIntegrationTests {
    @Test func deniesOverridesAndForwards() async throws {
        let resolver = try await FakeResolver.start()
        let config = AppConfig.testing([("*.blocked.test", .deny), ("*.allowed.test", .allow)], overrides: ["db.allowed.test": "10.1.2.3"])
        let netd = try await TestNetd.start(config, upstreamDNS: resolver.address)
        try await withCleanup({ await resolver.stop(); await netd.stop() }) {
            let port = Int(netd.ports.dns)

            let denied = try await DNSClient.query(port: port, name: "ads.blocked.test")
            #expect(denied.rcode == .nameError && denied.answers.isEmpty)
            #expect(try await netd.record { $0.host == "ads.blocked.test" }.decision == .denied)

            let overridden = try await DNSClient.query(port: port, name: "db.allowed.test")
            #expect(overridden.rcode == .noError && overridden.answerAddresses == ["10.1.2.3"])
            let noAAAA = try await DNSClient.query(port: port, name: "db.allowed.test", type: DNSRecordType.aaaa)
            #expect(noAAAA.rcode == .noError && noAAAA.answers.isEmpty)

            let forwarded = try await DNSClient.query(port: port, name: "www.allowed.test")
            #expect(forwarded.rcode == .noError && forwarded.answerAddresses == ["192.0.2.10"])
            let overTCP = try await DNSClient.query(port: port, name: "tcp.allowed.test", tcp: true)
            #expect(overTCP.answerAddresses == ["192.0.2.10"])
            #expect(resolver.queries.all == ["www.allowed.test", "tcp.allowed.test"], "denied and overridden names never leave netd")

            let record = try await netd.record { $0.host == "www.allowed.test" }
            #expect(record.kind == .dns && record.decision == .allowed && record.dnsAnswers == ["192.0.2.10"] && record.port == nil)
        }
    }

    @Test func askRefusesNowAndAppliesTheAnswerToTheNextQuery() async throws {
        let resolver = try await FakeResolver.start()
        let netd = try await TestNetd.start(.testing(), upstreamDNS: resolver.address)
        try await withCleanup({ await resolver.stop(); await netd.stop() }) {
            let port = Int(netd.ports.dns)

            // Nobody answers asks: the fallback (deny) applies.
            #expect(try await DNSClient.query(port: port, name: "first.test").rcode == .nameError)

            let client = try await ControlClient.connect(socketPath: netd.socketPath)
            defer { client.close() }
            try await client.subscribe([.asks])
            #expect(try await DNSClient.query(port: port, name: "new.test").rcode == .refused)
            let ask = try #require(try await client.pendingAsks().first)
            #expect(ask.host == "new.test" && ask.kind == .dns && ask.port == nil)
            try await client.answer(AskAnswer(id: ask.id, decision: .allowOnce))
            #expect(try await DNSClient.query(port: port, name: "new.test").answerAddresses == ["192.0.2.10"])
        }
    }
}
