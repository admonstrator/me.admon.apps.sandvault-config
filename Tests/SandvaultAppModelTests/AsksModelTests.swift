import Foundation
import SandvaultCore
import Testing
@testable import SandvaultAppModel

/// The three requests of the approved panel mockup (D41), as netd would fill them.
enum AskFixtures {
    static let now = Date(timeIntervalSince1970: 1_800_000_000)

    static func signal(_ detail: AskDetailKind, _ effect: AskAssessment.Signal.Effect, _ points: Int, _ text: String) -> AskAssessment.Signal {
        AskAssessment.Signal(detail: detail, effect: effect, points: points, text: text)
    }

    /// mDNSResponder asks Google Public DNS for registry.npmjs.org.
    static var dns: AskRequest {
        AskRequest(
            host: "8.8.8.8", port: 53, kind: .dns, pid: 310, process: "mDNSResponder", createdAt: now, expiresAt: now.addingTimeInterval(45),
            details: AskDetails(
                address: "8.8.8.8", name: AskName(name: "registry.npmjs.org", source: .dns), reverseName: "dns.google",
                service: KnownService(port: 53, name: "DNS"),
                network: AskNetwork(asn: 15169, owner: "GOOGLE - Google LLC", country: "US", kind: .knownService, source: .offline),
                encryption: .plain, history: AskHistory(allowed: 214, denied: 0, lastSeen: now.addingTimeInterval(-120)),
                program: AskProgram(path: "/usr/sbin/mDNSResponder", signature: .apple, inTemporaryFolder: false),
                assessment: AskAssessment(level: .normal, score: -6, signals: [
                    signal(.name, .plus, -1, "The lookup is for registry.npmjs.org."),
                    signal(.port, .plus, -1, "Port 53 carries DNS, as expected."),
                    signal(.network, .plus, -2, "Google Public DNS, a known resolver (AS15169)."),
                    signal(.encryption, .info, 0, "Classic DNS is unencrypted. Normal for port 53."),
                    signal(.history, .plus, -1, "Allowed 214 times before."),
                    signal(.program, .plus, -1, "/usr/sbin/mDNSResponder, signed by Apple."),
                ])
            )
        )
    }

    /// node fetches a package over TLS through Cloudflare.
    static var npm: AskRequest {
        AskRequest(
            host: "registry.npmjs.org", port: 443, kind: .transparentTLS, pid: 4242, process: "node", createdAt: now, expiresAt: now.addingTimeInterval(45),
            details: AskDetails(
                address: "104.16.27.35", name: AskName(name: "registry.npmjs.org", source: .tls),
                service: KnownService(port: 443, name: "HTTPS"),
                network: AskNetwork(asn: 13335, owner: "CLOUDFLARENET - Cloudflare, Inc.", country: "US", kind: .cdn, source: .offline),
                encryption: .tls, history: AskHistory(allowed: 0, denied: 0, lastSeen: nil),
                program: AskProgram(path: "/opt/homebrew/bin/node", signature: .developer(team: nil), inTemporaryFolder: false),
                assessment: AskAssessment(level: .normal, score: -3, signals: [
                    signal(.name, .plus, -1, "Known package source. The name came from TLS."),
                    signal(.port, .plus, -1, "Port 443 with TLS, as expected."),
                    signal(.network, .info, 0, "Cloudflare network (AS13335). Many services share it."),
                    signal(.encryption, .plus, 0, "The connection uses TLS."),
                    signal(.history, .info, 0, "The sandbox has not reached this host before."),
                    signal(.program, .plus, -1, "/opt/homebrew/bin/node, validly signed."),
                ])
            )
        )
    }

    /// An unsigned python3 from /tmp talks to port 8947 of a rented server in a marked country.
    static var odd: AskRequest {
        AskRequest(
            host: "185.142.236.41", port: 8947, kind: .transparentTLS, pid: 777, process: "python3", createdAt: now, expiresAt: now.addingTimeInterval(45),
            details: AskDetails(
                address: "185.142.236.41", name: AskName(name: nil, source: .none), reverseName: "vps-41.example-host.ru",
                service: KnownService(port: 8947, name: nil),
                network: AskNetwork(asn: 48282, owner: "VDSINA-AS", country: "RU", kind: .hosting, source: .offline),
                encryption: .unknown, history: AskHistory(allowed: 0, denied: 0, lastSeen: nil),
                program: AskProgram(path: "/tmp/build-x/.venv/bin/python3", signature: .unsigned, inTemporaryFolder: true),
                assessment: AskAssessment(level: .suspicious, score: 8, signals: [
                    signal(.name, .minus, 2, "The program never looked up a name for this address."),
                    signal(.port, .minus, 2, "Port 8947 is in no list of known services."),
                    signal(.network, .minus, 2, "Rented servers in a country you marked."),
                    signal(.encryption, .info, 0, "netd cannot tell what protocol this is."),
                    signal(.history, .info, 0, "The sandbox has not reached this address before."),
                    signal(.program, .minus, 2, "/tmp/build-x/.venv/bin/python3 runs from a temporary folder."),
                ])
            )
        )
    }
}

@MainActor
@Suite struct AsksModelTests {
    private func lines(_ tiles: [AskTile]) -> [String] {
        tiles.map { "\($0.kind.rawValue) \($0.symbolName) \($0.title) | \($0.subtitle) | \($0.tone.rawValue)" }
    }

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
        #expect(model.asks.ringLabel(ask, at: start.addingTimeInterval(12.3)) == "18")
        #expect(model.asks.ringHelp(ask, at: start.addingTimeInterval(12.3)) == "0:18 left, then deny")
        #expect(model.asks.detail(for: ask) == "node (42) · port 443 · tls")

        let long = AskRequest(host: "api.example.com", port: 443, kind: .transparentTLS, createdAt: start, expiresAt: start.addingTimeInterval(150))
        #expect(model.asks.ringLabel(long, at: start) == "2m")
    }

    @Test func dnsToGoogleLooksNormal() {
        let world = TestWorld()
        defer { world.cleanUp() }
        let model = world.model()
        let ask = AskFixtures.dns
        let panel = model.asks.presentation(for: ask, at: AskFixtures.now)

        #expect(panel.process == "mDNSResponder")
        #expect(panel.iconPath == "/usr/sbin/mDNSResponder")
        #expect(panel.seal == AskSeal(symbolName: "checkmark.seal.fill", tint: .blue, help: "Signed by Apple"))
        #expect(panel.destination == "8.8.8.8:53")
        #expect(panel.subtitle == "dns.google")
        #expect(panel.verdict?.title == "Looks normal")
        #expect(panel.verdict?.symbolName == "checkmark.shield")
        #expect(panel.verdict?.tint == .green)
        #expect(panel.verdict?.hint == nil)
        #expect(panel.verdict?.help == "Score -6: unusual from 3, suspicious from 6")
        #expect(lines(panel.tiles) == [
            "name globe npmjs.org | asked for | plus",
            "port number 53 | DNS | plus",
            "network server.rack Google | US · known service | plus",
            "encryption lock.open Plain | DNS | neutral",
            "history clock 214× | 2 min ago | plus",
            "program checkmark.seal Apple | system | plus",
        ])
        #expect(panel.tiles[1].explanation == "Port 53 carries DNS, as expected.")
        #expect(!panel.prefersDeny)
        #expect(panel.options.map(\.label) == ["Just once", "Always: This address and port", "Always: This address, any port"])
        #expect(panel.options.map(\.target) == ["this request only", "8.8.8.8:53", "8.8.8.8"])
        #expect(model.asks.notificationTitle(for: ask) == "Allow 8.8.8.8:53?")
        #expect(model.asks.notificationBody(for: ask) == "Looks normal · mDNSResponder (310) · port 53 · dns")
    }

    @Test func npmRegistryLooksNormal() {
        let world = TestWorld()
        defer { world.cleanUp() }
        let model = world.model()
        let panel = model.asks.presentation(for: AskFixtures.npm, at: AskFixtures.now)

        #expect(panel.destination == "registry.npmjs.org:443")
        #expect(panel.subtitle == "104.16.27.35")
        #expect(panel.seal?.tint == .blue)
        #expect(lines(panel.tiles) == [
            "name globe npmjs.org | from TLS | plus",
            "port number 443 | HTTPS | plus",
            "network server.rack Cloudflare | US · CDN | neutral",
            "encryption lock Encrypted | TLS | plus",
            "history clock New | first time | neutral",
            "program checkmark.seal Signed | developer | plus",
        ])
        #expect(panel.tiles[2].explanation == "Cloudflare network (AS13335). Many services share it.")
        #expect(panel.options.map(\.label) == ["Just once", "Always: This host", "Always: Whole domain"])
        #expect(panel.options.map(\.target) == ["this request only", "registry.npmjs.org", "*.npmjs.org"])
        #expect(!panel.prefersDeny)
    }

    @Test func unknownPortToMarkedCountryIsSuspicious() async {
        let world = TestWorld()
        defer { world.cleanUp() }
        let model = world.model()
        let ask = AskFixtures.odd
        let panel = model.asks.presentation(for: ask, at: AskFixtures.now)

        #expect(panel.process == "python3")
        #expect(panel.iconPath == "/tmp/build-x/.venv/bin/python3")
        #expect(panel.seal?.symbolName == "exclamationmark.circle.fill")
        #expect(panel.seal?.tint == .orange)
        #expect(panel.destination == "185.142.236.41:8947")
        #expect(panel.subtitle == "vps-41.example-host.ru")
        #expect(panel.verdict?.title == "Suspicious")
        #expect(panel.verdict?.symbolName == "xmark.shield")
        #expect(panel.verdict?.tint == .red)
        #expect(panel.verdict?.hint == "Tap a red tile for the reason")
        #expect(lines(panel.tiles) == [
            "name globe No name | IP only | minus",
            "port number 8947 | unknown | minus",
            "network server.rack VDSINA-AS | RU · hosting | minus",
            "encryption lock.slash Unknown | no TLS seen | neutral",
            "history clock New | first time | neutral",
            "program exclamationmark.triangle Temp folder | unsigned | minus",
        ])
        #expect(panel.tiles[5].explanation == "/tmp/build-x/.venv/bin/python3 runs from a temporary folder.")
        #expect(panel.options.map(\.label) == ["Just once", "Always: This address and port", "Always: This address, any port"])
        #expect(panel.options.map(\.target) == ["this request only", "185.142.236.41:8947", "185.142.236.41"])
        #expect(panel.prefersDeny)

        // Without the safer default, Allow stays the default button.
        await model.settings.setAskDetail(.saferDefault, false)
        #expect(!model.asks.prefersDeny(ask))
        // An unusual request never makes Deny the default.
        await model.settings.setAskDetail(.saferDefault, true)
        var unusual = ask
        unusual.details?.assessment?.level = .unusual
        #expect(!model.asks.prefersDeny(unusual))
        #expect(model.asks.prefersDeny(ask))
    }

    @Test func missingDetailsLeaveTheirTilesOut() {
        let world = TestWorld()
        defer { world.cleanUp() }
        let model = world.model()

        var ask = AskFixtures.odd
        ask.details?.service = nil
        ask.details?.reverseName = nil
        ask.details?.program = nil
        ask.details?.assessment = nil
        let panel = model.asks.presentation(for: ask, at: AskFixtures.now)
        #expect(panel.tiles.map(\.kind) == [.name, .network, .encryption, .history])
        #expect(panel.tiles.allSatisfy { $0.tone == .neutral })
        #expect(panel.tiles[0].explanation == "The program never looked up a name for this address.")
        #expect(panel.tiles[1].explanation == "VDSINA-AS (AS48282): rented servers in Russia.")
        #expect(panel.verdict == nil)
        #expect(panel.seal == nil)
        #expect(panel.subtitle == nil)
        #expect(!panel.prefersDeny)

        // An older netd sends no details: header, ring and buttons only.
        let bare = AskRequest(host: "cdn.jsdelivr.net", port: 443, kind: .transparentTLS, createdAt: AskFixtures.now, expiresAt: AskFixtures.now.addingTimeInterval(30))
        let plain = model.asks.presentation(for: bare, at: AskFixtures.now)
        #expect(plain.process == "Unknown program")
        #expect(plain.iconPath == nil)
        #expect(plain.tiles.isEmpty)
        #expect(plain.verdict == nil)
        #expect(plain.destination == "cdn.jsdelivr.net:443")
        #expect(plain.options.map(\.target) == ["this request only", "cdn.jsdelivr.net", "*.jsdelivr.net"])
        #expect(model.asks.notificationBody(for: bare) == "port 443 · tls")
    }

    @Test func formattingDetails() {
        #expect(AskFormat.endpoint("2001:db8::1", 8947) == "[2001:db8::1]:8947")
        #expect(AskFormat.endpoint("example.com", nil) == "example.com")
        #expect(AskFormat.iconPath("/Applications/Ghostty.app/Contents/MacOS/ghostty") == "/Applications/Ghostty.app")
        #expect(AskFormat.iconPath("/opt/homebrew/bin/node") == "/opt/homebrew/bin/node")
        #expect(AskFormat.shortOwner("GOOGLE - Google LLC") == "Google")
        #expect(AskFormat.shortOwner("CLOUDFLARENET - Cloudflare, Inc.") == "Cloudflare")
        #expect(AskFormat.shortOwner("Hetzner Online GmbH") == "Hetzner Online")
        #expect(AskFormat.hasDomain("registry.npmjs.org"))
        #expect(!AskFormat.hasDomain("185.142.236.41"))
        #expect(!AskFormat.hasDomain("localhost"))
        #expect(AskFormat.scopeLabel(.host, host: "db.internal.example", port: 5432) == "This host, any port")
        #expect(AskFormat.scopeLabel(.hostAndPort, host: "db.internal.example", port: 5432) == "This host and port")
        #expect(AskFormat.scopeLabel(.host, host: "203.0.113.9", port: 443) == "This address")

        let history = AskFormat.historyLines(AskHistory(allowed: 3, denied: 2, lastSeen: AskFixtures.now.addingTimeInterval(-7200)), at: AskFixtures.now)
        #expect(history.0 == "3×")
        #expect(history.1 == "2× denied")
        #expect(history.2 == "Allowed 3 times before, denied 2 times, last 2 h ago.")
        let denied = AskFormat.historyLines(AskHistory(allowed: 0, denied: 1, lastSeen: nil), at: AskFixtures.now)
        #expect(denied.0 == "1× denied")
        #expect(denied.1 == "before")

        #expect(Format.ago(30) == "just now")
        #expect(Format.ago(3 * 86400) == "3 d ago")
        #expect(Format.grouped(512_034) == "512,034")
        #expect(Format.grouped(999) == "999")
    }

    @Test func menuChoiceAndButtonGiveTheDecision() {
        #expect(AsksModel.decision(allow: true, remembered: nil) == .allowOnce)
        #expect(AsksModel.decision(allow: false, remembered: nil) == .denyOnce)
        #expect(AsksModel.decision(allow: true, remembered: .domain) == .allowAlways)
        #expect(AsksModel.decision(allow: false, remembered: .hostAndPort) == .denyAlways)
    }

    @Test func answerSendsDecisionAndScopeThroughNetd() async throws {
        let world = TestWorld()
        defer { world.cleanUp() }
        let now = world.clock.current.get()
        let first = AskRequest(host: "cdn.jsdelivr.net", port: 443, kind: .transparentTLS, createdAt: now, expiresAt: now.addingTimeInterval(30))
        let second = AskRequest(host: "registry.npmjs.org", port: nil, kind: .dns, createdAt: now.addingTimeInterval(1), expiresAt: now.addingTimeInterval(31))
        var third = AskFixtures.odd
        third.createdAt = now.addingTimeInterval(2)
        third.expiresAt = now.addingTimeInterval(32)
        let client = FakeNetdClient(pending: [second, first, third])
        world.netd.queue.set([.client(client)])
        let model = world.model()
        model.netd.start()
        defer { model.netd.stop() }
        #expect(await eventually { model.asks.pending.count == 3 })
        #expect(model.asks.isListening)
        #expect(model.asks.pending.map(\.host) == ["cdn.jsdelivr.net", "registry.npmjs.org", "185.142.236.41"])
        #expect(model.asks.detail(for: second) == "DNS lookup · dns")

        #expect(model.asks.rememberTitle(for: first) == "Just once")
        #expect(model.asks.rememberHelp(for: first) == "Answer only this request")
        model.asks.setRememberedScope(.domain, for: first)
        #expect(model.asks.rememberTitle(for: first) == "Always")
        #expect(model.asks.rememberHelp(for: first) == "Rule: *.jsdelivr.net")
        await model.asks.answer(first, allow: true)
        #expect(client.answers.get() == [AskAnswer(id: first.id, decision: .allowAlways, scope: .domain)])
        #expect(model.asks.message?.title == "Allow always: cdn.jsdelivr.net (rule *.jsdelivr.net)")
        #expect(model.asks.pending.map(\.host) == ["registry.npmjs.org", "185.142.236.41"])
        #expect(model.asks.rememberedScope(for: first) == nil)

        await model.asks.answer(second, allow: false)
        #expect(client.answers.get().last == AskAnswer(id: second.id, decision: .denyOnce, scope: .host))

        model.asks.setRememberedScope(.hostAndPort, for: third)
        await model.asks.answer(third, allow: false)
        #expect(client.answers.get().last == AskAnswer(id: third.id, decision: .denyAlways, scope: .hostAndPort))
        #expect(model.asks.message?.title == "Deny always: 185.142.236.41 (rule 185.142.236.41:8947)")
        #expect(model.asks.pending.isEmpty)
        #expect(model.menuBar.pendingAsks == 0)
    }

    @Test func notificationAlwaysUsesTheMostSpecificScope() async throws {
        let world = TestWorld()
        defer { world.cleanUp() }
        let ask = AskFixtures.odd
        let client = FakeNetdClient(pending: [ask])
        world.netd.queue.set([.client(client)])
        let model = world.model()
        model.netd.start()
        defer { model.netd.stop() }
        #expect(await eventually { model.asks.pending.count == 1 })
        await model.asks.answer(ask, .denyAlways)
        #expect(client.answers.get() == [AskAnswer(id: ask.id, decision: .denyAlways, scope: .hostAndPort)])
    }

    @Test func answeringWhileNetdIsDownIsAnError() async {
        let world = TestWorld()
        defer { world.cleanUp() }
        let model = world.model()
        let now = world.clock.current.get()
        let ask = AskRequest(host: "x.example", port: 443, kind: .transparentTLS, createdAt: now, expiresAt: now.addingTimeInterval(30))
        await model.asks.answer(ask, allow: true)
        #expect(model.asks.message?.kind == .warning)
        #expect(model.asks.message?.suggestedCommand == "svctl netd install")
    }
}
