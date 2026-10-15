import Foundation
import SandvaultCore
import Testing
@testable import SandvaultAppModel

@MainActor
@Suite struct WebsitesModelTests {
    /// Ask mode with one rule of each kind, and a record for every state.
    private func makeWorld(rules: [DomainRule], records: (Date) -> [ConnectionRecord], pending: (Date) -> [AskRequest] = { _ in [] }) throws -> (TestWorld, AppModel, FakeNetdClient) {
        let world = TestWorld()
        try world.store.save(AppConfig(network: NetworkPolicy(mode: .proxyOnly, defaultAction: .ask, domainRules: rules)))
        let now = world.clock.current.get()
        let client = FakeNetdClient(pending: pending(now), recent: records(now))
        world.netd.queue.set([.client(client)])
        return (world, world.model(), client)
    }

    @Test func eachWebsiteShowsWhatDecidesItNow() async throws {
        let (world, model, _) = try makeWorld(
            rules: [DomainRule(pattern: "*.sentry.io", action: .allow), DomainRule(pattern: "telemetry.nextjs.org", action: .deny)],
            records: { now in [
                record("o42.sentry.io", .allowed, at: now.addingTimeInterval(-60), process: "claude"),
                record("telemetry.nextjs.org", .denied, at: now.addingTimeInterval(-50)),
                record("registry.npmjs.org", .allowed, at: now.addingTimeInterval(-40)),
                record("registry.npmjs.org", .allowed, at: now.addingTimeInterval(-35), process: "npm"),
                record("cdn.example.com", .askedAllowed, at: now.addingTimeInterval(-30)),
                record("ads.example.net", .timedOut, at: now.addingTimeInterval(-20), process: "curl"),
                record("plain.example.org", .denied, at: now.addingTimeInterval(-10)),
            ] },
            pending: { now in [AskRequest(host: "api.segment.io", port: 443, kind: .transparentTLS, process: "node", createdAt: now, expiresAt: now.addingTimeInterval(30))] }
        )
        defer { world.cleanUp() }
        model.netd.start()
        defer { model.netd.stop() }
        #expect(await eventually { model.netd.records.count == 7 && model.asks.pending.count == 1 })

        let rows = model.websites.allRows
        #expect(rows.map(\.host) == [
            "api.segment.io", "plain.example.org", "ads.example.net", "cdn.example.com", "registry.npmjs.org", "telemetry.nextjs.org", "o42.sentry.io",
        ])
        #expect(rows.map(\.state) == [.waiting, .blocked, .asked, .asked, .allowedByBasics, .blocked, .allowedByYou])
        #expect(rows[0].processes == ["node"] && rows[0].count == 0)
        #expect(rows[4].basics?.id == "npm")
        #expect(rows[4].processes == ["node", "npm"] && rows[4].count == 2)
        #expect(rows[4].note(mode: .easy) == "Part of developer basics (npm).")
        #expect(rows[6].note(mode: .easy) == "You allowed *.sentry.io.")
        #expect(rows[5].note(mode: .easy) == "You blocked telemetry.nextjs.org.")
        #expect(rows[1].note(mode: .easy) == "Blocked by your protection level.")
        #expect(rows[2].note(mode: .easy) == "Nobody answered in time, so it was blocked. It asks again next time.")
        #expect(rows[3].note(mode: .easy) == "You allowed it once. It asks again next time.")
        #expect(model.websites.summary == "7 websites · 3 blocked · 1 waiting")
        #expect(model.websites.hint == "Allow and Block are remembered. A website without a choice waits for your answer.")
        #expect(model.websites.basicsSummary == "GitHub, npm, Python packages and 5 more")

        // Allowed: your rule, developer basics and the once-allowed; Blocked: rules, the protection level and timeouts.
        model.websites.filter = .allowed
        #expect(model.websites.rows.map(\.host) == ["cdn.example.com", "registry.npmjs.org", "o42.sentry.io"])
        model.websites.filter = .blocked
        #expect(model.websites.rows.map(\.host) == ["plain.example.org", "ads.example.net", "telemetry.nextjs.org"])
        model.websites.filter = .all
        model.websites.search = "CURL"
        #expect(model.websites.rows.map(\.host) == ["ads.example.net"])
        model.websites.search = "example"
        #expect(model.websites.rows.count == 3)
    }

    @Test func watchAllowsWhatNoRuleDecides() async throws {
        let world = TestWorld()
        defer { world.cleanUp() }
        try world.store.save(AppConfig(network: NetworkPolicy(mode: .watch)))
        let now = world.clock.current.get()
        world.netd.queue.set([.client(FakeNetdClient(recent: [record("example.com", .allowed, at: now)]))])
        let model = world.model()
        model.netd.start()
        defer { model.netd.stop() }
        #expect(await eventually { model.netd.records.count == 1 })
        let row = try #require(model.websites.allRows.first)
        #expect(row.state == .allowed && row.canAllow && row.canBlock)
        #expect(model.websites.hint.hasPrefix("Watch lets every website through."))
    }

    @Test func detailsGrowWithTheMode() throws {
        let now = Date(timeIntervalSince1970: 1_800_000_000)
        let records = [
            ConnectionRecord(timestamp: now, kind: .dns, host: "api.example.com", decision: .allowed, process: "node", dnsAnswers: ["203.0.113.5", "203.0.113.6", "203.0.113.7"]),
            record("api.example.com", .allowed, port: 443, at: now.addingTimeInterval(1)),
            record("api.example.com", .allowed, port: 8443, at: now.addingTimeInterval(2)),
            ConnectionRecord(timestamp: now, kind: .dns, host: "lookup.example.org", decision: .allowed, process: "dig"),
        ]
        let rows = WebsiteRow.rows(records, pending: [], policy: NetworkPolicy(mode: .watch))
        let api = try #require(rows.first { $0.host == "api.example.com" })
        #expect(api.detail(mode: .easy) == "node · 3 times")
        #expect(api.detail(mode: .advanced) == "node · 3 times · ports 443, 8443")
        #expect(api.detail(mode: .expert) == "node · 3 times · ports 443, 8443 · 203.0.113.5, 203.0.113.6 +1")
        #expect(api.lastPort == 8443 && !api.lookupOnly)
        // Developer basics cover only the web ports; 8443 is not one of them.
        let lookup = try #require(rows.first { $0.host == "lookup.example.org" })
        #expect(lookup.lookupOnly && lookup.detail(mode: .advanced) == "Looked up only · dig · 1 time")
        let github = WebsiteRow.rows([record("github.com", .allowed, port: 22, at: now)], pending: [], policy: NetworkPolicy(mode: .proxyOnly))
        #expect(github.first?.state == .allowed && github.first?.basics == nil)
        let web = WebsiteRow.rows([record("github.com", .allowed, port: 443, at: now)], pending: [], policy: NetworkPolicy(mode: .proxyOnly))
        #expect(web.first?.state == .allowedByBasics && web.first?.canAllow == false)
        // Developer basics off: the same record is allowed by the level, not by the basics.
        var off = NetworkPolicy(mode: .proxyOnly)
        off.developerBasics.enabled = false
        #expect(WebsiteRow.rows([record("github.com", .allowed, port: 443, at: now)], pending: [], policy: off).first?.state == .allowed)
    }

    @Test func allowAndBlockWriteRules() async throws {
        let (world, model, _) = try makeWorld(
            rules: [DomainRule(pattern: "tracker.example.com", action: .deny), DomainRule(pattern: "*.example.org", action: .allow)],
            records: { now in [
                record("tracker.example.com", .denied, at: now.addingTimeInterval(-30)),
                record("cdn.unknown.net", .denied, at: now.addingTimeInterval(-20)),
                record("www.example.org", .allowed, at: now.addingTimeInterval(-10)),
            ] }
        )
        defer { world.cleanUp() }
        model.netd.start()
        defer { model.netd.stop() }
        #expect(await eventually { model.netd.records.count == 3 })
        func row(_ host: String) throws -> WebsiteRow { try #require(model.websites.allRows.first { $0.host == host }) }

        // Your exact deny rule flips; a wider allow would lose against it.
        await model.websites.allow(try row("tracker.example.com"))
        #expect(model.editor.config.network.domainRules.first { $0.pattern == "tracker.example.com" }?.action == .allow)
        #expect(model.websites.message?.title == "Allowed tracker.example.com")
        #expect(try row("tracker.example.com").state == .allowedByYou)

        // Without a rule, Allow covers the whole domain like Activity does.
        await model.websites.allow(try row("cdn.unknown.net"))
        #expect(model.editor.config.network.domainRules.contains { $0.pattern == "*.unknown.net" && $0.action == .allow })

        // Blocking one site under an allowed domain adds an exact deny, which wins.
        await model.websites.block(try row("www.example.org"))
        #expect(model.editor.config.network.domainRules.contains { $0.pattern == "www.example.org" && $0.action == .deny })
        #expect(model.editor.config.network.domainRules.first { $0.pattern == "*.example.org" }?.action == .allow)
        #expect(try row("www.example.org").state == .blocked)
        #expect(try row("www.example.org").canBlock == false)
        #expect(model.websites.message?.title == "Blocked www.example.org")
    }

    @Test func allowAnswersAWaitingRequest() async throws {
        let (world, model, client) = try makeWorld(rules: [], records: { _ in [] }, pending: { now in
            [AskRequest(host: "api.segment.io", port: 443, kind: .transparentTLS, process: "node", createdAt: now, expiresAt: now.addingTimeInterval(30))]
        })
        defer { world.cleanUp() }
        model.netd.start()
        defer { model.netd.stop() }
        #expect(await eventually { model.asks.pending.count == 1 })
        let row = try #require(model.websites.allRows.first)
        #expect(row.state == .waiting && !row.isAllowed && !row.isBlocked)
        await model.websites.allow(row)
        #expect(client.answers.get().map(\.decision) == [.allowAlways])
        #expect(client.answers.get().map(\.scope) == [.host])
        #expect(model.editor.config.network.domainRules.isEmpty)
    }

    @Test func rulesAreListedAndRemoved() async throws {
        let (world, model, _) = try makeWorld(
            rules: [DomainRule(pattern: "*", action: .deny), DomainRule(pattern: "*.npmjs.org", action: .allow), DomainRule(pattern: "nas.local", action: .allow, port: 22)],
            records: { _ in [] }
        )
        defer { world.cleanUp() }
        let rules = model.websites.rules
        #expect(rules.map { $0.websiteTitle(mode: .easy) } == ["Every other website", "*.npmjs.org", "nas.local"])
        #expect(rules.map { $0.websiteTitle(mode: .advanced) } == ["Every other website", "*.npmjs.org", "nas.local:22"])
        #expect(rules.map(\.websiteScope) == ["Websites without a rule of their own", "npmjs.org and every subdomain", "Only this website"])
        #expect(rules.map(\.websiteActionTitle) == ["Blocked", "Allowed", "Allowed"])

        await model.websites.removeRule(rules[1])
        #expect(model.websites.rules.map(\.pattern) == ["*", "nas.local"])
        #expect(model.websites.message?.title == "Removed *.npmjs.org")
        await model.websites.removeRule(rules[1])
        #expect(model.websites.message?.title == "*.npmjs.org was already removed")
        #expect(model.websites.rules.count == 2)
    }

    @Test func hintFollowsTheProtection() async throws {
        let world = TestWorld()
        defer { world.cleanUp() }
        try world.store.save(AppConfig(network: NetworkPolicy(mode: .off)))
        let model = world.model()
        #expect(model.websites.hint == "Protection is off, so websites are not listed. Choose Watch or Ask on Home.")
        try world.store.save(AppConfig(network: NetworkPolicy(mode: .proxyOnly)))
        model.editor.reload()
        #expect(model.websites.hint.hasPrefix("sandvault-netd is not running"))
    }
}

/// The ask panel per interface mode (D53).
@MainActor
@Suite struct AskModeTests {
    @Test func easyShowsThreeTilesAndTwoChoices() {
        let world = TestWorld()
        defer { world.cleanUp() }
        let model = world.model()
        let ask = AskFixtures.npm
        let panel = model.asks.presentation(for: ask, at: AskFixtures.now, mode: .easy)
        #expect(panel.tiles.map(\.kind) == [.name, .program, .history])
        #expect(panel.destination == "registry.npmjs.org")
        #expect(panel.subtitle == "A website the sandbox has not used before.")
        #expect(panel.technical == nil)
        #expect(panel.advice == "Allow it if you expect node to use this website. Unsure? Deny.")
        #expect(panel.options.map(\.label) == ["Only this time", "Always for this site"])
        #expect(panel.options.map(\.target) == ["Asks again next time", "registry.npmjs.org"])
        #expect(model.asks.rememberTitle(for: ask, mode: .easy) == "Only this time")
        model.asks.setRememberedScope(.host, for: ask)
        #expect(model.asks.rememberTitle(for: ask, mode: .easy) == "Always for this site")
        // A choice Easy does not offer (made in another mode) still reads sensibly.
        model.asks.setRememberedScope(.domain, for: ask)
        #expect(model.asks.rememberTitle(for: ask, mode: .easy) == "Always")
        #expect(model.asks.rememberTitle(for: ask, mode: .advanced) == "Always for *.npmjs.org")
    }

    @Test func easyFillsUpWhenDetailsAreMissing() {
        var ask = AskFixtures.dns
        ask.details?.name = nil
        ask.details?.program = nil
        let world = TestWorld()
        defer { world.cleanUp() }
        let panel = world.model().asks.presentation(for: ask, at: AskFixtures.now, mode: .easy)
        #expect(panel.tiles.map(\.kind) == [.history, .port, .network])
        #expect(panel.subtitle == nil)
        #expect(panel.destination == "8.8.8.8")
        #expect(panel.options.map(\.label) == ["Only this time", "Always for this address"])
        #expect(panel.options.map(\.target) == ["Asks again next time", "8.8.8.8"])
    }

    @Test func advancedAndExpertShowEverything() {
        let world = TestWorld()
        defer { world.cleanUp() }
        let model = world.model()
        let advanced = model.asks.presentation(for: AskFixtures.npm, at: AskFixtures.now, mode: .advanced)
        #expect(advanced.tiles.count == 6)
        #expect(advanced.destination == "registry.npmjs.org:443")
        #expect(advanced.technical == nil && advanced.advice == nil)
        #expect(advanced.options.map(\.label) == ["Only this time", "Always for this site", "Always for *.npmjs.org"])
        #expect(advanced.options.map(\.target) == ["Asks again next time", "registry.npmjs.org", "Every subdomain"])

        let expert = model.asks.presentation(for: AskFixtures.odd, at: AskFixtures.now, mode: .expert)
        #expect(expert.tiles.count == 6)
        #expect(expert.technical == "185.142.236.41:8947 · tls · pid 777")
        #expect(expert.options.map(\.label) == ["Only this time", "Always for this address and port", "Always for this address, any port"])
        #expect(expert.options.map(\.target) == ["Asks again next time", "185.142.236.41:8947", "185.142.236.41"])
        #expect(AskFormat.technicalLine(AskFixtures.npm) == "registry.npmjs.org:443 · tls · pid 4242 · 104.16.27.35")
    }

    @Test func notificationsSpeakPlainlyInEasy() {
        let world = TestWorld()
        defer { world.cleanUp() }
        let asks = world.model().asks
        let ask = AskFixtures.odd
        #expect(asks.notificationTitle(for: ask, mode: .easy) == "Allow 185.142.236.41?")
        #expect(asks.notificationBody(for: ask, mode: .easy) == "python3 wants to connect · Suspicious")
        #expect(asks.notificationTitle(for: ask, mode: .advanced) == "Allow 185.142.236.41:8947?")
        #expect(asks.notificationBody(for: ask, mode: .expert) == "Suspicious · python3 (777) · port 8947 · tls")
        #expect(AsksModel.notificationDecisions(for: .easy) == [.allowOnce, .denyOnce])
        #expect(AsksModel.notificationDecisions(for: .advanced) == [.allowOnce, .allowAlways, .denyOnce, .denyAlways])
    }
}
