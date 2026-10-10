import Foundation
import SandvaultCore
import Testing
@testable import SandvaultAppModel

@Suite struct WebRequestRowTests {
    static let start = Date(timeIntervalSince1970: 1_800_000_000)

    static func inspected(at offset: Double = 0) -> ConnectionRecord {
        ConnectionRecord(
            timestamp: start.addingTimeInterval(offset), kind: .transparentTLS, host: "api.anthropic.com", port: 443, decision: .allowed,
            pid: 7, process: "claude", bytesIn: 20_000, bytesOut: 3_000, durationMs: 4_000, inspected: true,
            http: [
                HTTPSummary(
                    method: "POST", url: "https://api.anthropic.com/v1/messages?beta=true", status: 200,
                    requestHeaders: [["content-type", "application/json"], ["x-api-key", "<redacted>"]],
                    responseHeaders: [["content-type", "text/event-stream"]], startedAt: start.addingTimeInterval(offset + 1),
                    durationMs: 2_310, requestBytes: 512, responseBytes: 18_400
                ),
                HTTPSummary(method: "GET", url: "https://api.anthropic.com/v1/models", status: 404, startedAt: start.addingTimeInterval(offset + 2), durationMs: 88, responseBytes: 21),
            ]
        )
    }

    @Test func oneRowPerRequestNewestFirstWithoutDNSAndTCP() {
        let encrypted = ConnectionRecord(
            timestamp: Self.start.addingTimeInterval(10), kind: .transparentTLS, host: "github.com", port: 443, decision: .allowed,
            process: "git", bytesIn: 4_000_000, bytesOut: 200_000, durationMs: 3_040
        )
        let blocked = ConnectionRecord(
            timestamp: Self.start.addingTimeInterval(20), kind: .transparentHTTP, host: "example-updates.net", port: 80, decision: .denied,
            ruleID: UUID(), process: "curl"
        )
        let dns = ConnectionRecord(timestamp: Self.start.addingTimeInterval(30), kind: .dns, host: "github.com", decision: .allowed)
        let tcp = ConnectionRecord(timestamp: Self.start.addingTimeInterval(40), kind: .transparentTCP, host: "10.0.0.1", port: 22, decision: .allowed)

        let rows = WebRequestRow.rows([Self.inspected(), encrypted, blocked, dns, tcp])
        #expect(rows.map(\.host) == ["example-updates.net", "github.com", "api.anthropic.com", "api.anthropic.com"])

        let blockedRow = rows[0]
        #expect(blockedRow.statusText == "Blocked" && blockedRow.statusTint == .red)
        #expect(blockedRow.resultText == "Blocked by rule")
        #expect(blockedRow.visibility == .connectionOnly)
        #expect(blockedRow.subtitle == "curl · plain HTTP")
        #expect(blockedRow.curl() == nil)

        let lock = rows[1]
        #expect(lock.visibility == .encrypted)
        #expect(lock.statusText == "Encrypted" && lock.statusTint == .gray)
        #expect(lock.subtitle == "git · contents not visible")
        #expect(lock.method == nil && lock.path == nil && lock.isTLS)
        #expect(lock.sizeText == "4.2 MB" && lock.durationText == "3.04 s")
        #expect(lock.resultText == "Connected")

        let models = rows[2]
        #expect(models.method == "GET" && models.path == "/v1/models")
        #expect(models.statusText == "404" && models.statusTint == .orange)
        #expect(models.resultText == "404 Not Found")
        #expect(models.durationText == "88 ms" && models.sizeText == "21 B")

        let messages = rows[3]
        #expect(messages.path == "/v1/messages?beta=true")
        #expect(messages.statusTint == .green && messages.resultText == "200 OK")
        #expect(messages.sizeDetail == "18.4 kB, sent 512 B")
        #expect(messages.subtitle == "claude")
    }

    @Test func filterMatchesHostAndPath() {
        let other = ConnectionRecord(kind: .explicitProxy, host: "registry.npmjs.org", port: 80, decision: .allowed, process: "node",
                                     http: [HTTPSummary(method: "GET", url: "http://registry.npmjs.org/left-pad", status: 200)])
        let records = [Self.inspected(), other]
        #expect(WebRequestRow.rows(records, filter: "NPMJS").map(\.path) == ["/left-pad"])
        #expect(WebRequestRow.rows(records, filter: "messages").map(\.path) == ["/v1/messages?beta=true"])
        #expect(WebRequestRow.rows(records, filter: " ").count == 3)
        #expect(WebRequestRow.rows(records, filter: "left").first?.subtitle == "node · plain HTTP")
    }

    @Test func pathsOfAbsoluteURLs() {
        #expect(WebRequestRow.path(of: "https://example.com") == "/")
        #expect(WebRequestRow.path(of: "https://example.com:8443/a/b?c=1") == "/a/b?c=1")
        #expect(WebRequestRow.path(of: "http://example.com?x=1") == "/?x=1")
    }

    @Test func requestsWithoutStartTimeKeepTheirOrder() {
        var record = Self.inspected()
        record.http = record.http.map { summary in
            var copy = summary
            copy.startedAt = nil
            return copy
        }
        #expect(WebRequestRow.rows([record]).map(\.method) == ["GET", "POST"])
    }

    @Test func curlUsesMethodURLAndHeaders() {
        let summary = HTTPSummary(
            method: "POST", url: "https://api.example.com/v1/it's",
            requestHeaders: [["Host", "api.example.com"], ["Content-Type", "application/json"], ["Authorization", "<redacted>"], ["Accept-Encoding", "gzip"], ["Content-Length", "2"]]
        )
        #expect(CurlCommand.make(summary, body: "{}") == """
            curl -X POST 'https://api.example.com/v1/it'\\''s' -H 'Content-Type: application/json' -H 'Authorization: <redacted>' --compressed --data-binary '{}'
            """)
        #expect(CurlCommand.make(HTTPSummary(method: "GET", url: "http://a.example/")) == "curl 'http://a.example/'")
        #expect(CurlCommand.make(HTTPSummary(method: "HEAD", url: "http://a.example/")) == "curl --head 'http://a.example/'")
    }

    @Test func contentsAsTextBinaryAndTruncated() {
        let text = StoredContent(contentType: "application/json", size: 10, storedBytes: 10, binary: false)
        #expect(ContentLoad.make(text, Data("{\"a\": 1}\n".utf8)) == .text(text, "{\"a\": 1}\n"))
        #expect(ContentLoad.truncationNote(text) == nil)

        let notUTF8 = StoredContent(contentType: nil, size: 2, storedBytes: 2, binary: false)
        #expect(ContentLoad.make(notUTF8, Data([0xFF, 0xFE])) == .binary(notUTF8))

        let archive = StoredContent(contentType: "application/octet-stream", size: 1_900_000, storedBytes: 1_048_576, binary: true)
        #expect(ContentLoad.binaryNote(archive) == "Binary (application/octet-stream), 1.9 MB. Not shown.")
        #expect(ContentLoad.truncationNote(archive) == "Showing the first 1.0 MB of 1.9 MB.")

        let cut = StoredContent(contentType: "text/plain", size: nil, storedBytes: 300, binary: false)
        #expect(ContentLoad.truncationNote(cut) == "The transfer ended early; this is what arrived (300 B).")
    }

    @Test func millisecondFormatting() {
        #expect(Format.milliseconds(410) == "410 ms")
        #expect(Format.milliseconds(2_310) == "2.31 s")
        #expect(Format.milliseconds(14_200) == "14.2 s")
        #expect(Format.milliseconds(185_000) == "3m 05s")
    }
}

@MainActor
@Suite struct WebTrafficModelTests {
    @Test func selectingARowLoadsItsContentsOnceAndCopiesCurlWithTheBody() async throws {
        let world = TestWorld()
        defer { world.cleanUp() }
        try world.store.save(AppConfig(network: NetworkPolicy(mode: .watch, inspection: InspectionSettings(enabled: true))))
        let requestBody = StoredContent(contentType: "application/json", size: 7, storedBytes: 7, binary: false)
        let responseBody = StoredContent(contentType: "image/png", size: 2_000, storedBytes: 2_000, binary: true)
        let missing = StoredContent(contentType: "text/plain", size: 5, storedBytes: 5, binary: false)
        var record = WebRequestRowTests.inspected()
        record.http[0].requestContent = requestBody
        record.http[0].responseContent = responseBody
        record.http[1].responseContent = missing
        let client = FakeNetdClient(recent: [record])
        client.stored.set([requestBody.id: (requestBody, Data("{\"q\":1}".utf8)), responseBody.id: (responseBody, Data([0x89, 0x50]))])
        world.netd.queue.set([.client(client)])
        let model = world.model()
        model.netd.start()
        defer { model.netd.stop() }
        #expect(await eventually { model.netd.isConnected })

        let activity = model.activity
        #expect(activity.webSummary == "2 requests")
        let row = try #require(activity.webRows.last)
        activity.selectedRequestID = row.id
        #expect(activity.selectedRequest?.path == "/v1/messages?beta=true")

        await activity.loadContent(requestBody)
        await activity.loadContent(requestBody)
        await activity.loadContent(responseBody)
        #expect(client.contentRequests.get() == [requestBody.id, responseBody.id])
        #expect(activity.content(requestBody) == .text(requestBody, "{\"q\":1}"))
        #expect(activity.content(responseBody) == .binary(responseBody))
        #expect(activity.curl(row)?.hasSuffix("--data-binary '{\"q\":1}'") == true)

        // A failed fetch is shown and tried again next time.
        await activity.loadContent(missing)
        guard case .failed? = activity.content(missing) else { Issue.record("expected a failure"); return }
        await activity.loadContent(missing)
        #expect(client.contentRequests.get().filter { $0 == missing.id }.count == 2)

        activity.showAll(from: "api.anthropic.com")
        #expect(activity.webFilter == "api.anthropic.com" && activity.selectedRequestID == nil)
    }

    @Test func withoutNetdContentsFailWithAReason() async throws {
        let world = TestWorld()
        defer { world.cleanUp() }
        let activity = world.model().activity
        let meta = StoredContent(contentType: nil, size: 1, storedBytes: 1, binary: false)
        await activity.loadContent(meta)
        #expect(activity.content(meta) == .failed("sandvault-netd is not running."))
        #expect(ActivityModel.contentError(SandvaultError.notImplemented("stored contents")) == "This netd does not keep contents yet.")
    }

    @Test func hintsNotesAndInspectingAHost() async throws {
        let world = TestWorld()
        defer { world.cleanUp() }
        let deny = DomainRule(pattern: "example-updates.net", action: .deny)
        try world.store.save(AppConfig(network: NetworkPolicy(mode: .watch, domainRules: [deny])))
        let model = world.model()
        let activity = model.activity

        #expect(activity.webHint == "sandvault-netd is not running: nothing is recorded.")
        let blocked = try #require(WebRequestRow.make(ConnectionRecord(kind: .transparentHTTP, host: "example-updates.net", port: 80, decision: .denied, ruleID: deny.id)).first)
        #expect(activity.blockedNote(blocked) == "Blocked by your rule Deny example-updates.net. Nothing left the Mac.")
        let timedOut = try #require(WebRequestRow.make(ConnectionRecord(kind: .transparentTLS, host: "x.example", decision: .timedOut)).first)
        #expect(activity.blockedNote(timedOut) == "Nobody answered the request in time. Nothing left the Mac.")

        let lock = try #require(WebRequestRow.make(ConnectionRecord(kind: .transparentTLS, host: "github.com", port: 443, decision: .allowed)).first)
        #expect(activity.encryptedNote(lock).hasSuffix("Turn on Look inside HTTPS to see the requests."))
        #expect(!activity.canInspect("github.com"))

        // Turning inspection on stays the user's choice (Settings > Recording); then Watch offers one host.
        await model.recording.setInspection(true)
        #expect(activity.inspectionEnabled)
        #expect(activity.canInspect("github.com"))
        await activity.inspect("github.com")
        let rule = try #require(try world.store.load().network.domainRules.first { $0.pattern == "github.com" })
        #expect(rule.inspect && rule.action == .allow)
        #expect(!activity.canInspect("github.com"))
    }

    @Test func recordingRequestsOffIsExplained() async throws {
        let world = TestWorld()
        defer { world.cleanUp() }
        try world.store.save(AppConfig(network: NetworkPolicy(mode: .proxyOnly, recording: WebRecordingSettings(requests: false))))
        world.netd.queue.set([.client(FakeNetdClient())])
        let model = world.model()
        model.netd.start()
        defer { model.netd.stop() }
        #expect(await eventually { model.netd.isConnected })
        #expect(model.activity.webHint == "Recording requests is off in Settings > Recording; only connections are listed.")
    }

    @Test func theLinkKeepsSummariesBounded() {
        let many = (0..<30).map { index in
            ConnectionRecord(kind: .transparentTLS, host: "h\(index)", decision: .allowed, http: Array(repeating: HTTPSummary(method: "GET", url: "https://h/"), count: 1_000))
        }
        let kept = NetdLink.trimmed(many)
        #expect(kept.reduce(0) { $0 + $1.http.count } <= NetdLink.summaryLimit)
        #expect(kept.last?.host == "h29")
        #expect(NetdLink.trimmed(Array(many.prefix(3))).count == 3)
    }
}
