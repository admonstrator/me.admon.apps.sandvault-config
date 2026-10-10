import Foundation
import NIOCore
import NIOHTTP1
import NIOSSL
import SandvaultCore
import Testing
@testable import SandvaultNet

@Suite struct BodyCaptureTests {
    func buffer(_ text: String) -> ByteBuffer { ByteBufferAllocator().buffer(string: text) }

    @Test func keepsUpToTheCapAndCountsEverything() throws {
        var capture = BodyCapture(headers: ["Content-Type": "text/plain"], limit: 5)
        capture.append(buffer("hel"))
        capture.append(buffer("lo world"))
        #expect(capture.size == 11)
        let (meta, data) = try #require(capture.stored(complete: true))
        #expect(data == Data("hello".utf8))
        #expect(meta.size == 11 && meta.storedBytes == 5 && meta.truncated && !meta.binary)
        #expect(meta.contentType == "text/plain")
    }

    @Test func aBodyUnderTheCapIsComplete() throws {
        var capture = BodyCapture(headers: [:], limit: 100)
        capture.append(buffer("{\"a\":1}"))
        let (meta, data) = try #require(capture.stored(complete: true))
        #expect(data == Data("{\"a\":1}".utf8) && meta.size == 7 && !meta.truncated && !meta.binary)
    }

    @Test func anEarlyEndHasNoSize() throws {
        var capture = BodyCapture(headers: [:], limit: 100)
        capture.append(buffer("partial"))
        let (meta, _) = try #require(capture.stored(complete: false))
        #expect(meta.size == nil && meta.truncated)
    }

    @Test func emptyBodiesAndCountingOnlyKeepNothing() {
        #expect(BodyCapture(headers: [:], limit: 100).stored(complete: true) == nil)
        var counting = BodyCapture(headers: [:], limit: nil)
        counting.append(buffer("not kept"))
        #expect(counting.size == 8)
        #expect(counting.stored(complete: true) == nil)
    }

    @Test(arguments: [
        ("image/png", nil, "PNG", true),
        ("application/octet-stream", nil, "data", true),
        ("application/json; charset=utf-8", nil, "{}", false),
        ("application/vnd.api+json", nil, "{}", false),
        ("image/svg+xml", nil, "<svg/>", false),
        ("text/html", "gzip", "compressed", true),
        ("text/html", "identity", "<p>", false),
        (nil, nil, "plain words", false),
        (nil, nil, "nul\u{0}byte", true),
    ] as [(String?, String?, String, Bool)])
    func binaryByTypeEncodingOrBytes(type: String?, encoding: String?, body: String, binary: Bool) throws {
        var headers = HTTPHeaders()
        if let type { headers.add(name: "Content-Type", value: type) }
        if let encoding { headers.add(name: "Content-Encoding", value: encoding) }
        var capture = BodyCapture(headers: headers, limit: 100)
        capture.append(buffer(body))
        #expect(try #require(capture.stored(complete: true)).0.binary == binary)
    }

    @Test func textCutInsideACharacterIsStillText() {
        let bytes = Data("grüße".utf8)
        #expect(BodyCapture.looksLikeText(bytes.prefix(3)))
        #expect(!BodyCapture.looksLikeText(Data([0xFF, 0xFE, 0x41, 0x42, 0x43])))
    }
}

@Suite struct ContentStoreTests {
    func make() throws -> (ContentStore, TempLayout) {
        let layout = try TempLayout()
        return (ContentStore(directory: layout.paths.httpContentDir), layout)
    }

    @Test func writesServesAndClears() throws {
        let (store, layout) = try make()
        defer { layout.cleanup() }
        let meta = StoredContent(contentType: "text/plain", size: 5, storedBytes: 5, binary: false)
        store.save(meta, Data("hello".utf8))

        let (served, data) = try #require(store.content(id: meta.id))
        #expect(served == meta && data == Data("hello".utf8))
        #expect(store.content(id: UUID()) == nil)
        let directory = layout.paths.httpContentDir
        #expect(try Self.mode(directory) == 0o700)
        #expect(try Self.mode("\(directory)/\(meta.id.uuidString)") == 0o600)
        #expect(try Self.mode("\(directory)/\(meta.id.uuidString).json") == 0o600)
        #expect(store.totalBytes == Self.bytes(in: directory))
        #expect(store.totalBytes > 5)

        try store.clear()
        #expect(store.content(id: meta.id) == nil)
        #expect(store.totalBytes == 0)
        #expect(try FileManager.default.contentsOfDirectory(atPath: directory).isEmpty)
    }

    @Test func pruneRemovesWhatIsPastTheRetention() throws {
        let (store, layout) = try make()
        defer { layout.cleanup() }
        let old = StoredContent(contentType: nil, size: 3, storedBytes: 3, binary: false)
        let recent = StoredContent(contentType: nil, size: 3, storedBytes: 3, binary: false)
        store.save(old, Data("old".utf8))
        store.save(recent, Data("new".utf8))
        _ = store.totalBytes  // waits for the writes
        let directory = layout.paths.httpContentDir
        let longAgo = Date().addingTimeInterval(-8 * 86_400)
        for name in [old.id.uuidString, "\(old.id.uuidString).json"] {
            try FileManager.default.setAttributes([.modificationDate: longAgo], ofItemAtPath: "\(directory)/\(name)")
        }

        #expect(store.prune(retentionDays: 7) == 2)
        #expect(store.content(id: old.id) == nil)
        #expect(store.content(id: recent.id)?.1 == Data("new".utf8))
        #expect(store.totalBytes == Self.bytes(in: directory))
        #expect(store.prune(retentionDays: 7) == 0)
    }

    @Test func anEmptyStoreIsFine() throws {
        let (store, layout) = try make()
        defer { layout.cleanup() }
        #expect(store.totalBytes == 0)
        #expect(store.prune(retentionDays: 7) == 0)
        try store.clear()
    }

    static func mode(_ path: String) throws -> Int {
        (try FileManager.default.attributesOfItem(atPath: path)[.posixPermissions] as? NSNumber)?.intValue ?? -1
    }

    static func bytes(in directory: String) -> Int64 {
        let names = (try? FileManager.default.contentsOfDirectory(atPath: directory)) ?? []
        return names.reduce(Int64(0)) { total, name in
            let size = (try? FileManager.default.attributesOfItem(atPath: "\(directory)/\(name)")[.size] as? NSNumber)?.int64Value
            return total + (size ?? 0)
        }
    }
}

@Suite(.timeLimit(.minutes(1))) struct WebRecordingIntegrationTests {
    @Test func postThroughTheProxyKeepsBothBodiesAndServesThem() async throws {
        let answer = #"{"ok":true}"#
        let origin = try await HTTPOrigin.start(.init(contentType: "application/json", body: Array(answer.utf8)))
        var config = AppConfig.testing([("127.0.0.1", .allow)])
        config.network.recording.contents = true
        let netd = try await TestNetd.start(config)
        try await withCleanup({ await origin.stop(); await netd.stop() }) {
            let body = #"{"name":"sandvault"}"#
            let authority = "127.0.0.1:\(origin.port)"
            let response = try await RawClient.exchange(
                port: Int(netd.ports.explicitProxy),
                "POST http://\(authority)/items HTTP/1.1\r\nHost: \(authority)\r\nContent-Type: application/json\r\n"
                    + "Content-Length: \(body.utf8.count)\r\nConnection: close\r\n\r\n\(body)"
            )
            #expect(response.hasPrefix("HTTP/1.1 200 OK\r\n") && response.hasSuffix(answer))
            #expect(origin.bodies.all == [Array(body.utf8)])

            let record = try await netd.record { !$0.http.isEmpty }
            let summary = try #require(record.http.first)
            #expect(summary.method == "POST" && summary.status == 200 && summary.url == "http://\(authority)/items")
            #expect(summary.startedAt.map { abs($0.timeIntervalSinceNow) < 30 } == true)
            #expect(summary.durationMs.map { $0 >= 0 } == true)
            #expect(summary.requestBytes == Int64(body.utf8.count))
            #expect(summary.responseBytes == Int64(answer.utf8.count))
            let sent = try #require(summary.requestContent)
            let received = try #require(summary.responseContent)
            #expect(sent.contentType == "application/json" && sent.size == Int64(body.utf8.count) && !sent.truncated && !sent.binary)
            #expect(received.storedBytes == answer.utf8.count && !received.truncated)

            let client = try await ControlClient.connect(socketPath: netd.socketPath)
            defer { client.close() }
            let (sentMeta, sentData) = try await client.content(id: sent.id)
            #expect(sentMeta == sent && sentData == Data(body.utf8))
            let (receivedMeta, receivedData) = try await client.content(id: received.id)
            #expect(receivedMeta == received && receivedData == Data(answer.utf8))
            await #expect(throws: SandvaultError.self) { try await client.content(id: UUID()) }
            #expect((try await client.status().storedContentBytes ?? 0) > 0)

            try await client.clearContent()
            await #expect(throws: SandvaultError.self) { try await client.content(id: sent.id) }
            #expect(try await client.status().storedContentBytes == 0)
        }
    }

    @Test func chunkedBodiesAreKeptWithoutFramingAndCapped() async throws {
        let payload = Array(String(repeating: "abcdefghij", count: 100).utf8)
        let origin = try await HTTPOrigin.start(.init(contentType: "text/plain", body: payload, chunked: true, pieces: 7))
        var config = AppConfig.testing([("web.test", .allow)], overrides: ["web.test": "127.0.0.1"])
        config.network.recording.contents = true
        config.network.recording.maxContentBytes = 64
        let netd = try await TestNetd.start(config, transparentHTTPPort: origin.port)
        try await withCleanup({ await origin.stop(); await netd.stop() }) {
            let response = try await RawClient.exchange(
                port: Int(netd.ports.transparentHTTP),
                "POST /upload HTTP/1.1\r\nHost: web.test\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n5\r\nhello\r\n6\r\n world\r\n0\r\n\r\n"
            )
            #expect(response.hasPrefix("HTTP/1.1 200 OK\r\n"))
            #expect(response.lowercased().contains("transfer-encoding: chunked"))
            #expect(origin.bodies.all == [Array("hello world".utf8)])

            let summary = try #require(try await netd.record { $0.kind == .transparentHTTP && !$0.http.isEmpty }.http.first)
            #expect(summary.requestBytes == 11 && summary.responseBytes == Int64(payload.count))
            let sent = try #require(summary.requestContent)
            let received = try #require(summary.responseContent)
            #expect(sent.size == 11 && sent.storedBytes == 11 && !sent.truncated)
            #expect(received.size == Int64(payload.count) && received.storedBytes == 64 && received.truncated)

            let store = netd.daemon.runtime.contents
            #expect(store.content(id: sent.id)?.1 == Data("hello world".utf8))
            #expect(store.content(id: received.id)?.1 == Data(payload.prefix(64)))
        }
    }

    @Test func requestsOffKeepsTheConnectionAndAReloadTurnsThemOn() async throws {
        let origin = try await TestOrigin.start(name: "origin")
        var config = AppConfig.testing([("127.0.0.1", .allow)])
        config.network.recording.requests = false
        config.network.recording.contents = true
        let netd = try await TestNetd.start(config)
        try await withCleanup({ await origin.stop(); await netd.stop() }) {
            let request = "POST http://127.0.0.1:\(origin.port)/x HTTP/1.1\r\nHost: x\r\nContent-Length: 4\r\nConnection: close\r\n\r\nbody"
            #expect(try await RawClient.exchange(port: Int(netd.ports.explicitProxy), request).hasPrefix("HTTP/1.1 200 OK"))
            let unrecorded = try await netd.record { $0.host == "127.0.0.1" }
            #expect(unrecorded.http.isEmpty && unrecorded.decision == .allowed && unrecorded.bytesOut > 0)
            #expect(netd.daemon.runtime.contents.totalBytes == 0, "contents need requests")

            var updated = try netd.store.load()
            updated.network.recording = WebRecordingSettings()
            try netd.store.save(updated)
            try netd.daemon.reload()
            #expect(try await RawClient.exchange(port: Int(netd.ports.explicitProxy), request).hasPrefix("HTTP/1.1 200 OK"))
            let summary = try #require(try await netd.record { !$0.http.isEmpty }.http.first)
            #expect(summary.requestBytes == 4 && summary.responseBytes == Int64("origin saw POST /x".utf8.count))
            #expect(summary.requestContent == nil && summary.responseContent == nil, "contents are off by default")
            #expect(!FileManager.default.fileExists(atPath: netd.layout.paths.httpContentDir))
        }
    }

    @Test func inspectedTLSRequestsAreTimedAndKept() async throws {
        let tls = try OriginTLS()
        let origin = try await TestOrigin.start(name: "secure", tls: try tls.serverContext(for: "secure.test"))
        var config = AppConfig.testing(
            [("secure.test", .allow)], inspect: ["secure.test"], overrides: ["secure.test": "127.0.0.1"], blockPrivate: true, inspection: true
        )
        config.network.recording.contents = true
        let netd = try await TestNetd.start(config, transparentTLSPort: origin.port, trustRoots: try tls.trustRoots, createCA: true)
        try await withCleanup({ await origin.stop(); await netd.stop() }) {
            var trust = TLSConfiguration.makeClientConfiguration()
            trust.trustRoots = .file(CAStore(paths: netd.layout.paths).certificatePath)
            let response = try await RawClient.exchange(
                port: Int(netd.ports.transparentTLS), "POST /t HTTP/1.1\r\nHost: secure.test\r\nContent-Length: 5\r\nConnection: close\r\n\r\nhello",
                tls: try NIOSSLContext(configuration: trust), serverName: "secure.test"
            )
            #expect(response.hasSuffix("secure saw POST /t"))
            let record = try await netd.record { $0.kind == .transparentTLS && !$0.http.isEmpty }
            #expect(record.inspected)
            let summary = try #require(record.http.first)
            #expect(summary.startedAt != nil && summary.durationMs != nil)
            #expect(summary.requestBytes == 5 && summary.responseBytes == Int64("secure saw POST /t".utf8.count))
            let sent = try #require(summary.requestContent)
            #expect(netd.daemon.runtime.contents.content(id: sent.id)?.1 == Data("hello".utf8))
            #expect(summary.responseContent?.contentType == "text/plain")
        }
    }

    @Test func aDeniedRequestStillGetsTimingAndSizes() async throws {
        let netd = try await TestNetd.start(.testing([("blocked.test", .deny)]))
        try await withCleanup({ await netd.stop() }) {
            let response = try await RawClient.exchange(
                port: Int(netd.ports.explicitProxy), "GET http://blocked.test/ HTTP/1.1\r\nHost: blocked.test\r\n\r\n"
            )
            #expect(response.hasPrefix("HTTP/1.1 403 Forbidden\r\n"))
            let summary = try #require(try await netd.record { $0.host == "blocked.test" }.http.first)
            #expect(summary.status == 403 && summary.startedAt != nil && summary.durationMs != nil)
            #expect(summary.requestBytes == 0 && (summary.responseBytes ?? 0) > 0 && summary.responseContent == nil)
        }
    }
}
