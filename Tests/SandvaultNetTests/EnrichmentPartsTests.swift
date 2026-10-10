import Foundation
import SandvaultCore
import Testing
@testable import SandvaultNet

@Suite struct EnrichmentPartsTests {
    // MARK: Network table

    @Test func theNetworkTableFindsRangesAndSkipsUnroutedOnes() throws {
        let table = NetworkTable(tsv: try Fixture.data("ip2asn-v4-sample.tsv"))
        #expect(table.count == 11)
        let google = try #require(table.lookup("8.8.8.8"))
        #expect(google.asn == 15169)
        #expect(google.country == "US")
        #expect(google.owner == "GOOGLE")
        #expect(table.lookup("185.142.236.41")?.owner == "VDSINA-AS")
        #expect(table.lookup("185.142.236.41")?.country == "RU")
        #expect(table.lookup("104.31.255.255")?.asn == 13335)
        #expect(table.lookup("1.0.2.1") == nil)  // AS 0, not routed
        #expect(table.lookup("0.0.0.1") == nil)
        #expect(table.lookup("9.9.9.9") == nil)  // between ranges
        #expect(table.lookup("255.255.255.255") == nil)
        #expect(table.lookup("2001:4860:4860::8888") == nil)  // IPv6 is not covered
        #expect(table.lookup("not an address") == nil)
    }

    @Test func networkLinesParseStrictly() {
        #expect(NetworkTable.parseLine("1.0.0.0\t1.0.0.255\t13335\tUS\tCLOUDFLARENET")?.owner == "CLOUDFLARENET")
        #expect(NetworkTable.parseLine("1.0.0.0\t1.0.0.255\t13335\tNone\tX\r")?.country == nil)
        #expect(NetworkTable.parseLine("1.0.0.0\t1.0.0.255\t0\tNone\tNot routed") == nil)
        #expect(NetworkTable.parseLine("1.0.0.256\t1.0.1.0\t1\tUS\tX") == nil)
        #expect(NetworkTable.parseLine("1.0.1.0\t1.0.0.0\t1\tUS\tX") == nil)
        #expect(NetworkTable.parseLine("1.0.0.0 1.0.0.255 13335 US CLOUDFLARENET") == nil)
        #expect(NetworkTable.isWellFormed("1.0.1.0\t1.0.3.255\t0\tNone\tNot routed"))
        #expect(!NetworkTable.isWellFormed("<html>"))
    }

    @Test func theDatabaseLoadsLazilyAndReloadsAChangedFile() async throws {
        let dir = try temporaryDirectory()
        let path = dir + "/ip2asn-v4.tsv"
        let database = NetworkDatabase(path: path)
        #expect(await database.lookup("8.8.8.8") == nil)
        try Fixture.data("ip2asn-v4-sample.tsv").write(to: URL(fileURLWithPath: path))
        #expect(await database.lookup("8.8.8.8")?.asn == 15169)
        try Data("8.8.8.0\t8.8.8.255\t64512\tCH\tCHANGED\n".utf8).write(to: URL(fileURLWithPath: path))
        try FileManager.default.setAttributes([.modificationDate: Date().addingTimeInterval(60)], ofItemAtPath: path)
        #expect(await database.lookup("8.8.8.8")?.owner == "CHANGED")
    }

    @Test func theStoreDownloadsUnpacksChecksAndReports() async throws {
        let dir = try temporaryDirectory()
        let path = dir + "/data/ip2asn-v4.tsv"
        let runner = FakeCommandRunner()
        let sample = try Fixture.text("ip2asn-v4-sample.tsv")
        runner.on(["/usr/bin/curl"], stdout: "")
        runner.on(["/usr/bin/gunzip", "-c", path + ".download.gz"], stdout: sample)
        var store = NetworkDatabaseStore(path: path, runner: runner)
        store.minimumLines = 5
        #expect(await store.status() == NetworkDatabaseStatus(installed: false))

        let status = try await store.update()
        #expect(status.installed)
        #expect(status.ranges == 13)
        #expect(status.updatedAt != nil)
        #expect(try String(contentsOfFile: path, encoding: .utf8) == sample)
        let curl = try #require(runner.invocations.first)
        #expect(curl.argv == [
            "/usr/bin/curl", "-fsSL", "--max-time", "120", "-o", path + ".download.gz", "https://iptoasn.com/data/ip2asn-v4.tsv.gz",
        ])
        #expect(await store.status().ranges == 13)
    }

    @Test func theStoreRefusesWhatIsNotATable() async throws {
        let dir = try temporaryDirectory()
        let path = dir + "/ip2asn-v4.tsv"
        let runner = FakeCommandRunner()
        runner.on(["/usr/bin/curl"], stdout: "")
        runner.on(["/usr/bin/gunzip"], stdout: String(repeating: "<html>error</html>\n", count: 2000))
        let store = NetworkDatabaseStore(path: path, runner: runner)
        await #expect(throws: SandvaultError.self) { try await store.update() }
        #expect(!FileManager.default.fileExists(atPath: path))

        runner.on(["/usr/bin/gunzip"], stdout: try Fixture.text("ip2asn-v4-sample.tsv"))
        await #expect(throws: SandvaultError.self) { try await store.update() }  // too short for the default minimum
        runner.on(["/usr/bin/curl"], stdout: "", exitCode: 22, stderr: "curl: (22) The requested URL returned error: 503")
        await #expect(throws: SandvaultError.self) { try await store.update() }
    }

    // MARK: Network kinds and RDAP

    @Test func networkKindsFollowTheCatalog() {
        #expect(NetworkCatalog.kind(address: "8.8.8.8", asn: 15169, owner: "GOOGLE") == .knownService)
        #expect(NetworkCatalog.kind(address: "1.1.1.1", asn: 13335, owner: "CLOUDFLARENET") == .knownService)
        #expect(NetworkCatalog.kind(address: "104.16.27.35", asn: 13335, owner: "CLOUDFLARENET") == .cdn)
        #expect(NetworkCatalog.kind(address: nil, asn: 714, owner: "APPLE-ENGINEERING") == .knownService)
        #expect(NetworkCatalog.kind(address: nil, asn: 24940, owner: "HETZNER-AS") == .hosting)
        #expect(NetworkCatalog.kind(address: nil, asn: 64999, owner: "Example VPS Hosting Ltd") == .hosting)
        #expect(NetworkCatalog.kind(address: nil, asn: 64998, owner: "Example CDN") == .cdn)
        #expect(NetworkCatalog.kind(address: nil, asn: 64500, owner: "EXAMPLE-ISP Example Broadband Ltd") == .other)
        #expect(NetworkCatalog.kind(address: nil, asn: nil, owner: nil) == .other)
    }

    @Test func rdapAnswersParse() throws {
        let arin = try #require(RDAPClient.parse(try Fixture.data("rdap-arin-8.8.8.8.json")))
        #expect(arin == RDAPClient.Result(asn: 15169, owner: "Google LLC", country: nil))
        let ripe = try #require(RDAPClient.parse(try Fixture.data("rdap-ripe-185.142.236.41.json")))
        #expect(ripe == RDAPClient.Result(asn: nil, owner: "VDSINA-NET", country: "RU"))
        #expect(RDAPClient.parse(Data("{}".utf8)) == nil)
        #expect(RDAPClient.parse(Data("not json".utf8)) == nil)
    }

    struct FakeFetcher: HTTPFetching {
        var status = 200
        var body: Data
        var delay: Double = 0
        func get(_ url: URL, timeout: Double) async throws -> (status: Int, body: Data) {
            if delay > 0 { try await Task.sleep(nanoseconds: UInt64(delay * 1_000_000_000)) }
            #expect(url.absoluteString == "https://rdap.org/ip/185.142.236.41")
            return (status, body)
        }
    }

    @Test func onlineLookupsUseRDAPAndClassify() async throws {
        let fetcher = FakeFetcher(body: try Fixture.data("rdap-ripe-185.142.236.41.json"))
        let lookup = LiveNetworkLookup(database: NetworkDatabase(path: "/nonexistent"), rdap: RDAPClient(fetcher: fetcher))
        let network = try #require(await lookup.network(for: "185.142.236.41", mode: .online))
        #expect(network == AskNetwork(asn: nil, owner: "VDSINA-NET", country: "RU", kind: .hosting, source: .online))
        let failing = LiveNetworkLookup(database: NetworkDatabase(path: "/nonexistent"), rdap: RDAPClient(fetcher: FakeFetcher(status: 404, body: Data())))
        #expect(await failing.network(for: "185.142.236.41", mode: .online) == nil)
        #expect(await failing.network(for: "185.142.236.41", mode: .off) == nil)
    }

    @Test func knownResolversNeedNoTable() async {
        let lookup = LiveNetworkLookup(database: NetworkDatabase(path: "/nonexistent"))
        let network = await lookup.network(for: "9.9.9.9", mode: .offline)
        #expect(network == AskNetwork(asn: 19281, owner: "Quad9", country: "CH", kind: .knownService, source: .offline))
    }

    // MARK: Program signatures

    @Test func codesignOutputMapsToSignatures() throws {
        #expect(CodesignOutput.signature(stderr: try Fixture.text("codesign-apple-mdnsresponder.txt"), exitCode: 0) == .apple)
        #expect(CodesignOutput.signature(stderr: try Fixture.text("codesign-developer-id.txt"), exitCode: 0) == .developer(team: "A1B2C3D4E5"))
        #expect(CodesignOutput.signature(stderr: try Fixture.text("codesign-adhoc-node.txt"), exitCode: 0) == .adHoc)
        #expect(CodesignOutput.signature(stderr: try Fixture.text("codesign-unsigned.txt"), exitCode: 1) == .unsigned)
        #expect(CodesignOutput.signature(stderr: "/x: No such file or directory\n", exitCode: 1) == .unknown)
        #expect(CodesignOutput.signature(stderr: "", exitCode: 0) == .unknown)
    }

    @Test func temporaryFoldersAreRecognised() {
        for path in ["/tmp/build-x/.venv/bin/python3", "/private/tmp/a", "/private/var/folders/xy/T/tool", "/var/folders/a/b", "/Users/a/tmp/bin/x"] {
            #expect(LiveProgramInspector.isTemporary(path), "\(path)")
        }
        for path in ["/usr/bin/python3", "/opt/homebrew/bin/node", "/Users/a/tmpfiles/x", "/Users/a/bin/tmp"] {
            #expect(!LiveProgramInspector.isTemporary(path), "\(path)")
        }
    }

    @Test func programsAreInspectedOnceUntilTheFileChanges() async throws {
        let dir = try temporaryDirectory()
        let binary = dir + "/tool"
        try Data("binary".utf8).write(to: URL(fileURLWithPath: binary))
        let runner = FakeCommandRunner()
        runner.on(["/bin/ps", "-o", "comm=", "-p", "4242"], stdout: binary + "\n")
        runner.on(["/usr/bin/codesign", "-dv", "--verbose=2", binary], .result(CommandResult(
            exitCode: 0, stdout: "", stderr: try Fixture.text("codesign-developer-id.txt")
        )))
        let inspector = LiveProgramInspector(runner: runner)
        let first = try #require(await inspector.program(pid: 4242))
        #expect(first == AskProgram(path: binary, signature: .developer(team: "A1B2C3D4E5"), inTemporaryFolder: LiveProgramInspector.isTemporary(binary)))
        _ = await inspector.program(pid: 4242)
        #expect(runner.invocations.filter { $0.executable == "/usr/bin/codesign" }.count == 1)

        try FileManager.default.setAttributes([.modificationDate: Date().addingTimeInterval(60)], ofItemAtPath: binary)
        _ = await inspector.program(pid: 4242)
        #expect(runner.invocations.filter { $0.executable == "/usr/bin/codesign" }.count == 2)

        runner.on(["/bin/ps", "-o", "comm=", "-p", "4343"], stdout: "", exitCode: 1)
        #expect(await inspector.program(pid: 4343) == nil)
        runner.on(["/bin/ps", "-o", "comm=", "-p", "4444"], stdout: "python3\n")
        #expect(await inspector.program(pid: 4444) == AskProgram(path: "python3", signature: .unknown, inTemporaryFolder: false))
    }

    // MARK: DNS names, PTR, history

    @Test func dnsAnswersAreRememberedForAWhile() {
        let clock = Clock()
        let cache = DNSNameCache(retention: 600, capacity: 4, now: { clock.now })
        cache.record(name: "registry.npmjs.org", addresses: ["104.16.27.35", "2606:4700::6810:1B23"])
        #expect(cache.name(for: "104.16.27.35") == "registry.npmjs.org")
        #expect(cache.name(for: "2606:4700::6810:1b23") == "registry.npmjs.org")
        #expect(cache.address(for: "registry.npmjs.org") == "104.16.27.35")
        clock.advance(601)
        #expect(cache.name(for: "104.16.27.35") == nil)
        #expect(cache.address(for: "registry.npmjs.org") == nil)
    }

    @Test func theDNSCacheStaysBounded() {
        let clock = Clock()
        let cache = DNSNameCache(retention: 600, capacity: 10, now: { clock.now })
        for index in 0..<50 {
            cache.record(name: "host\(index).test", addresses: ["10.0.0.\(index)"])
            clock.advance(1)
        }
        #expect(cache.count <= 10)
        #expect(cache.name(for: "10.0.0.49") == "host49.test")
        #expect(cache.name(for: "10.0.0.0") == nil)
    }

    @Test func ptrQueriesAndAnswers() throws {
        #expect(ReverseDNS.queryName(for: "185.142.236.41") == "41.236.142.185.in-addr.arpa")
        #expect(ReverseDNS.queryName(for: "2001:db8::1") == "1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.b.d.0.1.0.0.2.ip6.arpa")
        #expect(ReverseDNS.queryName(for: "example.com") == nil)

        let question = DNSQuestion(name: "8.8.8.8.in-addr.arpa", type: ReverseDNS.typePTR)
        let query = DNSMessage(id: 7, flags: 0x0100, questions: [question])
        var target: [UInt8] = []
        target.appendName("dns.google")
        let answer = DNSRecord(name: question.name, type: ReverseDNS.typePTR, ttl: 300, data: target)
        let reply = DNSMessage.response(to: query, rcode: .noError, answers: [answer]).encoded()
        #expect(try ReverseDNS.ptrName(in: reply) == "dns.google")
        #expect(try ReverseDNS.ptrName(in: DNSMessage.response(to: query, rcode: .nameError).encoded()) == nil)
        #expect(try ReverseDNS.ptrName(in: DNSMessage.response(to: query, rcode: .noError).encoded()) == nil)
        #expect(throws: (any Error).self) { try ReverseDNS.ptrName(in: DNSMessage.response(to: query, rcode: .serverFailure).encoded()) }
    }

    @Test func ptrTargetsMayUseCompression() throws {
        // Answer data "vps-41" + pointer to "example-host.ru" written earlier in the question name.
        let question = DNSQuestion(name: "x.example-host.ru", type: ReverseDNS.typePTR)
        let query = DNSMessage(id: 9, flags: 0x0100, questions: [question])
        var target: [UInt8] = [6] + Array("vps-41".utf8)
        target += [0xC0, 14]  // the question name starts at 12; 14 skips its "x" label
        let answer = DNSRecord(name: question.name, type: ReverseDNS.typePTR, ttl: 300, data: target)
        let reply = DNSMessage.response(to: query, rcode: .noError, answers: [answer]).encoded()
        #expect(try ReverseDNS.ptrName(in: reply) == "vps-41.example-host.ru")
    }

    @Test func historyCountsPerHostAndPort() {
        let index = ConnectionHistoryIndex()
        let earlier = Date(timeIntervalSince1970: 1_000)
        index.add(ConnectionRecord(timestamp: earlier, kind: .transparentTLS, host: "Registry.npmjs.org", port: 443, decision: .allowed))
        index.add(ConnectionRecord(timestamp: earlier.addingTimeInterval(5), kind: .transparentTLS, host: "registry.npmjs.org", port: 443, decision: .askedAllowed))
        index.add(ConnectionRecord(kind: .transparentTLS, host: "registry.npmjs.org", port: 8443, decision: .denied))
        index.add(ConnectionRecord(timestamp: earlier, kind: .dns, host: "registry.npmjs.org", decision: .timedOut))
        #expect(index.history(host: "registry.npmjs.org", port: 443) == AskHistory(allowed: 2, denied: 0, lastSeen: earlier.addingTimeInterval(5)))
        #expect(index.history(host: "registry.npmjs.org", port: 8443).denied == 1)
        #expect(index.history(host: "registry.npmjs.org", port: nil) == AskHistory(allowed: 0, denied: 1, lastSeen: earlier))
        #expect(index.history(host: "other.test", port: 443) == AskHistory(allowed: 0, denied: 0, lastSeen: nil))
    }

    @Test func historyIsSeededFromTheLogWithoutCountingTwice() throws {
        let dir = try temporaryDirectory()
        let log = ConnectionLog(path: dir + "/connections.jsonl")
        let cutoff = Date()
        log.append(ConnectionRecord(timestamp: cutoff.addingTimeInterval(-60), kind: .transparentTLS, host: "a.test", port: 443, decision: .allowed))
        log.append(ConnectionRecord(timestamp: cutoff.addingTimeInterval(5), kind: .transparentTLS, host: "a.test", port: 443, decision: .allowed))
        log.close()
        let index = ConnectionHistoryIndex()
        index.seed(logPath: dir + "/connections.jsonl", before: cutoff)
        #expect(index.history(host: "a.test", port: 443).allowed == 1)
    }

    // MARK: Helpers

    final class Clock: @unchecked Sendable {
        private let lock = NSLock()
        private var current = Date(timeIntervalSince1970: 1_000_000)
        var now: Date { lock.withLock { current } }
        func advance(_ seconds: TimeInterval) { lock.withLock { current += seconds } }
    }

    func temporaryDirectory() throws -> String {
        let path = NSTemporaryDirectory() + "enrich-" + UUID().uuidString
        try FileManager.default.createDirectory(atPath: path, withIntermediateDirectories: true)
        return path
    }
}
