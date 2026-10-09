import Foundation
import NIOHTTP1
import SandvaultCore
import Testing
@testable import SandvaultNet

enum Fixture {
    static func data(_ name: String) throws -> Data {
        guard let url = Bundle.module.url(forResource: name, withExtension: nil, subdirectory: "Fixtures") else {
            throw SandvaultError.notInstalled("fixture \(name)")
        }
        return try Data(contentsOf: url)
    }

    static func text(_ name: String) throws -> String {
        String(decoding: try data(name), as: UTF8.self)
    }

    static func hex(_ name: String) throws -> [UInt8] {
        let text = try self.text(name).trimmingCharacters(in: .whitespacesAndNewlines)
        var bytes: [UInt8] = []
        var index = text.startIndex
        while index < text.endIndex {
            let next = text.index(index, offsetBy: 2)
            bytes.append(UInt8(text[index..<next], radix: 16)!)
            index = next
        }
        return bytes
    }
}

@Suite struct ClientHelloTests {
    @Test func extractsSNIFromARealClientHello() throws {
        let bytes = [UInt8](try Fixture.data("clienthello-sni-example.com.bin"))
        #expect(ClientHelloParser.parse(bytes) == .complete(serverName: "example.com"))
    }

    @Test func reportsAMissingSNI() throws {
        let bytes = [UInt8](try Fixture.data("clienthello-no-sni.bin"))
        #expect(ClientHelloParser.parse(bytes) == .complete(serverName: nil))
    }

    @Test func asksForMoreDataUntilTheRecordIsComplete() throws {
        let bytes = [UInt8](try Fixture.data("clienthello-sni-example.com.bin"))
        for cut in [0, 3, 5, 40, bytes.count - 1] {
            #expect(ClientHelloParser.parse(Array(bytes.prefix(cut))) == .needMoreData, "cut at \(cut)")
        }
    }

    @Test func reassemblesAHandshakeSplitAcrossRecords() throws {
        let bytes = [UInt8](try Fixture.data("clienthello-sni-example.com.bin"))
        let body = Array(bytes.dropFirst(5))
        let split = 100
        func record(_ payload: ArraySlice<UInt8>) -> [UInt8] {
            [0x16, 0x03, 0x01, UInt8(payload.count >> 8), UInt8(payload.count & 0xFF)] + payload
        }
        let fragmented = record(body[..<split]) + record(body[split...])
        #expect(ClientHelloParser.parse(fragmented) == .complete(serverName: "example.com"))
        #expect(ClientHelloParser.parse(record(body[..<split])) == .needMoreData)
    }

    @Test func rejectsNonTLS() {
        #expect(ClientHelloParser.parse(Array("GET / HTTP/1.1\r\n\r\n".utf8)) == .invalid("not a TLS handshake record"))
        #expect(ClientHelloParser.parse([0x16, 0x03, 0x01, 0x00, 0x04, 0x02, 0x00, 0x00, 0x00]) == .invalid("first handshake message is not a ClientHello"))
    }
}

@Suite struct DNSMessageTests {
    @Test func decodesCompressedAnswers() throws {
        let message = try DNSMessage(bytes: try Fixture.hex("dns-response-www.github.com.hex"))
        #expect(message.id == 0x1A2B)
        #expect(message.isResponse)
        #expect(message.rcode == .noError)
        #expect(message.questions == [DNSQuestion(name: "www.github.com", type: DNSRecordType.a)])
        #expect(message.answers.map(\.name) == ["www.github.com", "github.com", "github.com"])
        #expect(message.answers[0].type == 5)
        #expect(message.answerAddresses == ["140.82.121.3", "2001:db8::1"])
    }

    @Test func roundTripsAQueryAndASynthesizedAnswer() throws {
        let query = DNSMessage(id: 7, flags: 0x0100, questions: [DNSQuestion(name: "api.Example.com", type: DNSRecordType.aaaa)])
        let decoded = try DNSMessage(bytes: query.encoded())
        #expect(decoded == query)
        #expect(!decoded.isResponse && decoded.recursionDesired && decoded.opcode == 0)

        let record = try #require(DNSRecord.address(name: "api.Example.com", address: "fd00::1", ttl: 60))
        let response = DNSMessage.response(to: decoded, rcode: .noError, answers: [record])
        let bytes = response.encoded()
        // The answer name is a pointer to the question (0xC00C).
        #expect(bytes[(12 + 17 + 4)...].starts(with: [0xC0, 0x0C]))
        let parsed = try DNSMessage(bytes: bytes)
        #expect(parsed.id == 7 && parsed.isResponse && parsed.recursionDesired)
        #expect(parsed.flags & 0x0080 != 0, "recursion available")
        #expect(parsed.answerAddresses == ["fd00::1"])
    }

    @Test func encodesErrorCodes() throws {
        let query = DNSMessage(id: 9, flags: 0x0100, questions: [DNSQuestion(name: "blocked.test", type: DNSRecordType.a)])
        for code in [DNSResponseCode.nameError, .refused, .serverFailure] {
            let parsed = try DNSMessage(bytes: DNSMessage.response(to: query, rcode: code).encoded())
            #expect(parsed.rcode == code)
            #expect(parsed.answers.isEmpty)
            #expect(parsed.questions == query.questions)
        }
        #expect(DNSMessage.formatError(for: [0x12, 0x34] + Array(repeating: 0, count: 10)).map { Array($0.prefix(2)) } == [0x12, 0x34])
        #expect(DNSMessage.formatError(for: [1, 2, 3]) == nil)
    }

    @Test func rejectsMalformedMessages() {
        #expect(throws: (any Error).self) { try DNSMessage(bytes: [0, 1, 2]) }
        // A question whose name points forward (or at itself) must not loop.
        var looping: [UInt8] = [0, 1, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0]
        looping += [0xC0, 0x0C, 0, 1, 0, 1]
        #expect(throws: (any Error).self) { try DNSMessage(bytes: looping) }
    }

    @Test func formatsIPv6LikeRFC5952() {
        func format(_ text: String) -> String { DNSRecord.formatIPv6(AddressRange.parseAddress(text)!.1) }
        #expect(format("2001:0db8:0000:0000:0000:0000:0000:0001") == "2001:db8::1")
        #expect(format("::") == "::")
        #expect(format("fe80::1:0:0:1") == "fe80::1:0:0:1")
        #expect(format("2001:db8:0:1:1:1:1:1") == "2001:db8:0:1:1:1:1:1")
    }

    @Test func readsTheFirstUsableNameserver() throws {
        let file = FileManager.default.temporaryDirectory.appendingPathComponent("resolv-\(UUID().uuidString).conf")
        defer { try? FileManager.default.removeItem(at: file) }
        try "# generated\nsearch lan\nnameserver fe80::1%en0\nnameserver 192.168.1.1\nnameserver 1.1.1.1\n".write(to: file, atomically: true, encoding: .utf8)
        #expect(DNSUpstream.systemResolver(resolvConf: file.path) == "192.168.1.1")
        #expect(DNSUpstream.systemResolver(resolvConf: "/nonexistent/resolv.conf") == nil)
    }
}

@Suite struct HTTPRewriteTests {
    @Test func parsesAbsoluteURLs() throws {
        let url = try #require(HTTPRewrite.parseAbsolute("http://user:pw@Example.COM:8080/a/b?q=1#frag"))
        #expect(url.host == "example.com")
        #expect(url.port == 8080)
        #expect(url.originForm == "/a/b?q=1")
        #expect(url.authority == "Example.COM:8080")
        #expect(url.display == "http://Example.COM:8080/a/b?q=1")
        #expect(HTTPRewrite.parseAbsolute("http://example.com")?.originForm == "/")
        #expect(HTTPRewrite.parseAbsolute("HTTP://example.com?x=1")?.originForm == "/?x=1")
        #expect(HTTPRewrite.parseAbsolute("http://[::1]:81/")?.host == "::1")
        #expect(HTTPRewrite.parseAbsolute("https://example.com/") == nil)
        #expect(HTTPRewrite.parseAbsolute("/relative") == nil)
        #expect(HTTPRewrite.parseAbsolute("http://exa mple.com/") == nil)
        #expect(HTTPRewrite.parseAbsolute("http://example.com:99999/") == nil)
    }

    @Test func parsesConnectTargets() {
        #expect(HTTPRewrite.parseAuthority("github.com:443")! == ("github.com", 443))
        #expect(HTTPRewrite.parseAuthority("GitHub.com")! == ("github.com", 443))
        #expect(HTTPRewrite.parseAuthority("[2606:4700::1]:8443")! == ("2606:4700::1", 8443))
        #expect(HTTPRewrite.parseAuthority("bad host:443") == nil)
        #expect(HTTPRewrite.parseAuthority("host:port") == nil)
    }

    @Test func stripsHopByHopAndProxyHeaders() {
        var headers = HTTPHeaders()
        headers.add(name: "Host", value: "example.com")
        headers.add(name: "Connection", value: "keep-alive, X-Secret-Hop")
        headers.add(name: "Keep-Alive", value: "timeout=5")
        headers.add(name: "Proxy-Connection", value: "Keep-Alive")
        headers.add(name: "Proxy-Authorization", value: "Basic abc")
        headers.add(name: "X-Secret-Hop", value: "1")
        headers.add(name: "TE", value: "trailers")
        headers.add(name: "Upgrade", value: "websocket")
        headers.add(name: "Transfer-Encoding", value: "chunked")
        headers.add(name: "Accept", value: "*/*")
        let stripped = HTTPRewrite.stripHopByHop(headers)
        #expect(stripped.map(\.name) == ["Host", "Transfer-Encoding", "Accept"])
    }

    @Test func redactsConfiguredHeaders() {
        var headers = HTTPHeaders()
        headers.add(name: "Authorization", value: "Bearer secret")
        headers.add(name: "X-Api-Key", value: "k")
        headers.add(name: "Accept", value: "*/*")
        let summary = HTTPRewrite.summarize(headers, redact: Set(InspectionSettings.defaultRedactedHeaders))
        #expect(summary == [["Authorization", "<redacted>"], ["X-Api-Key", "<redacted>"], ["Accept", "*/*"]])
    }

    @Test func denialMessageIsOneLineWithTheAllowCommand() {
        let result = GateResult(verdict: .deny, host: "evil.test", port: 443, decision: .denied, reason: "rule *.evil.test (deny)")
        let message = NetRuntime.denialMessage(result)
        #expect(message == "sandvault-config blocked evil.test:443: rule *.evil.test (deny). To allow it: svctl proxy allow evil.test\n")
        #expect(message.filter { $0 == "\n" }.count == 1)
    }
}
