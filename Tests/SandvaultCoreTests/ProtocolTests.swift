import Foundation
import Testing
@testable import SandvaultCore

@Suite struct ProtocolTests {
    @Test func controlMessagesAreSingleJSONLines() throws {
        let id = UUID()
        let requests: [ControlRequest] = [
            .hello(client: "svctl"), .subscribe(topics: [.connections, .asks]), .status, .reloadConfig,
            .answer(AskAnswer(id: id, decision: .allowAlways, scope: .domain)), .recent(limit: 50), .pendingAsks,
        ]
        for request in requests {
            let data = try ControlCodec.encode(request)
            #expect(data.last == 0x0A)
            #expect(data.dropLast().contains(0x0A) == false)
            let line = String(decoding: data.dropLast(), as: UTF8.self)
            #expect(try ControlCodec.decode(ControlRequest.self, line: line) == request)
        }

        let record = ConnectionRecord(timestamp: Date(timeIntervalSince1970: 1_700_000_000), kind: .transparentTLS, host: "api.anthropic.com", port: 443, decision: .allowed)
        let ask = AskRequest(host: "example.com", port: 443, kind: .explicitProxy, createdAt: Date(timeIntervalSince1970: 1), expiresAt: Date(timeIntervalSince1970: 31))
        let events: [ControlEvent] = [
            .hello(version: "0.0.0"), .connection(record), .recent([record]), .ask(ask), .pending([ask]),
            .askResolved(id: id, decision: .askedDenied), .ack, .error("boom"),
            .status(NetdStatus(startedAt: Date(timeIntervalSince1970: 1), ports: ProxyPorts(), mode: .proxyOnly)),
        ]
        for event in events {
            let line = String(decoding: try ControlCodec.encode(event).dropLast(), as: UTF8.self)
            #expect(try ControlCodec.decode(ControlEvent.self, line: line) == event)
        }
    }

    @Test func helperClientSendsStateOnStdinAndDecodesResult() async throws {
        let fake = FakeCommandRunner()
        let result = HelperResult(ok: true, message: "applied", details: ["anchorRules": "12"])
        fake.on(["/usr/bin/sudo", "-n", AppPaths.helperPath, "pf-apply"], stdout: String(decoding: try JSONCoding.lineEncoder.encode(result), as: UTF8.self))
        let state = AppliedState(config: AppConfig(), dynamicLocalPorts: [9222])
        let answer = try await HelperClient(runner: fake).run(.pfApply, state: state)
        #expect(answer == result)
        let sent = try #require(fake.invocations.first?.stdin)
        #expect(try JSONCoding.decoder.decode(AppliedState.self, from: sent).dynamicLocalPorts == [9222])
    }

    @Test func helperClientExplainsMissingSudoersRule() async {
        let fake = FakeCommandRunner()
        fake.on(["/usr/bin/sudo"], stdout: "", exitCode: 1, stderr: "sudo: a password is required")
        await #expect(throws: SandvaultError.permissionDenied("helper sudoers rule missing; run `svctl helper install`")) {
            try await HelperClient(runner: fake).run(.status)
        }
    }

    @Test func gitSafeHardensBeforeTheRepository() {
        let invocation = GitSafe.invocation(repository: "/Users/Shared/sv-alice/repos/app", ["status", "--porcelain"])
        #expect(invocation.executable == "/usr/bin/git")
        let cIndex = invocation.arguments.firstIndex(of: "-C")
        #expect(cIndex == GitSafe.hardeningArguments.count)
        #expect(invocation.arguments.contains("core.hooksPath=/dev/null"))
        #expect(invocation.environment?["GIT_CONFIG_NOSYSTEM"] == "1")
    }

    @Test func checkReportWorstState() {
        let report = CheckReport(checks: [
            Check(id: "a", title: "A", state: .ok, detail: ""),
            Check(id: "b", title: "B", state: .warning, detail: ""),
            Check(id: "c", title: "C", state: .skipped, detail: ""),
        ])
        #expect(report.worst == .warning)
        #expect(CheckReport(checks: []).worst == .ok)
    }
}

@Suite struct AskDetailsContractTests {
    @Test func oldFilesDecodeWithTheNewDefaults() throws {
        let policy = try JSONDecoder().decode(NetworkPolicy.self, from: Data(#"{"mode":"proxyOnly","ports":{"dns":5353}}"#.utf8))
        #expect(policy.routeAllTCP)
        #expect(policy.askDetails == AskDetailSettings())
        #expect(policy.ports.transparentTCP == 18444 && policy.ports.dns == 5353)
        #expect(policy.ports.all.contains(18444))
        let rule = try JSONDecoder().decode(DomainRule.self, from: Data(#"{"pattern":"a.test","action":"allow"}"#.utf8))
        #expect(rule.port == nil)
        // A rule without a port is written without the key, so existing files stay as they are.
        #expect(!String(decoding: try JSONEncoder().encode(rule), as: UTF8.self).contains("port"))
    }

    @Test func detailsRoundTrip() throws {
        let details = AskDetails(
            address: "185.142.236.41", name: AskName(name: nil, source: .none), reverseName: "vps-41.example-host.ru",
            service: KnownService(port: 8947, name: nil),
            network: AskNetwork(asn: 48282, owner: "Example Hosting", country: "RU", kind: .hosting, source: .offline),
            encryption: .unknown, history: AskHistory(allowed: 0, denied: 0, lastSeen: nil),
            program: AskProgram(path: "/tmp/x/python3", signature: .developer(team: nil), inTemporaryFolder: true),
            assessment: AskAssessment(level: .suspicious, score: 8, signals: [
                .init(detail: .port, effect: .minus, points: 2, text: "Port 8947 is in no list of known services."),
            ])
        )
        let request = AskRequest(host: "185.142.236.41", port: 8947, kind: .transparentTLS, expiresAt: Date(timeIntervalSince1970: 60), details: details)
        let decoded = try JSONDecoder().decode(AskRequest.self, from: try JSONEncoder().encode(request))
        #expect(decoded == request)
        let rule = DomainRule(pattern: "185.142.236.41", action: .allow, port: 8947)
        #expect(try JSONDecoder().decode(DomainRule.self, from: try JSONEncoder().encode(rule)).port == 8947)
    }

    @Test func scopeOptionsAndLevels() {
        #expect(AskScope.options(port: 443, hasDomain: true) == [.host, .domain])
        #expect(AskScope.options(port: nil, hasDomain: false) == [.host])
        #expect(AskScope.options(port: 8947, hasDomain: true) == [.hostAndPort, .host])
        #expect(AskAssessment.level(for: 2) == .normal)
        #expect(AskAssessment.level(for: 3) == .unusual)
        #expect(AskAssessment.level(for: 6) == .suspicious)
    }
}
