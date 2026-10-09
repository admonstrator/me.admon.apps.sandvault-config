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
