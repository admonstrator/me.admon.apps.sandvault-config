import Foundation
import SandvaultCore
import Testing
@testable import SandvaultObserve

@Suite struct ConnectionParserTests {
    @Test func parsesLsofFieldOutput() throws {
        let connections = LsofParser.parse(try fixture("lsof-sandbox.txt"))
        #expect(connections.count == 9)
        #expect(connections[0] == SandboxConnection(
            pid: 4121, process: "claude", proto: .tcp, family: .ipv4, localAddress: "127.0.0.1", localPort: 52000,
            remoteAddress: "127.0.0.1", remotePort: 18080, state: "ESTABLISHED"
        ))
        #expect(connections[1].localAddress == "2a00:1450:4001:82b::200e")
        #expect(connections[1].remotePort == 443)
        #expect(connections[1].family == .ipv6)

        let listening = connections.filter(\.isListening)
        #expect(listening.map(\.localPort) == [3000, 5173, 8080, 9229])
        #expect(listening.map(\.localAddress) == ["127.0.0.1", "*", "192.168.1.20", "::1"])

        let udp = connections.filter { $0.proto == .udp }
        #expect(udp.count == 2)
        #expect(udp.allSatisfy { $0.state == nil })
        #expect(udp[0].localAddress == "*" && udp[0].localPort == 0 && udp[0].remoteAddress == nil)
        #expect(udp[1].remoteAddress == "1.1.1.1" && udp[1].remotePort == 53)
    }

    @Test func emptyOutputHasNoConnections() {
        #expect(LsofParser.parse("").isEmpty)
        #expect(LsofParser.parse("p12\ncfoo\n").isEmpty)
    }

    @Test(arguments: [
        ("127.0.0.1:443", "127.0.0.1 443"), ("[::1]:8080", "::1 8080"), ("[fe80::1%lo0]:5000", "fe80::1%lo0 5000"),
        ("*:5353", "* 5353"), ("*:*", "* 0"), ("nonsense", nil), ("[::1]8080", nil), ("1.2.3.4:99999", nil),
    ] as [(String, String?)])
    func parsesEndpoints(text: String, expected: String?) {
        #expect(LsofParser.endpoint(text).map { "\($0.address) \($0.port)" } == expected)
    }

    @Test func loopbackReachability() throws {
        let connections = LsofParser.parse(try fixture("lsof-sandbox.txt")).filter(\.isListening)
        #expect(connections.map(\.isLoopbackReachable) == [true, true, false, true])
    }

    @Test func parsesNettop() throws {
        let traffic = NettopParser.parse(try fixture("nettop.csv"))
        #expect(traffic.count == 7)
        #expect(traffic.first { $0.pid == 4121 } == ProcessTraffic(pid: 4121, process: "claude", bytesIn: 5_234_112, bytesOut: 734_001))
        #expect(traffic.first { $0.pid == 4106 }?.process == "Google Chrome H")
    }

    @Test func parsesNettopWithTimeColumn() throws {
        let traffic = NettopParser.parse(try fixture("nettop-time.csv"))
        #expect(traffic.map(\.pid) == [389, 4121])
        #expect(traffic[1].bytesIn == 5_234_112)
    }
}

@Suite struct ConnectionMonitorTests {
    @Test func readsConnectionsAsTheSandboxUser() async throws {
        let fake = try observeRunner()
        let connections = try await ConnectionMonitor(environment: alice, runner: fake).connections()
        #expect(connections.count == 9)
        #expect(fake.invocations.map(\.argv) == [[
            "/usr/bin/sudo", "-n", "-u", "sandvault-alice", "/usr/bin/env",
            "/usr/sbin/lsof", "-nP", "-i", "-a", "-u", "sandvault-alice", "-F", "pcPtnT",
        ]])
    }

    @Test func noSocketsIsNotAnError() async throws {
        let fake = FakeCommandRunner()
        fake.on(Invocations.lsof(alice).argv, stdout: "", exitCode: 1)
        #expect(try await ConnectionMonitor(environment: alice, runner: fake).connections().isEmpty)
    }

    @Test func lsofErrorsAreReported() async throws {
        let fake = FakeCommandRunner()
        fake.on(Invocations.lsof(alice).argv, stdout: "", exitCode: 1, stderr: "lsof: unsupported option\n")
        await #expect(throws: SandvaultError.self) { try await ConnectionMonitor(environment: alice, runner: fake).connections() }
        fake.on(Invocations.lsof(alice).argv, stdout: "p1\ncx\nf3\ntIPv4\nPTCP\nn*:22\nTST=LISTEN\n", exitCode: 1, stderr: "lsof: WARNING: can't stat()\n")
        #expect(try await ConnectionMonitor(environment: alice, runner: fake).connections().map(\.localPort) == [22])
    }

    @Test func refusedSudoIsAPermissionError() async throws {
        let fake = FakeCommandRunner()
        fake.on(Invocations.lsof(alice).argv, stdout: "", exitCode: 1, stderr: "sudo: a password is required\n")
        await #expect(throws: SandvaultError.sudoMissing(alice)) {
            try await ConnectionMonitor(environment: alice, runner: fake).connections()
        }
    }

    @Test func trafficIsFilteredToSandboxProcesses() async throws {
        let traffic = try await ConnectionMonitor(environment: alice, runner: try observeRunner()).traffic()
        #expect(traffic.map(\.pid) == [4121, 4130, 5223])
        let chosen = try await ConnectionMonitor(environment: alice, runner: try observeRunner()).traffic(pids: [4130])
        #expect(chosen.map(\.process) == ["node"])
    }

    @Test func localPortsAreListenersAndHelpers() async throws {
        let source = SandboxLocalPortSource(environment: alice, runner: try observeRunner(), files: try helperLogs())
        // 3000 (127.0.0.1), 5173 (*), 9229 (::1), Chrome 52341, iOS bridge 52400; not 8080 (LAN address only), not UDP.
        #expect(try await source.allowedLocalPorts() == [3000, 5173, 9229, 52341, 52400])
    }

    @Test func localPortsFailWithoutSudo() async throws {
        let fake = try observeRunner()
        fake.on(Invocations.lsof(alice).argv, stdout: "", exitCode: 1, stderr: "sudo: a password is required\n")
        let source = SandboxLocalPortSource(environment: alice, runner: fake, files: .fixed())
        await #expect(throws: SandvaultError.self) { try await source.allowedLocalPorts() }
    }
}

@Suite struct ProcessAttributorTests {
    @Test func attributesALoopbackSourcePort() async throws {
        let fake = try observeRunner()
        let attributor = CachedProcessAttributor(monitor: ConnectionMonitor(environment: alice, runner: fake))
        let owner = await attributor.process(forLocalPort: 52000, proto: .tcp)
        #expect(owner?.pid == 4121)
        #expect(owner?.name == "claude")
        #expect(await attributor.process(forLocalPort: 52000, proto: .udp) == nil)
    }

    @Test func oneLsofServesABurst() async throws {
        let fake = try observeRunner()
        let attributor = CachedProcessAttributor(monitor: ConnectionMonitor(environment: alice, runner: fake), minInterval: .seconds(5))
        async let a = attributor.process(forLocalPort: 52000, proto: .tcp)
        async let b = attributor.process(forLocalPort: 3000, proto: .tcp)
        async let c = attributor.process(forLocalPort: 52100, proto: .tcp)
        let owners = await [a, b, c].map { $0?.pid }
        #expect(owners == [4121, 4130, 5223])
        #expect(await attributor.process(forLocalPort: 5173, proto: .tcp)?.pid == 4130)
        #expect(await attributor.cache.refreshCount == 1)
    }

    @Test func aMissRefreshesAgainAfterTheMinimumInterval() async throws {
        let fake = try observeRunner()
        let attributor = CachedProcessAttributor(
            monitor: ConnectionMonitor(environment: alice, runner: fake), minInterval: .milliseconds(50), deadline: .seconds(1)
        )
        #expect(await attributor.process(forLocalPort: 1, proto: .tcp) == nil)
        #expect(await attributor.process(forLocalPort: 2, proto: .tcp) == nil)
        #expect(await attributor.cache.refreshCount == 2)
    }

    @Test func slowLsofYieldsNilWithinTheDeadline() async throws {
        let slow = SequencedRunner(delay: .seconds(10))
        slow.on(Invocations.lsof(alice).argv, stdout: try fixture("lsof-sandbox.txt"))
        let attributor = CachedProcessAttributor(monitor: ConnectionMonitor(environment: alice, runner: slow), deadline: .milliseconds(100))
        let start = ContinuousClock.now
        #expect(await attributor.process(forLocalPort: 52000, proto: .tcp) == nil)
        #expect(ContinuousClock.now - start < .seconds(5))  // generous: parallel tests share the thread pool
    }

    @Test func failingLsofAttributesNothing() async throws {
        let fake = FakeCommandRunner()
        fake.on(Invocations.lsof(alice).argv, stdout: "", exitCode: 1, stderr: "sudo: a password is required\n")
        let attributor = CachedProcessAttributor(monitor: ConnectionMonitor(environment: alice, runner: fake))
        #expect(await attributor.process(forLocalPort: 52000, proto: .tcp) == nil)
    }
}
