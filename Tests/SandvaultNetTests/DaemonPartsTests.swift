import Foundation
import SandvaultCore
import Testing
@testable import SandvaultNet

@Suite struct LaunchAgentTests {
    func agent(_ runner: FakeCommandRunner, home: String = "/Users/alice") -> NetdLaunchAgent {
        var agent = NetdLaunchAgent(paths: AppPaths(environment: SandvaultEnvironment(hostUser: "alice", hostHome: home)), runner: runner, uid: 501)
        agent.platformSupported = true
        return agent
    }

    @Test func propertyListRunsNetdAndKeepsItAlive() throws {
        let paths = AppPaths(environment: SandvaultEnvironment(hostUser: "alice", hostHome: "/Users/alice"))
        let data = try NetdLaunchAgent.propertyList(executable: "/Applications/Sandvault Config.app/Contents/MacOS/sandvault-netd", paths: paths)
        let plist = try #require(try PropertyListSerialization.propertyList(from: data, format: nil) as? [String: Any])
        #expect(plist["Label"] as? String == "me.admon.apps.sandvault-config.netd")
        #expect(plist["ProgramArguments"] as? [String] == ["/Applications/Sandvault Config.app/Contents/MacOS/sandvault-netd", "run"])
        #expect(plist["RunAtLoad"] as? Bool == true)
        #expect(plist["KeepAlive"] as? Bool == true)
        #expect(plist["StandardErrorPath"] as? String == "/Users/alice/Library/Application Support/me.admon.apps.sandvault-config/logs/netd.log")
        #expect(String(decoding: data, as: UTF8.self).hasPrefix("<?xml"))
    }

    @Test func parsesLaunchctlPrint() throws {
        let running = NetdLaunchAgent.parsePrint(try Fixture.text("launchctl-print-netd-running.txt"))
        #expect(running.state == "running")
        #expect(running.pid == 4242)
        #expect(running.lastExitCode == "(never exited)")
        #expect(running.executable == "/Applications/Sandvault Config.app/Contents/MacOS/sandvault-netd")
        let exited = NetdLaunchAgent.parsePrint(try Fixture.text("launchctl-print-netd-exited.txt"))
        #expect(exited.state == "not running")
        #expect(exited.pid == nil)
        #expect(exited.lastExitCode == "1")
    }

    @Test func installBootstrapsAndUninstallBootsOut() async throws {
        let layout = try TempLayout()
        defer { layout.cleanup() }
        let runner = FakeCommandRunner()
        runner.on(["/bin/launchctl", "bootout"], stdout: "", exitCode: 113)
        runner.on(["/bin/launchctl", "bootstrap", "gui/501"], stdout: "")
        let agent = agent(runner, home: layout.paths.environment.hostHome)
        let executable = layout.base.appendingPathComponent("sandvault-netd").path
        try "#!/bin/sh\n".write(toFile: executable, atomically: true, encoding: .utf8)
        try FileManager.default.setAttributes([.posixPermissions: 0o755], ofItemAtPath: executable)

        try await agent.install(executable: executable)
        #expect(FileManager.default.fileExists(atPath: agent.plistPath))
        #expect(runner.invocations.map(\.argv).last == ["/bin/launchctl", "bootstrap", "gui/501", agent.plistPath])

        try await agent.uninstall()
        #expect(!FileManager.default.fileExists(atPath: agent.plistPath))
        #expect(runner.invocations.map(\.argv).last == ["/bin/launchctl", "bootout", "gui/501/me.admon.apps.sandvault-config.netd"])
    }

    @Test func statusCombinesPlistAndLaunchd() async throws {
        let runner = FakeCommandRunner()
        runner.on(["/bin/launchctl", "print", "gui/501/me.admon.apps.sandvault-config.netd"], stdout: try Fixture.text("launchctl-print-netd-running.txt"))
        let status = try await agent(runner, home: "/nonexistent").status()
        #expect(!status.installed)
        #expect(status.loaded && status.pid == 4242)

        let missing = FakeCommandRunner()
        missing.on(["/bin/launchctl", "print"], stdout: "", exitCode: 113, stderr: "Could not find service")
        let unloaded = try await agent(missing).status()
        #expect(!unloaded.loaded && unloaded.state == nil)
    }

    @Test func refusesOffMac() async {
        var agent = agent(FakeCommandRunner())
        agent.platformSupported = false
        await #expect(throws: SandvaultError.unsupportedPlatform("LaunchAgents (launchd) exist only on macOS")) { try await agent.restart() }
    }
}

@Suite struct LocalPortRefresherTests {
    final class Ports: LocalPortSource, @unchecked Sendable {
        let lock = NSLock()
        var ports: [UInt16] = []
        var error: Error?
        func allowedLocalPorts() async throws -> [UInt16] {
            try lock.withLock {
                if let error { throw error }
                return ports
            }
        }
    }

    final class Applier: PolicyApplier, @unchecked Sendable {
        let lock = NSLock()
        var applied: [AppliedState] = []
        var error: Error?
        func applyFirewall(_ state: AppliedState) async throws -> HelperResult {
            try lock.withLock {
                if let error { throw error }
                applied.append(state)
                return HelperResult(ok: true, message: "ok")
            }
        }
        func applyProfile(_ state: AppliedState) async throws -> HelperResult { HelperResult(ok: true, message: "") }
    }

    final class Messages: @unchecked Sendable {
        let lock = NSLock()
        var lines: [String] = []
        func add(_ line: String) { lock.withLock { lines.append(line) } }
    }

    @Test func appliesOnlyWhenPortsChange() async {
        let ports = Ports(), applier = Applier(), messages = Messages()
        let refresher = LocalPortRefresher(source: ports, applier: applier, log: messages.add)
        var config = AppConfig()
        config.network.mode = .proxyOnly

        ports.ports = [9222, 18080, 9222]
        #expect(await refresher.tick(config: config) == .applied([9222, 18080]))
        #expect(await refresher.tick(config: config) == .unchanged([9222, 18080]))
        ports.ports = [9222]
        #expect(await refresher.tick(config: config) == .applied([9222]))
        #expect(applier.applied.map(\.dynamicLocalPorts) == [[9222, 18080], [9222]])
        #expect(applier.applied.last?.network.mode == .proxyOnly)

        config.network.localhost = .allowAll
        #expect(await refresher.tick(config: config) == .notApplicable)
        config.network.localhost = .sandboxAndHelpers
        config.network.mode = .off
        #expect(await refresher.tick(config: config) == .notApplicable)
        // After a pause the same ports are applied again.
        config.network.mode = .open
        #expect(await refresher.tick(config: config) == .applied([9222]))
    }

    @Test func logsEachErrorKindOnce() async {
        let ports = Ports(), applier = Applier(), messages = Messages()
        let refresher = LocalPortRefresher(source: ports, applier: applier, log: messages.add)
        var config = AppConfig()
        config.network.mode = .open
        applier.error = SandvaultError.notImplemented("Enforce.applyFirewall")
        for _ in 0..<3 { #expect(await refresher.tick(config: config) == .failed("firewall refresh: notImplemented")) }
        ports.error = SandvaultError.notImplemented("Observe.makeLocalPortSource")
        for _ in 0..<2 { #expect(await refresher.tick(config: config) == .failed("local ports: notImplemented")) }
        #expect(messages.lines.count == 2)
        #expect(messages.lines[0].contains("not implemented yet: Enforce.applyFirewall"))
    }
}

@Suite struct AskCoordinatorTests {
    final class Saved: @unchecked Sendable {
        let lock = NSLock()
        var rules: [(String, DomainAction)] = []
    }

    func coordinator(subscribed: Bool, saved: Saved = Saved()) -> (AskCoordinator, ControlHub) {
        let hub = ControlHub()
        if subscribed {
            let id = UUID()
            hub.add(id) { _ in }
            hub.subscribe(id, topics: [.asks])
        }
        let coordinator = AskCoordinator(
            hub: hub,
            persist: { pattern, action in
                saved.lock.withLock { saved.rules.append((pattern, action)) }
                return DomainRule(pattern: pattern, action: action)
            },
            log: { _ in }
        )
        return (coordinator, hub)
    }

    @Test func fallsBackWithoutASubscribedClient() async {
        let (asks, _) = coordinator(subscribed: false)
        var policy = NetworkPolicy()
        let denied = await asks.decide(host: "a.test", port: 443, kind: .explicitProxy, owner: nil, policy: policy)
        #expect(!denied.allowed && denied.decision == .timedOut)
        policy.askFallback = .allow
        let allowed = await asks.decide(host: "a.test", port: 443, kind: .explicitProxy, owner: nil, policy: policy)
        #expect(allowed.allowed && allowed.decision == .allowed)
        #expect(await asks.pendingCount == 0)
    }

    @Test func concurrentAsksShareOneRequestAndOneAnswer() async throws {
        let saved = Saved()
        let (asks, _) = coordinator(subscribed: true, saved: saved)
        let policy = NetworkPolicy(askTimeoutSeconds: 30)
        async let first = asks.decide(host: "api.github.com", port: 443, kind: .explicitProxy, owner: ProcessOwner(pid: 42, name: "curl"), policy: policy)
        async let second = asks.decide(host: "api.github.com", port: 443, kind: .transparentTLS, owner: nil, policy: policy)
        var pending: [AskRequest] = []
        for _ in 0..<200 {
            pending = await asks.pendingRequests()
            if !pending.isEmpty { break }
            try await Task.sleep(nanoseconds: 5_000_000)
        }
        #expect(pending.count == 1)
        #expect(pending.first?.host == "api.github.com")
        // Give the second caller time to join the same request.
        try await Task.sleep(nanoseconds: 50_000_000)
        try await asks.answer(AskAnswer(id: pending[0].id, decision: .allowAlways, scope: .domain))
        let results = await [first, second]
        #expect(results.allSatisfy { $0.allowed && $0.decision == .askedAllowed })
        #expect(saved.rules.map(\.0) == ["*.github.com"])
        #expect(saved.rules.map(\.1) == [.allow])
        // The answer is remembered briefly, so the next connection does not ask again.
        let next = await asks.decide(host: "api.github.com", port: 443, kind: .explicitProxy, owner: nil, policy: policy)
        #expect(next.decision == .askedAllowed)
        await #expect(throws: SandvaultError.self) { try await asks.answer(AskAnswer(id: pending[0].id, decision: .denyOnce)) }
    }

    @Test func timesOutToTheFallback() async {
        let (asks, _) = coordinator(subscribed: true)
        let started = Date()
        let result = await asks.decide(host: "slow.test", port: 443, kind: .explicitProxy, owner: nil, policy: NetworkPolicy(askTimeoutSeconds: 1))
        #expect(result.decision == .timedOut && !result.allowed)
        #expect(Date().timeIntervalSince(started) >= 0.9)
        #expect(await asks.pendingCount == 0)
    }

    @Test func dnsRaisesWithoutWaiting() async throws {
        let (asks, _) = coordinator(subscribed: true)
        let policy = NetworkPolicy()
        #expect(await asks.raise(host: "new.test", kind: .dns, owner: nil, policy: policy) == nil)
        let pending = await asks.pendingRequests()
        #expect(pending.count == 1 && pending[0].kind == .dns)
        try await asks.answer(AskAnswer(id: pending[0].id, decision: .denyOnce))
        #expect(await asks.raise(host: "new.test", kind: .dns, owner: nil, policy: policy)?.decision == .askedDenied)
    }
}
