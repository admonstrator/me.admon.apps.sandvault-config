import Foundation
import Testing
@testable import SandvaultCore
@testable import SandvaultEnforce

@Suite struct CheckProviderTests {
    let root: TempRoot
    let helperPath: String
    let fake = FakeCommandRunner()

    init() throws {
        root = try TempRoot()
        helperPath = root.path + "/helper"
        try Data("#!/bin/sh\n".utf8).write(to: URL(fileURLWithPath: helperPath))
        try FileManager.default.setAttributes([.posixPermissions: 0o755], ofItemAtPath: helperPath)
        fake.on(["/usr/bin/sudo", "-n", "-l", helperPath, "status", "--json"], stdout: "\(helperPath) status --json\n")
    }

    func provider(_ config: AppConfig, status: HelperStatus?, macOS: Bool = true) throws -> EnforceCheckProvider {
        if let status {
            let result = HelperResult(ok: true, message: status.summary, details: status.details)
            fake.on(["/usr/bin/sudo", "-n", AppPaths.helperPath, "status"], stdout: String(decoding: try JSONCoding.lineEncoder.encode(result), as: UTF8.self))
        }
        var provider = EnforceCheckProvider(environment: root.alice, runner: fake, config: config)
        provider.helperPath = helperPath
        provider.isMacOS = macOS
        provider.inspector = ProfileInspector(profilePath: root.path + root.alice.sandboxProfilePath, recordPath: root.path + "/none.json")
        return provider
    }

    func states(_ checks: [Check]) -> [String: CheckState] {
        Dictionary(uniqueKeysWithValues: checks.map { ($0.id, $0.state) })
    }

    @Test func healthyInstall() async throws {
        defer { root.cleanup() }
        var config = AppConfig()
        config.network.mode = .proxyOnly
        var status = HelperStatus()
        status.firewallMode = .proxyOnly
        status.pfEnabled = true
        let checks = try await provider(config, status: status).checks()
        #expect(states(checks) == [
            "enforce.helper": .ok, "enforce.profile": .ok, "enforce.firewall": .ok, "enforce.integrity": .ok, "enforce.panic": .ok,
        ])
    }

    @Test func driftTamperAndPanicAreReported() async throws {
        defer { root.cleanup() }
        var config = AppConfig()
        config.sandbox = SBPLGeneratorTests.rules
        config.network.mode = .open
        var status = HelperStatus()
        status.firewallMode = .blocked
        status.panicActive = true
        status.anchorChanged = true
        let checks = try await provider(config, status: status).checks()
        let byID = Dictionary(uniqueKeysWithValues: checks.map { ($0.id, $0) })
        #expect(byID["enforce.profile"]?.state == .warning)
        #expect(byID["enforce.profile"]?.fix == "svctl rules apply")
        #expect(byID["enforce.firewall"]?.detail == "config says open, loaded is blocked")
        #expect(byID["enforce.integrity"]?.state == .failure)
        #expect(byID["enforce.integrity"]?.detail == "pf anchor differs from the last apply")
        #expect(byID["enforce.panic"]?.state == .warning)
    }

    @Test func missingSudoersRuleAndMissingHelper() async throws {
        defer { root.cleanup() }
        fake.on(["/usr/bin/sudo", "-n", "-l", helperPath, "status", "--json"], stdout: "", exitCode: 1, stderr: "sudo: a password is required")
        var config = AppConfig()
        config.network.mode = .open
        var checks = try await provider(config, status: nil).checks()
        #expect(states(checks)["enforce.helper"] == .failure)
        #expect(states(checks)["enforce.firewall"] == .unknown)

        try FileManager.default.removeItem(atPath: helperPath)
        checks = try await provider(AppConfig(), status: nil).checks()
        #expect(states(checks)["enforce.helper"] == .skipped)
        checks = try await provider(config, status: nil).checks()
        #expect(states(checks)["enforce.helper"] == .warning)
    }

    @Test func offMacOSOnlyTheProfileIsChecked() async throws {
        defer { root.cleanup() }
        let checks = try await provider(AppConfig(), status: nil, macOS: false).checks()
        #expect(states(checks) == ["enforce.helper": .skipped, "enforce.profile": .ok, "enforce.firewall": .skipped, "enforce.integrity": .skipped])
        #expect(Enforce.makeCheckProvider(environment: root.alice, runner: fake, config: AppConfig()) is EnforceCheckProvider)
    }
}
