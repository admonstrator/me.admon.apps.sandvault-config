import Foundation
import Testing
@testable import SandvaultCore

@Suite struct ConfigTests {
    @Test func emptyObjectDecodesToDefaults() throws {
        let config = try JSONCoding.decoder.decode(AppConfig.self, from: Data("{}".utf8))
        #expect(config == AppConfig())
        #expect(config.network.mode == .off)
        #expect(config.network.defaultAction == .ask)
        #expect(config.network.askFallback == .deny)
        #expect(config.network.blockLAN)
        #expect(config.network.ports == ProxyPorts(explicitProxy: 18080, transparentHTTP: 18081, transparentTLS: 18443, dns: 18053))
        #expect(config.network.inspection.enabled == false)
        #expect(config.sandbox.preset == .standard)
    }

    @Test func partialObjectsKeepDefaultsAndIgnoreUnknownKeys() throws {
        let json = #"{"network":{"mode":"proxyOnly","ports":{"dns":5353},"future":1},"sandbox":{"fileRules":[{"path":"/opt/data","access":"read","effect":"allow"}]}}"#
        let config = try JSONCoding.decoder.decode(AppConfig.self, from: Data(json.utf8))
        #expect(config.network.mode == .proxyOnly)
        #expect(config.network.ports.dns == 5353)
        #expect(config.network.ports.explicitProxy == 18080)
        #expect(config.sandbox.fileRules.count == 1)
        #expect(config.sandbox.fileRules[0].match == .subpath)
    }

    @Test func roundTripIsStable() throws {
        var config = AppConfig()
        config.sandbox.fileRules = [FileRule(path: "/opt/tools", access: .read, effect: .allow, note: "tools")]
        config.sandbox.machRules = [MachRule(name: "com.apple.pasteboard.1", effect: .deny)]
        config.sandbox.execRules = [ExecRule(path: "/usr/bin/osascript")]
        config.network.domainRules = [DomainRule(pattern: "*.github.com", action: .allow, createdAt: Date(timeIntervalSince1970: 1_700_000_000))]
        config.network.dnsOverrides = [DnsOverride(pattern: "api.example.test", address: "127.0.0.1")]
        config.network.portExceptions = [PortException(proto: .tcp, destination: "140.82.112.0/20", port: 22)]
        config.repos = [HandoffRecord(hostPath: "/Users/alice/src/app", repoName: "app", sandboxPath: "/Users/Shared/sv-alice/repos/app", agent: .claude, createdAt: Date(timeIntervalSince1970: 1_700_000_000))]
        let first = try JSONCoding.encoder.encode(config)
        let decoded = try JSONCoding.decoder.decode(AppConfig.self, from: first)
        #expect(decoded == config)
        #expect(try JSONCoding.encoder.encode(decoded) == first)
    }

    @Test func storeWritesOwnerOnlyFile() throws {
        let directory = FileManager.default.temporaryDirectory.appendingPathComponent("svctl-config-\(UUID().uuidString)")
        defer { try? FileManager.default.removeItem(at: directory) }
        let store = ConfigStore(path: directory.appendingPathComponent("nested/config.json").path)
        #expect(try store.load() == AppConfig())

        var config = AppConfig()
        config.network.mode = .open
        try store.save(config)
        try store.save(config)
        #expect(try store.load() == config)

        let attributes = try FileManager.default.attributesOfItem(atPath: store.url.path)
        #expect((attributes[.posixPermissions] as? NSNumber)?.intValue == 0o600)
        let leftovers = try FileManager.default.contentsOfDirectory(atPath: store.url.deletingLastPathComponent().path)
        #expect(leftovers == ["config.json"])
    }
}
