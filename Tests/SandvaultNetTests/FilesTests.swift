import Foundation
import SandvaultCore
import Testing
@testable import SandvaultNet

/// A temporary host home and shared workspace for one test.
struct TempLayout {
    let base: URL
    let paths: AppPaths
    let shared: SharedFiles

    init() throws {
        base = FileManager.default.temporaryDirectory.appendingPathComponent("svnet-\(UUID().uuidString)")
        let home = base.appendingPathComponent("home")
        let workspace = base.appendingPathComponent("sv-alice")
        try FileManager.default.createDirectory(at: home, withIntermediateDirectories: true)
        try FileManager.default.createDirectory(at: workspace, withIntermediateDirectories: true)
        paths = AppPaths(environment: SandvaultEnvironment(hostUser: "alice", hostHome: home.path))
        shared = SharedFiles(root: workspace.path)
    }

    /// Where `SharedFiles` puts a path that `AppPaths` places under `/Users/Shared/sv-alice`.
    func onDisk(_ sharedPath: String) -> String {
        shared.root + "/" + SharedFiles(environment: paths.environment).relativePath(for: sharedPath)!
    }

    func cleanup() {
        try? FileManager.default.removeItem(at: base)
    }
}

@Suite struct EnvironmentBlockTests {
    @Test func variablesFollowTheConfig() {
        let paths = AppPaths(environment: SandvaultEnvironment(hostUser: "alice", hostHome: "/Users/alice"))
        var policy = NetworkPolicy(mode: .proxyOnly)
        policy.ports.explicitProxy = 18080
        #expect(SandboxEnvironmentBlock.variables(policy: policy, paths: paths).map(\.name) == [
            "http_proxy", "https_proxy", "HTTP_PROXY", "HTTPS_PROXY", "NO_PROXY", "no_proxy",
        ])
        policy.inspection.enabled = true
        let body = SandboxEnvironmentBlock.body(policy: policy, paths: paths)!
        #expect(body.contains("export https_proxy='http://127.0.0.1:18080'"))
        #expect(body.contains("export NO_PROXY='localhost,127.0.0.1,::1'"))
        #expect(body.contains("export NODE_EXTRA_CA_CERTS='/Users/Shared/sv-alice/_sandvault-config/sandvault-config-ca.pem'"))
        for name in ["SSL_CERT_FILE", "REQUESTS_CA_BUNDLE", "CURL_CA_BUNDLE", "GIT_SSL_CAINFO", "AWS_CA_BUNDLE"] {
            #expect(body.contains("export \(name)='/Users/Shared/sv-alice/_sandvault-config/ca-bundle.pem'"))
        }
        policy.mode = .off
        #expect(SandboxEnvironmentBlock.body(policy: policy, paths: paths) == nil)
        #expect(SandboxEnvironmentBlock.shellQuoted("it's") == "'it'\\''s'")
    }

    @Test func writesReplacesAndRemovesTheBlockThroughSharedFiles() throws {
        let layout = try TempLayout()
        defer { layout.cleanup() }
        let file = layout.onDisk(layout.paths.sharedZshenv)
        try FileManager.default.createDirectory(atPath: (file as NSString).deletingLastPathComponent, withIntermediateDirectories: true)
        try "export EDITOR=vim\n".write(toFile: file, atomically: true, encoding: .utf8)

        var policy = NetworkPolicy(mode: .open)
        #expect(try SandboxEnvironmentBlock.apply(policy: policy, paths: layout.paths, shared: layout.shared) == .written)
        var text = try String(contentsOfFile: file, encoding: .utf8)
        #expect(text.hasPrefix("export EDITOR=vim\n"))
        #expect(text.contains(ManagedBlock.zshenv.begin))
        #expect(try SandboxEnvironmentBlock.check(policy: policy, paths: layout.paths, shared: layout.shared) == .current)
        #expect(try SandboxEnvironmentBlock.apply(policy: policy, paths: layout.paths, shared: layout.shared) == .unchanged)

        policy.ports.explicitProxy = 18999
        #expect(try SandboxEnvironmentBlock.check(policy: policy, paths: layout.paths, shared: layout.shared) == .stale)
        #expect(try SandboxEnvironmentBlock.apply(policy: policy, paths: layout.paths, shared: layout.shared) == .written)
        text = try String(contentsOfFile: file, encoding: .utf8)
        #expect(text.contains("127.0.0.1:18999"))
        #expect(text.components(separatedBy: ManagedBlock.zshenv.begin).count == 2, "exactly one block")

        policy.mode = .off
        #expect(try SandboxEnvironmentBlock.check(policy: policy, paths: layout.paths, shared: layout.shared) == .stale)
        #expect(try SandboxEnvironmentBlock.apply(policy: policy, paths: layout.paths, shared: layout.shared) == .removed)
        #expect(try String(contentsOfFile: file, encoding: .utf8) == "export EDITOR=vim\n")
        #expect(try SandboxEnvironmentBlock.check(policy: policy, paths: layout.paths, shared: layout.shared) == .current)
    }

    @Test func refusesAPlantedSymlink() throws {
        let layout = try TempLayout()
        defer { layout.cleanup() }
        let hostFile = layout.base.appendingPathComponent("home/.zshrc")
        try "host secret\n".write(to: hostFile, atomically: true, encoding: .utf8)
        let file = layout.onDisk(layout.paths.sharedZshenv)
        try FileManager.default.createDirectory(atPath: (file as NSString).deletingLastPathComponent, withIntermediateDirectories: true)
        try FileManager.default.createSymbolicLink(atPath: file, withDestinationPath: hostFile.path)

        #expect(throws: SandvaultError.self) {
            try SandboxEnvironmentBlock.apply(policy: NetworkPolicy(mode: .proxyOnly), paths: layout.paths, shared: layout.shared)
        }
        #expect(try String(contentsOf: hostFile, encoding: .utf8) == "host secret\n")
        #expect(try FileManager.default.destinationOfSymbolicLink(atPath: file) == hostFile.path)
    }
}

@Suite struct CertificateAuthorityTests {
    @Test func createsSavesAndReloadsTheCA() throws {
        let layout = try TempLayout()
        defer { layout.cleanup() }
        let store = CAStore(paths: layout.paths)
        #expect(try store.load() == nil)
        let (ca, created) = try store.loadOrCreate(hostUser: "alice")
        #expect(created)
        #expect(ca.subject.contains("CN=Sandvault Config Inspection CA (alice)"))
        let keyMode = try FileManager.default.attributesOfItem(atPath: store.keyPath)[.posixPermissions] as? NSNumber
        #expect(keyMode?.intValue == 0o600)
        let dirMode = try FileManager.default.attributesOfItem(atPath: store.directory)[.posixPermissions] as? NSNumber
        #expect(dirMode?.intValue == 0o700)

        let (again, createdAgain) = try store.loadOrCreate(hostUser: "alice")
        #expect(!createdAgain)
        #expect(try again.fingerprint == ca.fingerprint)
        #expect(try ca.fingerprint.split(separator: ":").count == 32)
        try store.remove()
        #expect(!store.exists)
    }

    @Test func issuesLeavesSignedByTheCA() throws {
        let ca = try InspectionCA.generate(hostUser: "alice")
        let leaf = try ca.issueLeaf(for: "api.example.com", publicKey: ca.privateKey.publicKey)
        #expect(leaf.issuer == ca.certificate.subject)
        #expect(leaf.notValidAfter.timeIntervalSinceNow < 31 * 86_400)
        #expect(leaf.description.contains("api.example.com"))
    }

    @Test func rejectsAMismatchedKey() throws {
        let one = try InspectionCA.generate(hostUser: "alice")
        let two = try InspectionCA.generate(hostUser: "alice")
        #expect(throws: SandvaultError.self) { try InspectionCA(certificatePEM: one.certificatePEM, privateKeyPEM: two.privateKeyPEM) }
    }

    @Test func publishesCertificateAndBundleThroughSharedFiles() async throws {
        let layout = try TempLayout()
        defer { layout.cleanup() }
        let ca = try InspectionCA.generate(hostUser: "alice")
        var publisher = CAPublisher(paths: layout.paths, runner: FakeCommandRunner(), shared: layout.shared)
        publisher.rootBundlePath = Bundle.module.url(forResource: "root-bundle", withExtension: "pem", subdirectory: "Fixtures")!.path

        #expect(try publisher.state(of: ca) == .missing)
        let result = try await publisher.publish(ca)
        #expect(result.systemRootCount == 2)
        let certificate = try String(contentsOfFile: layout.onDisk(layout.paths.publicCACertificate), encoding: .utf8)
        #expect(certificate == (try ca.certificatePEM))
        let bundle = try String(contentsOfFile: layout.onDisk(layout.paths.publicCABundle), encoding: .utf8)
        #expect(bundle.components(separatedBy: "BEGIN CERTIFICATE").count - 1 == 3)
        #expect(bundle.hasSuffix(try ca.certificatePEM))
        #expect(try publisher.state(of: ca) == .current)
        #expect(try publisher.state(of: InspectionCA.generate(hostUser: "alice")) == .stale)

        try publisher.unpublish()
        #expect(try publisher.state(of: ca) == .missing)
    }
}

@Suite struct ConnectionLogTests {
    func record(_ host: String, _ decision: ConnectionDecision = .allowed) -> ConnectionRecord {
        ConnectionRecord(kind: .explicitProxy, host: host, port: 443, decision: decision)
    }

    @Test func appendsJSONLinesAndKeepsARing() throws {
        let layout = try TempLayout()
        defer { layout.cleanup() }
        let log = ConnectionLog(path: layout.paths.connectionLog, capacity: 3)
        for index in 0..<5 { log.append(record("h\(index).test", index.isMultiple(of: 2) ? .allowed : .denied)) }
        log.close()
        #expect(log.recent(limit: 10).map(\.host) == ["h2.test", "h3.test", "h4.test"])
        #expect(log.recent(limit: 1).map(\.host) == ["h4.test"])
        let mode = try FileManager.default.attributesOfItem(atPath: layout.paths.connectionLog)[.posixPermissions] as? NSNumber
        #expect(mode?.intValue == 0o600)

        let all = try ConnectionLog.read(path: layout.paths.connectionLog, limit: 100)
        #expect(all.map(\.host) == ["h0.test", "h1.test", "h2.test", "h3.test", "h4.test"])
        let denied = try ConnectionLog.read(path: layout.paths.connectionLog, limit: 100, filter: ConnectionFilter(deniedOnly: true))
        #expect(denied.map(\.host) == ["h1.test", "h3.test"])
        let byHost = try ConnectionLog.read(path: layout.paths.connectionLog, limit: 100, filter: ConnectionFilter(host: "H4"))
        #expect(byHost.map(\.host) == ["h4.test"])
        #expect(try ConnectionLog.read(path: layout.paths.connectionLog, limit: 2).map(\.host) == ["h3.test", "h4.test"])
    }

    @Test func rotatesAndKeepsThreeFiles() throws {
        let layout = try TempLayout()
        defer { layout.cleanup() }
        let path = layout.paths.connectionLog
        let lineSize = try JSONCoding.lineEncoder.encode(record("r00.test")).count + 1
        let log = ConnectionLog(path: path, maxBytes: lineSize * 2, keep: 3)
        for index in 0..<10 { log.append(record(String(format: "r%02d.test", index))) }
        log.close()
        let manager = FileManager.default
        #expect(manager.fileExists(atPath: path + ".1") && manager.fileExists(atPath: path + ".3"))
        #expect(!manager.fileExists(atPath: path + ".4"))
        // Two records per file: the current file holds the newest two, the three rotations the six before.
        let kept = try ConnectionLog.read(path: path, limit: 100)
        #expect(kept.map(\.host) == (2..<10).map { String(format: "r%02d.test", $0) })
    }

    @Test func blockedDecisions() {
        #expect(ConnectionDecision.denied.blocked && ConnectionDecision.askedDenied.blocked && ConnectionDecision.timedOut.blocked)
        #expect(!ConnectionDecision.allowed.blocked && !ConnectionDecision.askedAllowed.blocked)
    }
}
