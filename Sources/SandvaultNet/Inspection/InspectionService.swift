import Crypto
import Foundation
import NIOSSL
import SandvaultCore
import X509

/// TLS material for inspected connections: the CA (reloaded on demand), one in-memory leaf key,
/// a cache of per-host server contexts and the verifying client context for the upstream side.
final class InspectionService: @unchecked Sendable {
    static let cacheLifetime: TimeInterval = 24 * 3600
    static let cacheLimit = 512

    let store: CAStore
    let upstreamContext: NIOSSLContext

    private let lock = NSLock()
    private var ca: InspectionCA?
    private var fingerprintValue: String?
    private let leafKey = P256.Signing.PrivateKey()
    private let nioLeafKey: NIOSSLPrivateKey
    private var contexts: [String: (context: NIOSSLContext, created: Date)] = [:]

    init(store: CAStore, upstreamTrustRoots: NIOSSLTrustRoots) throws {
        self.store = store
        nioLeafKey = try NIOSSLPrivateKey(bytes: Array(leafKey.pemRepresentation.utf8), format: .pem)
        var client = TLSConfiguration.makeClientConfiguration()
        client.trustRoots = upstreamTrustRoots
        client.applicationProtocols = ["http/1.1"]
        upstreamContext = try NIOSSLContext(configuration: client)
    }

    /// Re-reads the CA from disk; clears cached leaf contexts when it changed.
    func reload() throws {
        let loaded = try store.load()
        let fingerprint = try loaded?.fingerprint
        lock.withLock {
            if fingerprint != fingerprintValue { contexts.removeAll() }
            ca = loaded
            fingerprintValue = fingerprint
        }
    }

    var isAvailable: Bool { lock.withLock { ca != nil } }
    var fingerprint: String? { lock.withLock { fingerprintValue } }

    /// Server context presenting a leaf for `host`, ALPN `http/1.1` only.
    func serverContext(for host: String) throws -> NIOSSLContext {
        let now = Date()
        let (cached, authority): (NIOSSLContext?, InspectionCA?) = lock.withLock {
            if let entry = contexts[host], now.timeIntervalSince(entry.created) < Self.cacheLifetime { return (entry.context, ca) }
            return (nil, ca)
        }
        if let cached { return cached }
        guard let authority else { throw SandvaultError.notInstalled("inspection CA (run `svctl ca create`)") }

        let leaf = try authority.issueLeaf(for: host, publicKey: leafKey.publicKey, now: now)
        let chain = try [leaf, authority.certificate].map {
            try NIOSSLCertificate(bytes: Array($0.serializeAsPEM().pemString.utf8), format: .pem)
        }
        var configuration = TLSConfiguration.makeServerConfiguration(
            certificateChain: chain.map { .certificate($0) }, privateKey: .privateKey(nioLeafKey)
        )
        configuration.applicationProtocols = ["http/1.1"]
        let context = try NIOSSLContext(configuration: configuration)
        lock.withLock {
            if contexts.count >= Self.cacheLimit { contexts.removeAll() }
            contexts[host] = (context, now)
        }
        return context
    }
}
