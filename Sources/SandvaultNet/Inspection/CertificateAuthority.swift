import Crypto
import Foundation
import SandvaultCore
import X509

/// The local CA for TLS inspection: a P-256 key and a self-signed CA certificate.
public struct InspectionCA: Sendable {
    public let certificate: Certificate
    public let privateKey: P256.Signing.PrivateKey

    public init(certificate: Certificate, privateKey: P256.Signing.PrivateKey) {
        self.certificate = certificate
        self.privateKey = privateKey
    }

    public static func commonName(hostUser: String) -> String {
        "\(BundleIdentity.displayName) Inspection CA (\(hostUser))"
    }

    /// A new CA valid for ten years.
    public static func generate(hostUser: String, now: Date = Date()) throws -> InspectionCA {
        let key = P256.Signing.PrivateKey()
        let publicKey = Certificate.PublicKey(key.publicKey)
        let name = try DistinguishedName {
            OrganizationName(BundleIdentity.displayName)
            CommonName(commonName(hostUser: hostUser))
        }
        let extensions = try Certificate.Extensions {
            Critical(BasicConstraints.isCertificateAuthority(maxPathLength: 0))
            Critical(KeyUsage(digitalSignature: true, keyCertSign: true, cRLSign: true))
            SubjectKeyIdentifier(hash: publicKey)
        }
        let certificate = try Certificate(
            version: .v3,
            serialNumber: Certificate.SerialNumber(),
            publicKey: publicKey,
            notValidBefore: now.addingTimeInterval(-3600),
            notValidAfter: now.addingTimeInterval(10 * 365 * 86_400),
            issuer: name,
            subject: name,
            signatureAlgorithm: .ecdsaWithSHA256,
            extensions: extensions,
            issuerPrivateKey: Certificate.PrivateKey(key)
        )
        return InspectionCA(certificate: certificate, privateKey: key)
    }

    public init(certificatePEM: String, privateKeyPEM: String) throws {
        do {
            certificate = try Certificate(pemEncoded: certificatePEM)
            privateKey = try P256.Signing.PrivateKey(pemRepresentation: privateKeyPEM)
        } catch {
            throw SandvaultError.io("cannot parse inspection CA: \(error)")
        }
        guard certificate.publicKey == Certificate.PublicKey(privateKey.publicKey) else {
            throw SandvaultError.invalidInput("inspection CA key does not match its certificate")
        }
    }

    public var certificatePEM: String {
        get throws { try certificate.serializeAsPEM().pemString + "\n" }
    }

    public var privateKeyPEM: String { privateKey.pemRepresentation + "\n" }

    /// SHA-256 over the DER certificate, uppercase hex pairs separated by colons (like `openssl x509 -fingerprint`).
    public var fingerprint: String {
        get throws { try Self.fingerprint(der: certificate.serializeAsPEM().derBytes) }
    }

    static func fingerprint(der: [UInt8]) -> String {
        SHA256.hash(data: der).map { String(format: "%02X", $0) }.joined(separator: ":")
    }

    public var subject: String { certificate.subject.description }
    public var notValidAfter: Date { certificate.notValidAfter }

    /// A server certificate for `host` (DNS SAN, serverAuth), signed by this CA, valid for 30 days.
    public func issueLeaf(for host: String, publicKey: P256.Signing.PublicKey, now: Date = Date()) throws -> Certificate {
        let subject = try DistinguishedName {
            OrganizationName(BundleIdentity.displayName)
            CommonName(String(host.prefix(64)))
        }
        let leafKey = Certificate.PublicKey(publicKey)
        let extensions = try Certificate.Extensions {
            Critical(BasicConstraints.notCertificateAuthority)
            Critical(KeyUsage(digitalSignature: true))
            try ExtendedKeyUsage([.serverAuth])
            SubjectAlternativeNames([.dnsName(host)])
            SubjectKeyIdentifier(hash: leafKey)
            AuthorityKeyIdentifier(keyIdentifier: try certificate.extensions.subjectKeyIdentifier?.keyIdentifier)
        }
        return try Certificate(
            version: .v3,
            serialNumber: Certificate.SerialNumber(),
            publicKey: leafKey,
            notValidBefore: now.addingTimeInterval(-86_400),
            notValidAfter: now.addingTimeInterval(30 * 86_400),
            issuer: certificate.subject,
            subject: subject,
            signatureAlgorithm: .ecdsaWithSHA256,
            extensions: extensions,
            issuerPrivateKey: Certificate.PrivateKey(privateKey)
        )
    }
}

/// CA files in `AppPaths.caDir` (host-only): `ca-key.pem` (mode 0600) and `ca-cert.pem`.
public struct CAStore: Sendable {
    public var directory: String

    public init(directory: String) {
        self.directory = directory
    }

    public init(paths: AppPaths) {
        self.init(directory: paths.caDir)
    }

    public var keyPath: String { "\(directory)/ca-key.pem" }
    public var certificatePath: String { "\(directory)/ca-cert.pem" }

    public var exists: Bool {
        FileManager.default.fileExists(atPath: keyPath) && FileManager.default.fileExists(atPath: certificatePath)
    }

    /// `nil` when no CA has been created yet.
    public func load() throws -> InspectionCA? {
        guard exists else { return nil }
        let certificate = try String(contentsOfFile: certificatePath, encoding: .utf8)
        let key = try String(contentsOfFile: keyPath, encoding: .utf8)
        return try InspectionCA(certificatePEM: certificate, privateKeyPEM: key)
    }

    public func save(_ ca: InspectionCA) throws {
        try FileManager.default.createDirectory(atPath: directory, withIntermediateDirectories: true, attributes: [.posixPermissions: 0o700])
        try AtomicFile.write(Data(ca.privateKeyPEM.utf8), to: keyPath, permissions: 0o600)
        try AtomicFile.write(Data(try ca.certificatePEM.utf8), to: certificatePath, permissions: 0o644)
    }

    /// Loads the existing CA or creates and saves a new one.
    public func loadOrCreate(hostUser: String) throws -> (ca: InspectionCA, created: Bool) {
        if let existing = try load() { return (existing, false) }
        let ca = try InspectionCA.generate(hostUser: hostUser)
        try save(ca)
        return (ca, true)
    }

    public func remove() throws {
        for path in [keyPath, certificatePath] where FileManager.default.fileExists(atPath: path) {
            try FileManager.default.removeItem(atPath: path)
        }
    }
}
