import Foundation
import SandvaultCore

/// Puts the CA certificate and a bundle (system roots plus the CA) into the shared workspace,
/// where the sandbox's `.zshenv` block points tools at them. Written through `SharedFiles` only.
public struct CAPublisher: Sendable {
    public var paths: AppPaths
    public var runner: CommandRunner
    /// The shared workspace; tests point it at a temporary directory.
    public var shared: SharedFiles
    /// Read the system roots from this PEM file instead of the platform source.
    public var rootBundlePath: String?

    public init(paths: AppPaths, runner: CommandRunner, shared: SharedFiles? = nil) {
        self.paths = paths
        self.runner = runner
        self.shared = shared ?? SharedFiles(environment: paths.environment)
    }

    public static let macRootKeychain = "/System/Library/Keychains/SystemRootCertificates.keychain"
    public static let linuxRootBundle = "/etc/ssl/certs/ca-certificates.crt"

    public struct Result: Codable, Sendable, Equatable {
        public var certificatePath: String
        public var bundlePath: String
        public var systemRootCount: Int
    }

    public enum State: String, Codable, Sendable {
        case current, missing, stale
    }

    /// PEM text of the platform's trusted roots.
    public func systemRootsPEM() async throws -> String {
        #if canImport(Darwin)
        if rootBundlePath == nil {
            let invocation = CommandInvocation("/usr/bin/security", ["find-certificate", "-a", "-p", Self.macRootKeychain])
            return try await runner.checked(invocation).stdoutString
        }
        #endif
        let path = rootBundlePath ?? Self.linuxRootBundle
        do {
            return try String(contentsOfFile: path, encoding: .utf8)
        } catch {
            throw SandvaultError.notInstalled("system CA bundle \(path)")
        }
    }

    public func publish(_ ca: InspectionCA) async throws -> Result {
        let certificate = try ca.certificatePEM
        let roots = try await systemRootsPEM()
        var bundle = roots
        if !bundle.isEmpty && !bundle.hasSuffix("\n") { bundle += "\n" }
        bundle += "# \(InspectionCA.commonName(hostUser: paths.environment.hostUser))\n" + certificate
        try shared.write(Data(certificate.utf8), to: try paths.sharedRelative(paths.publicCACertificate), permissions: 0o644)
        try shared.write(Data(bundle.utf8), to: try paths.sharedRelative(paths.publicCABundle), permissions: 0o644)
        let count = roots.components(separatedBy: "-----BEGIN CERTIFICATE-----").count - 1
        return Result(certificatePath: paths.publicCACertificate, bundlePath: paths.publicCABundle, systemRootCount: count)
    }

    public func unpublish() throws {
        try shared.remove(try paths.sharedRelative(paths.publicCACertificate))
        try shared.remove(try paths.sharedRelative(paths.publicCABundle))
    }

    /// Whether the published certificate is the CA's and the bundle contains it. Untrusted content is only compared.
    public func state(of ca: InspectionCA) throws -> State {
        let certificate = try ca.certificatePEM
        guard let published = try shared.read(try paths.sharedRelative(paths.publicCACertificate)),
              let bundle = try shared.read(try paths.sharedRelative(paths.publicCABundle), maxBytes: 8 << 20)
        else { return .missing }
        let current = String(decoding: published, as: UTF8.self) == certificate
            && String(decoding: bundle, as: UTF8.self).contains(certificate)
        return current ? .current : .stale
    }
}

extension AppPaths {
    /// `path` relative to the shared workspace root, for use with `SharedFiles`.
    func sharedRelative(_ path: String) throws -> String {
        guard let relative = SharedFiles(environment: environment).relativePath(for: path) else {
            throw SandvaultError.invalidInput("\(path) is outside the shared workspace")
        }
        return relative
    }
}
