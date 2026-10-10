import Foundation
import SandvaultCore

/// What a listener saw of a connection before asking: the original address, a server name, the protocol.
public struct ConnectionHint: Sendable, Equatable {
    public var address: String?
    public var serverName: String?
    public var nameSource: AskName.Source?
    public var encryption: AskEncryption?

    public init(address: String? = nil, serverName: String? = nil, nameSource: AskName.Source? = nil, encryption: AskEncryption? = nil) {
        self.address = address
        self.serverName = serverName
        self.nameSource = nameSource
        self.encryption = encryption
    }
}

/// Everything an enricher gets for one ask.
public struct AskEnrichmentInput: Sendable, Equatable {
    public var host: String
    public var port: UInt16?
    public var kind: ConnectionKind
    public var owner: ProcessOwner?
    public var hint: ConnectionHint

    public init(host: String, port: UInt16?, kind: ConnectionKind, owner: ProcessOwner?, hint: ConnectionHint) {
        self.host = host
        self.port = port
        self.kind = kind
        self.owner = owner
        self.hint = hint
    }
}

/// Fills `AskDetails` for an ask. `AskCoordinator` waits at most `AskDetailSettings.budgetSeconds` for it and
/// raises the ask without details when it takes longer, so an implementation returns what it has rather than
/// waiting on its slowest lookup.
public protocol AskEnriching: Sendable {
    func details(for input: AskEnrichmentInput, settings: AskDetailSettings) async -> AskDetails?
}

/// No lookups (tests, and netd until the real enricher is wired).
public struct NoAskEnrichment: AskEnriching {
    public init() {}
    public func details(for input: AskEnrichmentInput, settings: AskDetailSettings) async -> AskDetails? { nil }
}

/// The live `NetworkDatabaseService`: the table at `AppPaths.networkDatabase`.
public struct NetworkDatabaseStore: NetworkDatabaseService {
    public let path: String
    public let runner: CommandRunner

    public init(path: String, runner: CommandRunner) {
        self.path = path
        self.runner = runner
    }

    public func status() async -> NetworkDatabaseStatus {
        NetworkDatabaseStatus(installed: FileManager.default.fileExists(atPath: path))
    }

    public func update() async throws -> NetworkDatabaseStatus {
        throw SandvaultError.notImplemented("network database download")
    }
}
