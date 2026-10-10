import Foundation

// Control protocol between sandvault-netd (server) and the app / svctl (clients).
// Transport: Unix domain socket at `AppPaths.effectiveControlSocket`, one JSON object per line
// (`ControlCodec`). The socket lives in the host user's home, which the sandbox cannot traverse.

public enum ControlTopic: String, Codable, Sendable, CaseIterable {
    /// Every finished `ConnectionRecord`.
    case connections
    /// `AskRequest`s and their resolution.
    case asks
    /// Periodic `NetdStatus`.
    case status
}

public enum AskDecision: String, Codable, Sendable, CaseIterable { case allowOnce, allowAlways, denyOnce, denyAlways }

public enum AskScope: String, Codable, Sendable, CaseIterable {
    /// Rule for exactly this host name.
    case host
    /// Rule for `*.<registrable domain>`.
    case domain
    /// Rule for exactly this host or address and only this port (`DomainRule.port`).
    case hostAndPort
}

public struct AskRequest: Codable, Sendable, Equatable, Hashable, Identifiable {
    public var id: UUID
    public var host: String
    public var port: UInt16?
    public var kind: ConnectionKind
    public var pid: Int32?
    public var process: String?
    public var createdAt: Date
    public var expiresAt: Date
    /// What netd found out about the destination; `nil` from older netd versions or with every detail turned off.
    public var details: AskDetails?

    public init(
        id: UUID = UUID(), host: String, port: UInt16?, kind: ConnectionKind, pid: Int32? = nil, process: String? = nil,
        createdAt: Date = Date(), expiresAt: Date, details: AskDetails? = nil
    ) {
        self.id = id
        self.host = host
        self.port = port
        self.kind = kind
        self.pid = pid
        self.process = process
        self.createdAt = createdAt
        self.expiresAt = expiresAt
        self.details = details
    }
}

public struct AskAnswer: Codable, Sendable, Equatable, Hashable {
    public var id: UUID
    public var decision: AskDecision
    public var scope: AskScope

    public init(id: UUID, decision: AskDecision, scope: AskScope = .host) {
        self.id = id
        self.decision = decision
        self.scope = scope
    }
}

public struct NetdStatus: Codable, Sendable, Equatable {
    public var version: String
    public var startedAt: Date
    public var ports: ProxyPorts
    public var mode: FirewallMode
    public var activeConnections: Int
    public var allowedCount: Int
    public var deniedCount: Int
    public var pendingAsks: Int
    public var inspectionEnabled: Bool
    /// SHA-256 fingerprint of the inspection CA, when one exists.
    public var caFingerprint: String?
    /// Bytes under `AppPaths.httpContentDir`.
    public var storedContentBytes: Int64?

    public init(
        version: String = BundleIdentity.version, startedAt: Date, ports: ProxyPorts, mode: FirewallMode,
        activeConnections: Int = 0, allowedCount: Int = 0, deniedCount: Int = 0, pendingAsks: Int = 0,
        inspectionEnabled: Bool = false, caFingerprint: String? = nil, storedContentBytes: Int64? = nil
    ) {
        self.version = version
        self.startedAt = startedAt
        self.ports = ports
        self.mode = mode
        self.activeConnections = activeConnections
        self.allowedCount = allowedCount
        self.deniedCount = deniedCount
        self.pendingAsks = pendingAsks
        self.inspectionEnabled = inspectionEnabled
        self.caFingerprint = caFingerprint
        self.storedContentBytes = storedContentBytes
    }
}

/// Client to server.
public enum ControlRequest: Codable, Sendable, Equatable {
    case hello(client: String)
    case subscribe(topics: [ControlTopic])
    case status
    /// Re-read `AppPaths.configFile` and apply the network policy.
    case reloadConfig
    case answer(AskAnswer)
    /// Most recent records from the in-memory ring buffer.
    case recent(limit: Int)
    case pendingAsks
    /// The bytes of one `StoredContent` (D43).
    case content(id: UUID)
    /// Delete every stored content.
    case clearContent
}

/// Server to client.
public enum ControlEvent: Codable, Sendable, Equatable {
    case hello(version: String)
    case status(NetdStatus)
    case connection(ConnectionRecord)
    case recent([ConnectionRecord])
    case ask(AskRequest)
    case pending([AskRequest])
    case askResolved(id: UUID, decision: ConnectionDecision)
    case content(StoredContent, Data)
    case ack
    case error(String)
}

public enum ControlCodec {
    /// Encodes one message as a single JSON line terminated by `\n`.
    public static func encode<T: Encodable>(_ message: T) throws -> Data {
        var data = try JSONCoding.lineEncoder.encode(message)
        data.append(0x0A)
        return data
    }

    public static func decode<T: Decodable>(_ type: T.Type, line: String) throws -> T {
        try JSONCoding.decoder.decode(type, from: Data(line.utf8))
    }
}
