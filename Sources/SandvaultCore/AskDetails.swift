import Foundation

// What netd found out about the destination of an ask, and how it judges it (D37-D41).
// netd fills `AskDetails` within `AskDetailSettings.budgetSeconds`; every part is optional, because each lookup can
// be turned off, fail or come too late. The app shows the parts as tiles and never computes them itself.

/// The details of one ask. `nil` parts were turned off, failed, or did not finish in time.
public struct AskDetails: Codable, Sendable, Equatable, Hashable {
    /// The IP address the connection goes to, when netd knows it (always for TCP on other ports).
    public var address: String?
    public var name: AskName?
    /// PTR name of `address`.
    public var reverseName: String?
    public var service: KnownService?
    public var network: AskNetwork?
    public var encryption: AskEncryption?
    public var history: AskHistory?
    public var program: AskProgram?
    public var assessment: AskAssessment?

    public init(
        address: String? = nil, name: AskName? = nil, reverseName: String? = nil, service: KnownService? = nil,
        network: AskNetwork? = nil, encryption: AskEncryption? = nil, history: AskHistory? = nil, program: AskProgram? = nil,
        assessment: AskAssessment? = nil
    ) {
        self.address = address
        self.name = name
        self.reverseName = reverseName
        self.service = service
        self.network = network
        self.encryption = encryption
        self.history = history
        self.program = program
        self.assessment = assessment
    }
}

/// The host name behind the connection and where netd learned it. `source == .none` means: an IP address only.
public struct AskName: Codable, Sendable, Equatable, Hashable {
    public enum Source: String, Codable, Sendable, CaseIterable {
        /// A DNS answer the sandbox received through netd shortly before.
        case dns
        /// The TLS ClientHello (SNI).
        case tls
        /// The HTTP `Host` header or the proxy request.
        case http
        /// The program connected to a bare address; no name led there.
        case none
    }

    public var name: String?
    public var source: Source

    public init(name: String?, source: Source) {
        self.name = name
        self.source = source
    }
}

/// An entry of the built-in port list.
public struct KnownService: Codable, Sendable, Equatable, Hashable {
    public var port: UInt16
    /// Short name, e.g. `HTTPS`, `SSH`, `PostgreSQL`; `nil` when the port is in no list.
    public var name: String?

    public init(port: UInt16, name: String?) {
        self.port = port
        self.name = name
    }
}

/// Who runs the network the address belongs to.
public struct AskNetwork: Codable, Sendable, Equatable, Hashable {
    public enum Kind: String, Codable, Sendable, CaseIterable {
        /// A well-known service: public resolver, package registry, Apple, GitHub and the like.
        case knownService
        /// A content delivery network many services share.
        case cdn
        /// Rented servers (VPS, cloud compute, data centre).
        case hosting
        /// Anything else (access providers, companies, universities).
        case other
    }

    public var asn: UInt32?
    public var owner: String?
    /// ISO 3166-1 alpha-2, upper case.
    public var country: String?
    public var kind: Kind
    /// Where the data came from.
    public var source: NetworkLookupMode

    public init(asn: UInt32?, owner: String?, country: String?, kind: Kind, source: NetworkLookupMode) {
        self.asn = asn
        self.owner = owner
        self.country = country
        self.kind = kind
        self.source = source
    }
}

/// What netd saw of the protocol before deciding.
public enum AskEncryption: Codable, Sendable, Equatable, Hashable {
    /// A TLS ClientHello.
    case tls
    /// Plain text netd recognised (HTTP request line, classic DNS).
    case plain
    /// The client sent nothing in time (server-speaks-first protocols) or nothing netd recognised.
    case unknown
}

public struct AskHistory: Codable, Sendable, Equatable, Hashable {
    /// Earlier connections to the same host and port that were allowed.
    public var allowed: Int
    public var denied: Int
    public var lastSeen: Date?

    public init(allowed: Int, denied: Int, lastSeen: Date?) {
        self.allowed = allowed
        self.denied = denied
        self.lastSeen = lastSeen
    }
}

/// The executable of the connecting process.
public struct AskProgram: Codable, Sendable, Equatable, Hashable {
    public enum Signature: Codable, Sendable, Equatable, Hashable {
        case apple
        /// Signed with a developer certificate; the team identifier when known.
        case developer(team: String?)
        case adHoc
        case unsigned
        /// netd could not read or check the file.
        case unknown
    }

    public var path: String?
    public var signature: Signature
    /// Under `/tmp`, `/private/var/folders` or a `.../tmp/...` directory.
    public var inTemporaryFolder: Bool

    public init(path: String?, signature: Signature, inTemporaryFolder: Bool) {
        self.path = path
        self.signature = signature
        self.inTemporaryFolder = inTemporaryFolder
    }
}

/// Points with reasons, never a black box: every signal names the detail it comes from.
public struct AskAssessment: Codable, Sendable, Equatable, Hashable {
    public enum Level: String, Codable, Sendable, CaseIterable { case normal, unusual, suspicious }

    public struct Signal: Codable, Sendable, Equatable, Hashable {
        public enum Effect: String, Codable, Sendable, CaseIterable {
            /// Speaks for the destination (negative points).
            case plus
            /// Speaks against it (positive points).
            case minus
            /// Shown, but worth no points.
            case info
        }

        public var detail: AskDetailKind
        public var effect: Effect
        public var points: Int
        /// One short English sentence for the panel, e.g. "Port 8947 is in no list of known services."
        public var text: String

        public init(detail: AskDetailKind, effect: Effect, points: Int, text: String) {
            self.detail = detail
            self.effect = effect
            self.points = points
            self.text = text
        }
    }

    public var level: Level
    public var score: Int
    public var signals: [Signal]

    /// Score thresholds: below 3 normal, 3 to 5 unusual, 6 or more suspicious.
    public static let unusualFrom = 3
    public static let suspiciousFrom = 6

    public static func level(for score: Int) -> Level {
        score >= suspiciousFrom ? .suspicious : score >= unusualFrom ? .unusual : .normal
    }

    public init(level: Level, score: Int, signals: [Signal]) {
        self.level = level
        self.score = score
        self.signals = signals
    }
}

/// The detail a signal or a tile belongs to.
public enum AskDetailKind: String, Codable, Sendable, CaseIterable {
    case name, reverseName, port, network, encryption, history, program
}

public enum NetworkLookupMode: String, Codable, Sendable, CaseIterable {
    case off
    /// The database at `AppPaths.networkDatabase` (downloaded on request, stays on this Mac).
    case offline
    /// RDAP at the regional internet registry; reveals the address to it.
    case online
}

/// Settings > Connection requests. Lives in `NetworkPolicy`, because netd does the lookups.
public struct AskDetailSettings: Codable, Sendable, Equatable {
    public var name: Bool
    /// Asks the upstream DNS server for the PTR name.
    public var reverseDNS: Bool
    public var port: Bool
    public var network: NetworkLookupMode
    public var program: Bool
    public var history: Bool
    public var assessment: Bool
    /// The panel makes Deny the default button for a suspicious request (Return denies).
    public var saferDefault: Bool
    /// ISO country codes whose networks add points. Empty by default: the choice is the user's.
    public var markedCountries: [String]
    /// How long netd waits for the details before it raises the ask with what it has.
    public var budgetSeconds: Double

    public init(
        name: Bool = true, reverseDNS: Bool = true, port: Bool = true, network: NetworkLookupMode = .offline,
        program: Bool = true, history: Bool = true, assessment: Bool = true, saferDefault: Bool = true,
        markedCountries: [String] = [], budgetSeconds: Double = 1.5
    ) {
        self.name = name
        self.reverseDNS = reverseDNS
        self.port = port
        self.network = network
        self.program = program
        self.history = history
        self.assessment = assessment
        self.saferDefault = saferDefault
        self.markedCountries = markedCountries
        self.budgetSeconds = budgetSeconds
    }

    enum CodingKeys: String, CodingKey {
        case name, reverseDNS, port, network, program, history, assessment, saferDefault, markedCountries, budgetSeconds
    }

    public init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        let d = AskDetailSettings()
        name = try c.value(.name, default: d.name)
        reverseDNS = try c.value(.reverseDNS, default: d.reverseDNS)
        port = try c.value(.port, default: d.port)
        network = try c.value(.network, default: d.network)
        program = try c.value(.program, default: d.program)
        history = try c.value(.history, default: d.history)
        assessment = try c.value(.assessment, default: d.assessment)
        saferDefault = try c.value(.saferDefault, default: d.saferDefault)
        markedCountries = try c.value(.markedCountries, default: d.markedCountries)
        budgetSeconds = try c.value(.budgetSeconds, default: d.budgetSeconds)
    }
}

extension AskScope {
    /// The choices the panel offers for a request, most specific first.
    /// Web ports and DNS: this host, then the whole domain (only for names with a registrable domain).
    /// Other ports: this host or address with this port, then any port.
    public static func options(port: UInt16?, hasDomain: Bool) -> [AskScope] {
        let web: Set<UInt16> = [80, 443]
        if let port, !web.contains(port) {
            return [.hostAndPort, .host]
        }
        return hasDomain ? [.host, .domain] : [.host]
    }
}

// MARK: - Network database (offline lookups)

public struct NetworkDatabaseStatus: Codable, Sendable, Equatable {
    public var installed: Bool
    public var updatedAt: Date?
    public var ranges: Int

    public init(installed: Bool, updatedAt: Date? = nil, ranges: Int = 0) {
        self.installed = installed
        self.updatedAt = updatedAt
        self.ranges = ranges
    }
}

/// Downloads and reports the address-to-network table at `AppPaths.networkDatabase`.
public protocol NetworkDatabaseService: Sendable {
    func status() async -> NetworkDatabaseStatus
    func update() async throws -> NetworkDatabaseStatus
}
