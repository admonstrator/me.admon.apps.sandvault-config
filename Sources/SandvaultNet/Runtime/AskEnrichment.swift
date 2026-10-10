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
/// The file is iptoasn.com's `ip2asn-v4.tsv` (public domain, PDDL v1.0), downloaded with curl and unpacked with gunzip.
public struct NetworkDatabaseStore: NetworkDatabaseService {
    public let path: String
    public let runner: CommandRunner
    public var source = "https://iptoasn.com/data/ip2asn-v4.tsv.gz"
    /// A download with fewer lines is refused (the real table has about half a million).
    public var minimumLines = 1000

    public init(path: String, runner: CommandRunner) {
        self.path = path
        self.runner = runner
    }

    /// Installed, modification date and line count; reads the file memory-mapped, without parsing it.
    public func status() async -> NetworkDatabaseStatus {
        guard let attributes = try? FileManager.default.attributesOfItem(atPath: path) else {
            return NetworkDatabaseStatus(installed: false)
        }
        let data = (try? Data(contentsOf: URL(fileURLWithPath: path), options: .alwaysMapped)) ?? Data()
        return NetworkDatabaseStatus(
            installed: true, updatedAt: attributes[.modificationDate] as? Date, ranges: Self.lineCount(data)
        )
    }

    /// Downloads, unpacks, checks and atomically replaces the table.
    public func update() async throws -> NetworkDatabaseStatus {
        let directory = (path as NSString).deletingLastPathComponent
        try FileManager.default.createDirectory(atPath: directory, withIntermediateDirectories: true)
        let download = path + ".download.gz"
        defer { try? FileManager.default.removeItem(atPath: download) }
        _ = try await runner.checked(CommandInvocation("/usr/bin/curl", ["-fsSL", "--max-time", "120", "-o", download, source], timeout: 150))
        let unpacked = try await runner.checked(CommandInvocation("/usr/bin/gunzip", ["-c", download], timeout: 60)).stdout
        try Self.validate(unpacked, minimumLines: minimumLines)
        try unpacked.write(to: URL(fileURLWithPath: path), options: .atomic)
        return await status()
    }

    /// Refuses data whose first lines are not `start end asn country description` or that is too short.
    public static func validate(_ data: Data, minimumLines: Int) throws {
        let lines = lineCount(data)
        guard lines >= minimumLines else {
            throw SandvaultError.invalidInput("the network table has \(lines) lines, expected at least \(minimumLines)")
        }
        let sample = String(decoding: data.prefix(64 << 10), as: UTF8.self).split(separator: "\n").dropLast().prefix(200)
        let good = sample.filter { NetworkTable.isWellFormed(String($0)) }.count
        guard !sample.isEmpty, good * 10 >= sample.count * 9 else {
            throw SandvaultError.invalidInput("the downloaded file is not an ip2asn table (\(good) of \(sample.count) sample lines parse)")
        }
    }

    static func lineCount(_ data: Data) -> Int {
        guard !data.isEmpty else { return 0 }
        var count = 0
        data.withUnsafeBytes { raw in
            for byte in raw where byte == 0x0A { count += 1 }
        }
        return data.last == 0x0A ? count : count + 1
    }
}
