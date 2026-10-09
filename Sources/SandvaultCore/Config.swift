import Foundation
#if canImport(Darwin)
import Darwin
#elseif canImport(Glibc)
import Glibc
#endif

// The host-only configuration (`AppPaths.configFile`). Every type decodes missing keys to their defaults,
// so older files keep loading when fields are added. New fields go at the end with a default.

extension KeyedDecodingContainer {
    /// Decodes `key` or falls back to `fallback` when the key is absent.
    public func value<T: Decodable>(_ key: Key, default fallback: @autoclosure () -> T) throws -> T {
        try decodeIfPresent(T.self, forKey: key) ?? fallback()
    }
}

public struct AppConfig: Codable, Sendable, Equatable {
    public static let currentVersion = 1

    public var version: Int
    public var sandbox: SandboxSettings
    public var network: NetworkPolicy
    public var handoff: HandoffSettings
    public var tools: [ToolGrant]
    public var repos: [HandoffRecord]

    public init(
        version: Int = AppConfig.currentVersion,
        sandbox: SandboxSettings = SandboxSettings(),
        network: NetworkPolicy = NetworkPolicy(),
        handoff: HandoffSettings = HandoffSettings(),
        tools: [ToolGrant] = [],
        repos: [HandoffRecord] = []
    ) {
        self.version = version
        self.sandbox = sandbox
        self.network = network
        self.handoff = handoff
        self.tools = tools
        self.repos = repos
    }

    enum CodingKeys: String, CodingKey { case version, sandbox, network, handoff, tools, repos }

    public init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        version = try c.value(.version, default: AppConfig.currentVersion)
        sandbox = try c.value(.sandbox, default: SandboxSettings())
        network = try c.value(.network, default: NetworkPolicy())
        handoff = try c.value(.handoff, default: HandoffSettings())
        tools = try c.value(.tools, default: [])
        repos = try c.value(.repos, default: [])
    }
}

// MARK: - Sandbox rules (sandbox-exec profile, managed block)

public enum RuleEffect: String, Codable, Sendable, CaseIterable { case allow, deny }

public enum FileAccess: String, Codable, Sendable, CaseIterable { case read, write, readWrite }

/// SBPL path filters: `subpath` (directory tree), `literal` (exact path), `prefix` (string prefix).
public enum PathMatch: String, Codable, Sendable, CaseIterable { case subpath, literal, prefix }

public enum SandboxPreset: String, Codable, Sendable, CaseIterable {
    /// sv's profile unchanged, plus the user's own rules.
    case standard
    /// Additional denials for tools and services that let code leave the sandbox (opt-in).
    case hardened
}

public struct FileRule: Codable, Sendable, Equatable, Hashable, Identifiable {
    public var id: UUID
    public var path: String
    public var match: PathMatch
    public var access: FileAccess
    public var effect: RuleEffect
    public var note: String?

    public init(id: UUID = UUID(), path: String, match: PathMatch = .subpath, access: FileAccess, effect: RuleEffect, note: String? = nil) {
        self.id = id
        self.path = path
        self.match = match
        self.access = access
        self.effect = effect
        self.note = note
    }

    enum CodingKeys: String, CodingKey { case id, path, match, access, effect, note }

    public init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        id = try c.value(.id, default: UUID())
        path = try c.decode(String.self, forKey: .path)
        match = try c.value(.match, default: .subpath)
        access = try c.decode(FileAccess.self, forKey: .access)
        effect = try c.decode(RuleEffect.self, forKey: .effect)
        note = try c.decodeIfPresent(String.self, forKey: .note)
    }
}

/// `(allow|deny mach-lookup (global-name "<name>"))`
public struct MachRule: Codable, Sendable, Equatable, Hashable, Identifiable {
    public var id: UUID
    public var name: String
    public var effect: RuleEffect
    public var note: String?

    public init(id: UUID = UUID(), name: String, effect: RuleEffect, note: String? = nil) {
        self.id = id
        self.name = name
        self.effect = effect
        self.note = note
    }

    enum CodingKeys: String, CodingKey { case id, name, effect, note }

    public init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        id = try c.value(.id, default: UUID())
        name = try c.decode(String.self, forKey: .name)
        effect = try c.decode(RuleEffect.self, forKey: .effect)
        note = try c.decodeIfPresent(String.self, forKey: .note)
    }
}

/// `(deny process-exec (literal "<path>"))`
public struct ExecRule: Codable, Sendable, Equatable, Hashable, Identifiable {
    public var id: UUID
    public var path: String
    public var effect: RuleEffect
    public var note: String?

    public init(id: UUID = UUID(), path: String, effect: RuleEffect = .deny, note: String? = nil) {
        self.id = id
        self.path = path
        self.effect = effect
        self.note = note
    }

    enum CodingKeys: String, CodingKey { case id, path, effect, note }

    public init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        id = try c.value(.id, default: UUID())
        path = try c.decode(String.self, forKey: .path)
        effect = try c.value(.effect, default: .deny)
        note = try c.decodeIfPresent(String.self, forKey: .note)
    }
}

public struct SandboxSettings: Codable, Sendable, Equatable {
    public var preset: SandboxPreset
    public var fileRules: [FileRule]
    public var machRules: [MachRule]
    public var execRules: [ExecRule]
    /// Re-apply the managed block automatically when `sv --rebuild` removed it.
    public var autoReapply: Bool

    public init(
        preset: SandboxPreset = .standard,
        fileRules: [FileRule] = [],
        machRules: [MachRule] = [],
        execRules: [ExecRule] = [],
        autoReapply: Bool = false
    ) {
        self.preset = preset
        self.fileRules = fileRules
        self.machRules = machRules
        self.execRules = execRules
        self.autoReapply = autoReapply
    }

    enum CodingKeys: String, CodingKey { case preset, fileRules, machRules, execRules, autoReapply }

    public init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        preset = try c.value(.preset, default: .standard)
        fileRules = try c.value(.fileRules, default: [])
        machRules = try c.value(.machRules, default: [])
        execRules = try c.value(.execRules, default: [])
        autoReapply = try c.value(.autoReapply, default: false)
    }
}

// MARK: - Network policy (pf anchor + sandvault-netd)

public enum FirewallMode: String, Codable, Sendable, CaseIterable {
    /// No pf anchor loaded; sv's default (network fully open).
    case off
    /// Direct traffic allowed, LAN/localhost guards and port exceptions apply.
    case open
    /// Only the netd listeners (and exceptions) are reachable; 80/443/53 are redirected to netd.
    case proxyOnly
    /// Everything blocked for the sandbox user (also the panic state).
    case blocked
}

public enum DomainAction: String, Codable, Sendable, CaseIterable { case allow, deny, ask }

public struct DomainRule: Codable, Sendable, Equatable, Hashable, Identifiable {
    public var id: UUID
    /// `example.com` (exact), `*.example.com` (subdomains and the apex), or `*` (everything).
    public var pattern: String
    public var action: DomainAction
    /// Decrypt and log HTTP details for matching hosts (requires `InspectionSettings.enabled`).
    public var inspect: Bool
    public var note: String?
    public var createdAt: Date

    public init(id: UUID = UUID(), pattern: String, action: DomainAction, inspect: Bool = false, note: String? = nil, createdAt: Date = Date()) {
        self.id = id
        self.pattern = pattern
        self.action = action
        self.inspect = inspect
        self.note = note
        self.createdAt = createdAt
    }

    enum CodingKeys: String, CodingKey { case id, pattern, action, inspect, note, createdAt }

    public init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        id = try c.value(.id, default: UUID())
        pattern = try c.decode(String.self, forKey: .pattern)
        action = try c.decode(DomainAction.self, forKey: .action)
        inspect = try c.value(.inspect, default: false)
        note = try c.decodeIfPresent(String.self, forKey: .note)
        createdAt = try c.value(.createdAt, default: Date(timeIntervalSince1970: 0))
    }
}

/// Answers DNS queries (and proxy resolution) for `pattern` with a fixed address.
public struct DnsOverride: Codable, Sendable, Equatable, Hashable, Identifiable {
    public var id: UUID
    public var pattern: String
    public var address: String
    public var note: String?

    public init(id: UUID = UUID(), pattern: String, address: String, note: String? = nil) {
        self.id = id
        self.pattern = pattern
        self.address = address
        self.note = note
    }

    enum CodingKeys: String, CodingKey { case id, pattern, address, note }

    public init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        id = try c.value(.id, default: UUID())
        pattern = try c.decode(String.self, forKey: .pattern)
        address = try c.decode(String.self, forKey: .address)
        note = try c.decodeIfPresent(String.self, forKey: .note)
    }
}

public enum TransportProtocol: String, Codable, Sendable, CaseIterable { case tcp, udp }

/// Direct traffic the firewall lets through in `open` and `proxyOnly` modes (e.g. SSH to github.com).
public struct PortException: Codable, Sendable, Equatable, Hashable, Identifiable {
    public var id: UUID
    public var proto: TransportProtocol
    /// CIDR (`140.82.112.0/20`), single address, or `any`.
    public var destination: String
    /// `nil` means every port.
    public var port: UInt16?
    public var note: String?

    public init(id: UUID = UUID(), proto: TransportProtocol, destination: String, port: UInt16?, note: String? = nil) {
        self.id = id
        self.proto = proto
        self.destination = destination
        self.port = port
        self.note = note
    }

    enum CodingKeys: String, CodingKey { case id, proto, destination, port, note }

    public init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        id = try c.value(.id, default: UUID())
        proto = try c.decode(TransportProtocol.self, forKey: .proto)
        destination = try c.decode(String.self, forKey: .destination)
        port = try c.decodeIfPresent(UInt16.self, forKey: .port)
        note = try c.decodeIfPresent(String.self, forKey: .note)
    }
}

public enum LocalhostPolicy: String, Codable, Sendable, CaseIterable {
    /// Allow loopback only to ports the sandbox itself listens on, sv's host helpers and netd.
    case sandboxAndHelpers
    case allowAll
    /// Only netd and sv's host helpers.
    case blockAll
}

public struct ProxyPorts: Codable, Sendable, Equatable, Hashable {
    public var explicitProxy: UInt16
    public var transparentHTTP: UInt16
    public var transparentTLS: UInt16
    public var dns: UInt16

    public init(explicitProxy: UInt16 = 18080, transparentHTTP: UInt16 = 18081, transparentTLS: UInt16 = 18443, dns: UInt16 = 18053) {
        self.explicitProxy = explicitProxy
        self.transparentHTTP = transparentHTTP
        self.transparentTLS = transparentTLS
        self.dns = dns
    }

    public var all: [UInt16] { [explicitProxy, transparentHTTP, transparentTLS, dns] }

    enum CodingKeys: String, CodingKey { case explicitProxy, transparentHTTP, transparentTLS, dns }

    public init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        let d = ProxyPorts()
        explicitProxy = try c.value(.explicitProxy, default: d.explicitProxy)
        transparentHTTP = try c.value(.transparentHTTP, default: d.transparentHTTP)
        transparentTLS = try c.value(.transparentTLS, default: d.transparentTLS)
        dns = try c.value(.dns, default: d.dns)
    }
}

public struct InspectionSettings: Codable, Sendable, Equatable {
    /// Master switch; per-domain opt-in via `DomainRule.inspect`.
    public var enabled: Bool
    /// Header names (case-insensitive) whose values are replaced by `<redacted>` in logs.
    public var redactHeaders: [String]

    public static let defaultRedactedHeaders = [
        "authorization", "proxy-authorization", "cookie", "set-cookie", "x-api-key", "anthropic-api-key", "x-auth-token",
    ]

    public init(enabled: Bool = false, redactHeaders: [String] = InspectionSettings.defaultRedactedHeaders) {
        self.enabled = enabled
        self.redactHeaders = redactHeaders
    }

    enum CodingKeys: String, CodingKey { case enabled, redactHeaders }

    public init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        enabled = try c.value(.enabled, default: false)
        redactHeaders = try c.value(.redactHeaders, default: InspectionSettings.defaultRedactedHeaders)
    }
}

public struct NetworkPolicy: Codable, Sendable, Equatable {
    public var mode: FirewallMode
    /// Action for hosts no `DomainRule` matches.
    public var defaultAction: DomainAction
    /// How long netd holds a connection while waiting for an answer to an `ask`.
    public var askTimeoutSeconds: Int
    /// What happens when an ask times out or no UI is connected.
    public var askFallback: DomainAction
    public var domainRules: [DomainRule]
    public var dnsOverrides: [DnsOverride]
    public var portExceptions: [PortException]
    /// Block RFC 1918, link-local and CGNAT destinations for the sandbox user.
    public var blockLAN: Bool
    public var localhost: LocalhostPolicy
    /// Refuse proxy targets that resolve to private, loopback or link-local addresses.
    public var blockPrivateDestinations: Bool
    public var ports: ProxyPorts
    public var inspection: InspectionSettings

    public init(
        mode: FirewallMode = .off,
        defaultAction: DomainAction = .ask,
        askTimeoutSeconds: Int = 30,
        askFallback: DomainAction = .deny,
        domainRules: [DomainRule] = [],
        dnsOverrides: [DnsOverride] = [],
        portExceptions: [PortException] = [],
        blockLAN: Bool = true,
        localhost: LocalhostPolicy = .sandboxAndHelpers,
        blockPrivateDestinations: Bool = true,
        ports: ProxyPorts = ProxyPorts(),
        inspection: InspectionSettings = InspectionSettings()
    ) {
        self.mode = mode
        self.defaultAction = defaultAction
        self.askTimeoutSeconds = askTimeoutSeconds
        self.askFallback = askFallback
        self.domainRules = domainRules
        self.dnsOverrides = dnsOverrides
        self.portExceptions = portExceptions
        self.blockLAN = blockLAN
        self.localhost = localhost
        self.blockPrivateDestinations = blockPrivateDestinations
        self.ports = ports
        self.inspection = inspection
    }

    enum CodingKeys: String, CodingKey {
        case mode, defaultAction, askTimeoutSeconds, askFallback, domainRules, dnsOverrides, portExceptions
        case blockLAN, localhost, blockPrivateDestinations, ports, inspection
    }

    public init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        let d = NetworkPolicy()
        mode = try c.value(.mode, default: d.mode)
        defaultAction = try c.value(.defaultAction, default: d.defaultAction)
        askTimeoutSeconds = try c.value(.askTimeoutSeconds, default: d.askTimeoutSeconds)
        askFallback = try c.value(.askFallback, default: d.askFallback)
        domainRules = try c.value(.domainRules, default: [])
        dnsOverrides = try c.value(.dnsOverrides, default: [])
        portExceptions = try c.value(.portExceptions, default: [])
        blockLAN = try c.value(.blockLAN, default: d.blockLAN)
        localhost = try c.value(.localhost, default: d.localhost)
        blockPrivateDestinations = try c.value(.blockPrivateDestinations, default: d.blockPrivateDestinations)
        ports = try c.value(.ports, default: d.ports)
        inspection = try c.value(.inspection, default: d.inspection)
    }
}

// MARK: - Workflow (phase 2 fills the behaviour; the shapes are fixed here)

public enum AgentKind: String, Codable, Sendable, CaseIterable {
    case claude, codex, opencode, gemini, pi, muse, shell

    /// The `sv` subcommand that starts this agent.
    public var svCommand: String { rawValue }
}

public enum TerminalApp: String, Codable, Sendable, CaseIterable { case terminal, iterm2, ghostty }

public struct HandoffSettings: Codable, Sendable, Equatable {
    public var terminal: TerminalApp
    public var defaultAgent: AgentKind
    /// Extra `sv` options for hand-offs, e.g. `--browser`.
    public var svOptions: [String]

    public init(terminal: TerminalApp = .terminal, defaultAgent: AgentKind = .claude, svOptions: [String] = []) {
        self.terminal = terminal
        self.defaultAgent = defaultAgent
        self.svOptions = svOptions
    }

    enum CodingKeys: String, CodingKey { case terminal, defaultAgent, svOptions }

    public init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        terminal = try c.value(.terminal, default: .terminal)
        defaultAgent = try c.value(.defaultAgent, default: .claude)
        svOptions = try c.value(.svOptions, default: [])
    }
}

public enum ToolGrantMethod: String, Codable, Sendable, CaseIterable {
    /// Already reachable (system or Homebrew path with sufficient permissions).
    case available
    /// Installed with `brew install <formula>`.
    case brew
    /// Copied into `$SHARED_WORKSPACE/user/bin`.
    case copy
}

public struct ToolGrant: Codable, Sendable, Equatable, Hashable, Identifiable {
    public var id: UUID
    public var name: String
    /// Host path or Homebrew formula the grant came from.
    public var source: String
    public var method: ToolGrantMethod
    public var grantedAt: Date

    public init(id: UUID = UUID(), name: String, source: String, method: ToolGrantMethod, grantedAt: Date = Date()) {
        self.id = id
        self.name = name
        self.source = source
        self.method = method
        self.grantedAt = grantedAt
    }
}

public struct HandoffRecord: Codable, Sendable, Equatable, Hashable, Identifiable {
    public var id: UUID
    /// Original repository on the host.
    public var hostPath: String
    public var repoName: String
    /// `$SHARED_WORKSPACE/repos/<name>`.
    public var sandboxPath: String
    public var agent: AgentKind
    public var createdAt: Date

    public init(id: UUID = UUID(), hostPath: String, repoName: String, sandboxPath: String, agent: AgentKind, createdAt: Date = Date()) {
        self.id = id
        self.hostPath = hostPath
        self.repoName = repoName
        self.sandboxPath = sandboxPath
        self.agent = agent
        self.createdAt = createdAt
    }
}

// MARK: - Persistence

public struct ConfigStore: Sendable {
    public var url: URL

    public init(path: String) {
        url = URL(fileURLWithPath: path)
    }

    public init(paths: AppPaths) {
        self.init(path: paths.configFile)
    }

    /// Missing file yields the default configuration.
    public func load() throws -> AppConfig {
        guard FileManager.default.fileExists(atPath: url.path) else { return AppConfig() }
        do {
            return try JSONCoding.decoder.decode(AppConfig.self, from: Data(contentsOf: url))
        } catch {
            throw SandvaultError.io("cannot read \(url.path): \(error)")
        }
    }

    /// Writes atomically with mode 0600; the directory is created with mode 0700.
    public func save(_ config: AppConfig) throws {
        let directory = url.deletingLastPathComponent()
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true, attributes: [.posixPermissions: 0o700])
        let data = try JSONCoding.encoder.encode(config)
        try AtomicFile.write(data, to: url.path, permissions: 0o600)
    }
}

/// Shared JSON settings: ISO-8601 dates, sorted keys (stable diffs).
public enum JSONCoding {
    public static var encoder: JSONEncoder {
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.prettyPrinted, .sortedKeys, .withoutEscapingSlashes]
        encoder.dateEncodingStrategy = .iso8601
        return encoder
    }

    /// Single-line encoder for JSON Lines (control socket, connection log).
    public static var lineEncoder: JSONEncoder {
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.sortedKeys, .withoutEscapingSlashes]
        encoder.dateEncodingStrategy = .iso8601
        return encoder
    }

    public static var decoder: JSONDecoder {
        let decoder = JSONDecoder()
        decoder.dateDecodingStrategy = .iso8601
        return decoder
    }
}

public enum AtomicFile {
    /// Writes to a temporary sibling, sets permissions, then renames over the target.
    public static func write(_ data: Data, to path: String, permissions: Int) throws {
        let target = URL(fileURLWithPath: path)
        let temporary = target.deletingLastPathComponent()
            .appendingPathComponent(".\(target.lastPathComponent).\(UUID().uuidString).tmp")
        do {
            try data.write(to: temporary)
            try FileManager.default.setAttributes([.posixPermissions: permissions], ofItemAtPath: temporary.path)
            // rename(2) replaces the target atomically on the same file system.
            guard rename(temporary.path, target.path) == 0 else {
                throw SandvaultError.io("rename failed with errno \(errno)")
            }
        } catch {
            try? FileManager.default.removeItem(at: temporary)
            throw SandvaultError.io("cannot write \(path): \(error)")
        }
    }
}
