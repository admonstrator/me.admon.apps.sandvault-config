import Foundation

// Read-only snapshots of what the sandbox is doing. Produced by SandvaultObserve (agent A) and
// SandvaultNet (agent C), consumed by the CLI and the app.

public struct SandboxProcess: Codable, Sendable, Equatable, Hashable, Identifiable {
    public var pid: Int32
    public var ppid: Int32
    /// Effective user (`root` for a setuid tool such as `ping`).
    public var user: String
    /// Real user: the sandbox user for everything the sandbox started, setuid tools included.
    public var realUser: String
    public var cpuPercent: Double
    public var memPercent: Double
    /// Resident set size in KiB.
    public var rssKiB: Int
    public var elapsedSeconds: Int
    /// `ps` state letters, e.g. `S`, `R+`.
    public var state: String
    /// Full command line (without environment).
    public var command: String
    /// `SV_SESSION_ID` from the process environment, when readable.
    public var sessionID: String?

    public var id: Int32 { pid }

    public init(
        pid: Int32, ppid: Int32, user: String, realUser: String? = nil, cpuPercent: Double = 0, memPercent: Double = 0,
        rssKiB: Int = 0, elapsedSeconds: Int = 0, state: String = "", command: String, sessionID: String? = nil
    ) {
        self.pid = pid
        self.ppid = ppid
        self.user = user
        self.realUser = realUser ?? user
        self.cpuPercent = cpuPercent
        self.memPercent = memPercent
        self.rssKiB = rssKiB
        self.elapsedSeconds = elapsedSeconds
        self.state = state
        self.command = command
        self.sessionID = sessionID
    }
}

/// Host-side processes `sv` starts on behalf of a session.
public struct HostHelperProcess: Codable, Sendable, Equatable, Hashable, Identifiable {
    public enum Kind: String, Codable, Sendable, CaseIterable { case chrome, lightpanda, iosBridge, unknown }

    public var pid: Int32
    public var kind: Kind
    /// Loopback port the sandbox reaches it on (CDP endpoint, bridge), when known.
    public var port: UInt16?
    public var sessionID: String?

    public var id: Int32 { pid }

    public init(pid: Int32, kind: Kind, port: UInt16? = nil, sessionID: String? = nil) {
        self.pid = pid
        self.kind = kind
        self.port = port
        self.sessionID = sessionID
    }
}

/// One `sv` session: the process tree that shares an `SV_SESSION_ID`.
public struct SandboxSession: Codable, Sendable, Equatable, Hashable, Identifiable {
    public var id: String
    public var rootPID: Int32
    public var processCount: Int
    /// Best guess of what runs in it (`claude`, `codex`, `zsh`).
    public var command: String
    public var elapsedSeconds: Int
    public var helpers: [HostHelperProcess]

    public init(id: String, rootPID: Int32, processCount: Int, command: String, elapsedSeconds: Int, helpers: [HostHelperProcess] = []) {
        self.id = id
        self.rootPID = rootPID
        self.processCount = processCount
        self.command = command
        self.elapsedSeconds = elapsedSeconds
        self.helpers = helpers
    }
}

public enum AddressFamily: String, Codable, Sendable, CaseIterable { case ipv4, ipv6 }

public struct SandboxConnection: Codable, Sendable, Equatable, Hashable {
    public var pid: Int32
    public var process: String
    public var proto: TransportProtocol
    public var family: AddressFamily
    public var localAddress: String
    public var localPort: UInt16
    public var remoteAddress: String?
    public var remotePort: UInt16?
    /// TCP state as lsof reports it (`ESTABLISHED`, `LISTEN`, ...); `nil` for UDP.
    public var state: String?

    public var isListening: Bool { state == "LISTEN" }

    public init(
        pid: Int32, process: String, proto: TransportProtocol, family: AddressFamily, localAddress: String, localPort: UInt16,
        remoteAddress: String? = nil, remotePort: UInt16? = nil, state: String? = nil
    ) {
        self.pid = pid
        self.process = process
        self.proto = proto
        self.family = family
        self.localAddress = localAddress
        self.localPort = localPort
        self.remoteAddress = remoteAddress
        self.remotePort = remotePort
        self.state = state
    }
}

public struct ProcessTraffic: Codable, Sendable, Equatable, Hashable {
    public var pid: Int32
    public var process: String
    public var bytesIn: Int64
    public var bytesOut: Int64

    public init(pid: Int32, process: String, bytesIn: Int64, bytesOut: Int64) {
        self.pid = pid
        self.process = process
        self.bytesIn = bytesIn
        self.bytesOut = bytesOut
    }
}

/// One sandbox denial from the unified log: `Sandbox: <process>(<pid>) deny(1) <operation> <target>`.
public struct SandboxViolation: Codable, Sendable, Equatable, Hashable {
    public var timestamp: Date
    public var process: String
    public var pid: Int32
    public var operation: String
    public var target: String?
    /// Whether the pid belonged to the sandbox user when the violation was seen.
    public var attributedToSandbox: Bool
    public var raw: String

    public init(timestamp: Date, process: String, pid: Int32, operation: String, target: String?, attributedToSandbox: Bool, raw: String) {
        self.timestamp = timestamp
        self.process = process
        self.pid = pid
        self.operation = operation
        self.target = target
        self.attributedToSandbox = attributedToSandbox
        self.raw = raw
    }
}

/// A rule the learn mode proposes for a group of violations.
public struct RuleSuggestion: Codable, Sendable, Equatable, Hashable, Identifiable {
    public enum Proposal: Codable, Sendable, Equatable, Hashable {
        case file(FileRule)
        case mach(MachRule)
        case exec(ExecRule)
    }

    public var id: String
    public var proposal: Proposal
    public var occurrences: Int
    public var processes: [String]
    public var examples: [String]
    public var lastSeen: Date

    public init(id: String, proposal: Proposal, occurrences: Int, processes: [String], examples: [String], lastSeen: Date) {
        self.id = id
        self.proposal = proposal
        self.occurrences = occurrences
        self.processes = processes
        self.examples = examples
        self.lastSeen = lastSeen
    }
}

// MARK: - netd connection log

public enum ConnectionKind: String, Codable, Sendable, CaseIterable { case explicitProxy, transparentHTTP, transparentTLS, dns, transparentTCP }

public enum ConnectionDecision: String, Codable, Sendable, CaseIterable {
    case allowed, denied, askedAllowed, askedDenied, timedOut
}

public struct HTTPSummary: Codable, Sendable, Equatable, Hashable {
    public var method: String
    public var url: String
    public var status: Int?
    /// Header pairs in order, sensitive values already redacted.
    public var requestHeaders: [[String]]
    public var responseHeaders: [[String]]

    public init(method: String, url: String, status: Int? = nil, requestHeaders: [[String]] = [], responseHeaders: [[String]] = []) {
        self.method = method
        self.url = url
        self.status = status
        self.requestHeaders = requestHeaders
        self.responseHeaders = responseHeaders
    }
}

public struct ConnectionRecord: Codable, Sendable, Equatable, Hashable, Identifiable {
    public var id: UUID
    public var timestamp: Date
    public var kind: ConnectionKind
    public var host: String
    public var port: UInt16?
    public var decision: ConnectionDecision
    /// The `DomainRule` that decided, if any.
    public var ruleID: UUID?
    public var pid: Int32?
    public var process: String?
    public var bytesIn: Int64
    public var bytesOut: Int64
    public var durationMs: Int
    public var inspected: Bool
    public var http: [HTTPSummary]
    /// DNS answers (addresses) for `.dns` records.
    public var dnsAnswers: [String]
    /// Why an allowed connection did not work (resolution, connect, or the other side closing before any answer).
    public var error: String?

    public init(
        id: UUID = UUID(), timestamp: Date = Date(), kind: ConnectionKind, host: String, port: UInt16? = nil,
        decision: ConnectionDecision, ruleID: UUID? = nil, pid: Int32? = nil, process: String? = nil,
        bytesIn: Int64 = 0, bytesOut: Int64 = 0, durationMs: Int = 0, inspected: Bool = false,
        http: [HTTPSummary] = [], dnsAnswers: [String] = [], error: String? = nil
    ) {
        self.id = id
        self.timestamp = timestamp
        self.kind = kind
        self.host = host
        self.port = port
        self.decision = decision
        self.ruleID = ruleID
        self.pid = pid
        self.process = process
        self.bytesIn = bytesIn
        self.bytesOut = bytesOut
        self.durationMs = durationMs
        self.inspected = inspected
        self.http = http
        self.dnsAnswers = dnsAnswers
        self.error = error
    }
}

// MARK: - status / doctor

public enum CheckState: String, Codable, Sendable, CaseIterable, Comparable {
    case ok, skipped, unknown, warning, failure

    private var rank: Int {
        switch self {
        case .ok: 0
        case .skipped: 1
        case .unknown: 2
        case .warning: 3
        case .failure: 4
        }
    }

    public static func < (lhs: CheckState, rhs: CheckState) -> Bool { lhs.rank < rhs.rank }
}

public struct Check: Codable, Sendable, Equatable, Hashable, Identifiable {
    /// Stable identifier, e.g. `account.user`, `profile.managed-block`.
    public var id: String
    public var title: String
    public var state: CheckState
    public var detail: String
    /// What to run or do to fix it.
    public var fix: String?

    public init(id: String, title: String, state: CheckState, detail: String, fix: String? = nil) {
        self.id = id
        self.title = title
        self.state = state
        self.detail = detail
        self.fix = fix
    }
}

public struct CheckReport: Codable, Sendable, Equatable {
    public var checks: [Check]
    public var generatedAt: Date

    public init(checks: [Check], generatedAt: Date = Date()) {
        self.checks = checks
        self.generatedAt = generatedAt
    }

    public var worst: CheckState { checks.map(\.state).max() ?? .ok }
}
