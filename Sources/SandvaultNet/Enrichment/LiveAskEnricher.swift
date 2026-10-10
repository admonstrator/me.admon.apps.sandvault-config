import Foundation
import SandvaultCore

/// PTR lookups for the reverse name.
public protocol ReverseResolving: Sendable {
    /// The PTR name; `nil` when the address has none. Throws when the lookup failed.
    func reverseName(of address: String) async throws -> String?
}

/// Owner, AS number, country and kind of the network an address belongs to.
public protocol NetworkLooking: Sendable {
    func network(for address: String, mode: NetworkLookupMode) async -> AskNetwork?
}

/// The `AskEnriching` netd uses (D38, D39): runs the enabled lookups concurrently, returns what finished before
/// its deadline (a little inside `budgetSeconds`) and cancels the rest. Name, port and history are in memory;
/// reverse DNS, network, and program run as separate tasks.
public struct LiveAskEnricher: AskEnriching {
    public let names: DNSNameCache
    public let reverse: ReverseResolving
    public let networks: NetworkLooking
    public let programs: ProgramInspecting
    public let history: ConnectionHistoryIndex
    /// Share of the budget the enricher uses (and at least `budgetMargin` seconds less), so its answer reaches the
    /// coordinator in time.
    public var budgetShare = 0.8
    public var budgetMargin = 0.1

    public init(
        names: DNSNameCache, reverse: ReverseResolving, networks: NetworkLooking, programs: ProgramInspecting,
        history: ConnectionHistoryIndex
    ) {
        self.names = names
        self.reverse = reverse
        self.networks = networks
        self.programs = programs
        self.history = history
    }

    public func details(for input: AskEnrichmentInput, settings: AskDetailSettings) async -> AskDetails? {
        let isDNS = input.kind == .dns
        let port = isDNS ? 53 : input.port
        var base = AskDetails()
        base.address = input.hint.address ?? (HostName.isIPLiteral(input.host) ? input.host : names.address(for: input.host))
        base.encryption = isDNS ? .plain : input.hint.encryption
        if settings.name { base.name = name(for: input) }
        if settings.port, let port { base.service = KnownPorts.service(port) }
        if settings.history { base.history = history.history(host: input.host, port: isDNS ? nil : input.port) }

        var parts: [@Sendable () async -> (inout AskDetails) -> Void] = []
        if settings.reverseDNS, let address = base.address, HostName.isIPLiteral(address) {
            let reverse = self.reverse
            parts.append {
                do {
                    let found = try await reverse.reverseName(of: address)
                    return { $0.reverseName = found ?? AskDetails.noReverseName }
                } catch {
                    return { _ in }
                }
            }
        }
        if settings.network != .off, let address = base.address {
            let networks = self.networks, mode = settings.network
            parts.append {
                let network = await networks.network(for: address, mode: mode)
                return { $0.network = network }
            }
        }
        if settings.program, let pid = input.owner?.pid {
            let programs = self.programs
            parts.append {
                let program = await programs.program(pid: pid)
                return { $0.program = program }
            }
        }

        var details = await Self.collect(base, parts: parts, within: deadline(settings.budgetSeconds))
        if settings.assessment {
            details.assessment = AskAssessor.assess(details: details, port: port, settings: settings)
        }
        return details
    }

    func deadline(_ budget: Double) -> Double {
        max(0.05, min(budget * budgetShare, budget - budgetMargin))
    }

    /// Where the name came from: the hint, the queried name for DNS, the host itself, or a recent DNS answer.
    func name(for input: AskEnrichmentInput) -> AskName {
        if input.kind == .dns { return AskName(name: input.host, source: .dns) }
        let fallback: AskName.Source = input.kind == .transparentTLS ? .tls : .http
        if let server = input.hint.serverName, !server.isEmpty {
            return AskName(name: server, source: input.hint.nameSource ?? fallback)
        }
        if !HostName.isIPLiteral(input.host) {
            return AskName(name: input.host, source: input.hint.nameSource ?? fallback)
        }
        if let cached = names.name(for: input.host) { return AskName(name: cached, source: .dns) }
        return AskName(name: nil, source: .none)
    }

    /// Runs `parts` as tasks and applies each result to `base` as it arrives; at `seconds` it cancels the rest and
    /// returns. Unstructured tasks, so a part that ignores cancellation cannot hold the answer back.
    static func collect(
        _ base: AskDetails, parts: [@Sendable () async -> (inout AskDetails) -> Void], within seconds: Double
    ) async -> AskDetails {
        guard !parts.isEmpty else { return base }
        let collector = Collector(base, remaining: parts.count)
        return await withTaskCancellationHandler {
            await withCheckedContinuation { continuation in
                collector.start(continuation)
                var tasks = parts.map { part in
                    Task { collector.apply(await part()) }
                }
                tasks.append(Task {
                    try? await Task.sleep(nanoseconds: UInt64(seconds * 1_000_000_000))
                    collector.finish()
                })
                collector.track(tasks)
            }
        } onCancel: {
            collector.finish()
        }
    }

    private final class Collector: @unchecked Sendable {
        private let lock = NSLock()
        private var details: AskDetails
        private var remaining: Int
        private var continuation: CheckedContinuation<AskDetails, Never>?
        private var tasks: [Task<Void, Never>] = []
        private var done = false

        init(_ details: AskDetails, remaining: Int) {
            self.details = details
            self.remaining = remaining
        }

        func start(_ continuation: CheckedContinuation<AskDetails, Never>) {
            let finished = lock.withLock { () -> Bool in
                self.continuation = continuation
                return done
            }
            if finished { resume() }
        }

        func track(_ tasks: [Task<Void, Never>]) {
            let cancel = lock.withLock { () -> Bool in
                self.tasks = tasks
                return done
            }
            if cancel { tasks.forEach { $0.cancel() } }
        }

        func apply(_ change: (inout AskDetails) -> Void) {
            let last = lock.withLock { () -> Bool in
                guard !done else { return false }
                change(&details)
                remaining -= 1
                return remaining == 0
            }
            if last { finish() }
        }

        func finish() {
            let tasks = lock.withLock { () -> [Task<Void, Never>] in
                done = true
                return self.tasks
            }
            tasks.forEach { $0.cancel() }
            resume()
        }

        private func resume() {
            let pending = lock.withLock { () -> (CheckedContinuation<AskDetails, Never>, AskDetails)? in
                guard let continuation else { return nil }
                self.continuation = nil
                return (continuation, details)
            }
            pending.map { $0.0.resume(returning: $0.1) }
        }
    }
}

// MARK: - Live parts

/// Reverse lookups through netd's DNS upstream, which netd only knows once it starts.
public final class UpstreamReverseResolver: ReverseResolving, @unchecked Sendable {
    private let lock = NSLock()
    private var upstream: DNSForwarding?

    public init() {}

    func use(_ upstream: DNSForwarding?) {
        lock.withLock { self.upstream = upstream }
    }

    public func reverseName(of address: String) async throws -> String? {
        guard let upstream = lock.withLock({ upstream }) else { throw SandvaultError.notInstalled("DNS upstream") }
        return try await upstream.reverseName(of: address)
    }
}

/// Offline from `NetworkDatabase`, online from RDAP; the kind from `NetworkCatalog`.
public final class LiveNetworkLookup: NetworkLooking, @unchecked Sendable {
    public let database: NetworkDatabase
    public let rdap: RDAPClient
    private let lock = NSLock()
    private var online: [String: RDAPClient.Result] = [:]

    public init(database: NetworkDatabase, rdap: RDAPClient = RDAPClient()) {
        self.database = database
        self.rdap = rdap
    }

    public func network(for address: String, mode: NetworkLookupMode) async -> AskNetwork? {
        var found: (asn: UInt32?, owner: String?, country: String?)?
        switch mode {
        case .off:
            return nil
        case .offline:
            if let range = await database.lookup(address) { found = (range.asn, range.owner, range.country) }
        case .online:
            if let cached = lock.withLock({ online[address] }) {
                found = (cached.asn, cached.owner, cached.country)
            } else if let result = try? await rdap.lookup(address) {
                lock.withLock {
                    if online.count >= 1024 { online.removeAll(keepingCapacity: true) }
                    online[address] = result
                }
                found = (result.asn, result.owner, result.country)
            }
        }
        let known = NetworkCatalog.knownAddresses[address.lowercased()]
        guard found != nil || known != nil else { return nil }
        let asn = found?.asn ?? known?.asn
        let owner = known?.owner ?? found?.owner
        let kind = NetworkCatalog.kind(address: address, asn: asn, owner: found?.owner)
        return AskNetwork(asn: asn, owner: owner, country: found?.country ?? known?.country, kind: kind, source: mode)
    }
}

extension LiveAskEnricher {
    /// The parts netd uses, with the DNS upstream attached later (`UpstreamReverseResolver.use`).
    public static func live(paths: AppPaths, runner: CommandRunner) -> LiveAskEnricher {
        LiveAskEnricher(
            names: DNSNameCache(),
            reverse: UpstreamReverseResolver(),
            networks: LiveNetworkLookup(database: NetworkDatabase(path: paths.networkDatabase)),
            programs: LiveProgramInspector(runner: runner),
            history: ConnectionHistoryIndex()
        )
    }

    /// Starts the slow preparations in the background: the offline table and the history from the log.
    public func prepare(_ settings: AskDetailSettings, logPath: String) {
        let history = self.history, networks = self.networks
        let before = Date()
        Task.detached(priority: .utility) {
            if settings.history { history.seed(logPath: logPath, before: before) }
            if settings.network == .offline, let live = networks as? LiveNetworkLookup { live.database.prepare() }
        }
    }
}
