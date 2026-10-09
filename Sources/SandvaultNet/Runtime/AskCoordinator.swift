import Foundation
import SandvaultCore

/// What an ask came to.
public struct AskResolution: Sendable, Equatable {
    public var allowed: Bool
    public var decision: ConnectionDecision
    public var reason: String
}

/// The process behind a connection, as far as `ProcessAttributor` knows.
public struct ProcessOwner: Sendable, Equatable {
    public var pid: Int32
    public var name: String
}

/// Holds connections whose host matched an `ask` until a control client answers or the timeout passes.
/// Concurrent asks for the same host share one `AskRequest`. Answers are remembered for `graceSeconds`,
/// so the DNS query that raised an ask and the connection that follows it see the same decision.
actor AskCoordinator {
    private struct Pending {
        var request: AskRequest
        var waiters: [CheckedContinuation<AskResolution, Never>] = []
        var timeout: Task<Void, Never>?
    }

    private struct Grant {
        var resolution: AskResolution
        var until: Date
    }

    static let graceSeconds: TimeInterval = 30

    private let hub: ControlHub
    private let persist: @Sendable (_ pattern: String, _ action: DomainAction) throws -> DomainRule
    private let log: @Sendable (String) -> Void
    private var pending: [UUID: Pending] = [:]
    private var byHost: [String: UUID] = [:]
    private var grants: [String: Grant] = [:]

    init(
        hub: ControlHub,
        persist: @escaping @Sendable (_ pattern: String, _ action: DomainAction) throws -> DomainRule,
        log: @escaping @Sendable (String) -> Void
    ) {
        self.hub = hub
        self.persist = persist
        self.log = log
    }

    /// Waits for an answer (or the timeout); without a subscribed client the fallback applies at once.
    func decide(host: String, port: UInt16?, kind: ConnectionKind, owner: ProcessOwner?, policy: NetworkPolicy) async -> AskResolution {
        if let grant = activeGrant(host) { return grant }
        guard hub.hasSubscribers(.asks) else { return Self.fallback(policy, reason: "no client is answering asks") }
        let id = open(host: host, port: port, kind: kind, owner: owner, policy: policy)
        return await withCheckedContinuation { continuation in
            if pending[id] != nil {
                pending[id]!.waiters.append(continuation)
            } else {
                continuation.resume(returning: activeGrant(host) ?? Self.fallback(policy, reason: "ask expired"))
            }
        }
    }

    /// Raises (or joins) an ask without waiting, for DNS. Returns a resolution only when one applies right now.
    func raise(host: String, kind: ConnectionKind, owner: ProcessOwner?, policy: NetworkPolicy) -> AskResolution? {
        if let grant = activeGrant(host) { return grant }
        guard hub.hasSubscribers(.asks) else { return Self.fallback(policy, reason: "no client is answering asks") }
        _ = open(host: host, port: nil, kind: kind, owner: owner, policy: policy)
        return nil
    }

    func answer(_ answer: AskAnswer) throws {
        guard let entry = pending.removeValue(forKey: answer.id) else {
            throw SandvaultError.invalidInput("no pending ask with id \(answer.id.uuidString.lowercased())")
        }
        let host = entry.request.host
        byHost[host] = nil
        entry.timeout?.cancel()

        let allowed = answer.decision == .allowOnce || answer.decision == .allowAlways
        var reason = "answered \(answer.decision.rawValue)"
        if answer.decision == .allowAlways || answer.decision == .denyAlways {
            let pattern = RegistrableDomain.rulePattern(for: host, scope: answer.scope)
            do {
                let rule = try persist(pattern, allowed ? .allow : .deny)
                reason += ", saved rule \(rule.pattern)"
            } catch {
                log("cannot save rule \(pattern): \(error)")
            }
        }
        let resolution = AskResolution(allowed: allowed, decision: allowed ? .askedAllowed : .askedDenied, reason: reason)
        grants[host] = Grant(resolution: resolution, until: Date().addingTimeInterval(Self.graceSeconds))
        for waiter in entry.waiters { waiter.resume(returning: resolution) }
        hub.publish(.askResolved(id: answer.id, decision: resolution.decision), topic: .asks)
    }

    func pendingRequests() -> [AskRequest] {
        pending.values.map(\.request).sorted { $0.createdAt < $1.createdAt }
    }

    var pendingCount: Int { pending.count }

    /// Resolves every waiting connection with `deny` (shutdown).
    func cancelAll() {
        for (id, entry) in pending {
            entry.timeout?.cancel()
            let resolution = AskResolution(allowed: false, decision: .timedOut, reason: "netd is shutting down")
            for waiter in entry.waiters { waiter.resume(returning: resolution) }
            hub.publish(.askResolved(id: id, decision: .timedOut), topic: .asks)
        }
        pending.removeAll()
        byHost.removeAll()
    }

    // MARK: - Internals

    private func open(host: String, port: UInt16?, kind: ConnectionKind, owner: ProcessOwner?, policy: NetworkPolicy) -> UUID {
        if let id = byHost[host] { return id }
        let timeout = max(1, policy.askTimeoutSeconds)
        let now = Date()
        let request = AskRequest(
            host: host, port: port, kind: kind, pid: owner?.pid, process: owner?.name,
            createdAt: now, expiresAt: now.addingTimeInterval(TimeInterval(timeout))
        )
        let id = request.id
        let timer = Task { [weak self] in
            try? await Task.sleep(nanoseconds: UInt64(timeout) * 1_000_000_000)
            guard !Task.isCancelled else { return }
            await self?.expire(id, policy: policy)
        }
        pending[id] = Pending(request: request, timeout: timer)
        byHost[host] = id
        hub.publish(.ask(request), topic: .asks)
        return id
    }

    private func expire(_ id: UUID, policy: NetworkPolicy) {
        guard let entry = pending.removeValue(forKey: id) else { return }
        byHost[entry.request.host] = nil
        let resolution = Self.fallback(policy, reason: "ask timed out")
        for waiter in entry.waiters { waiter.resume(returning: resolution) }
        hub.publish(.askResolved(id: id, decision: .timedOut), topic: .asks)
    }

    private func activeGrant(_ host: String) -> AskResolution? {
        guard let grant = grants[host] else { return nil }
        if grant.until < Date() {
            grants[host] = nil
            return nil
        }
        return grant.resolution
    }

    /// `askFallback`: `allow` lets the connection through (recorded as allowed), anything else blocks it (`timedOut`).
    static func fallback(_ policy: NetworkPolicy, reason: String) -> AskResolution {
        if policy.askFallback == .allow {
            return AskResolution(allowed: true, decision: .allowed, reason: "\(reason), fallback allow")
        }
        return AskResolution(allowed: false, decision: .timedOut, reason: "\(reason), fallback deny")
    }
}
