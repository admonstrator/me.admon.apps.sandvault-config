import Foundation
import Observation
import SandvaultCore
import SandvaultNet

/// Pending connection asks from netd (ask panel and notifications). netd raises asks only while the app's
/// `NetdLink` is subscribed; otherwise the configured fallback applies at once (D22).
@MainActor @Observable
public final class AsksModel {
    public private(set) var answering: Set<UUID> = []
    public var message: UserMessage?
    private var scopes: [UUID: AskScope] = [:]

    @ObservationIgnored private let netd: NetdLink
    @ObservationIgnored private let editor: ConfigEditor

    public init(netd: NetdLink, editor: ConfigEditor) {
        self.netd = netd
        self.editor = editor
    }

    /// Oldest first.
    public var pending: [AskRequest] {
        netd.pendingAsks.sorted { ($0.createdAt, $0.id.uuidString) < ($1.createdAt, $1.id.uuidString) }
    }

    /// Whether netd can raise asks at all right now.
    public var isListening: Bool { netd.isConnected }

    /// What happens when nobody answers in time.
    public var fallback: DomainAction { editor.config.network.askFallback }

    public func scope(for ask: AskRequest) -> AskScope {
        scopes[ask.id] ?? .host
    }

    public func setScope(_ scope: AskScope, for ask: AskRequest) {
        scopes[ask.id] = scope
    }

    /// The rule pattern an `*Always` answer saves: the host, or `*.<registrable domain>`.
    public func rulePattern(for ask: AskRequest, scope: AskScope) -> String {
        RegistrableDomain.rulePattern(for: ask.host, scope: scope)
    }

    /// Whole seconds left until netd applies the fallback.
    public func remainingSeconds(_ ask: AskRequest, at date: Date) -> Int {
        max(0, Int(ask.expiresAt.timeIntervalSince(date).rounded(.up)))
    }

    /// 1 when the ask was raised, 0 when it expires.
    public func fractionRemaining(_ ask: AskRequest, at date: Date) -> Double {
        let total = ask.expiresAt.timeIntervalSince(ask.createdAt)
        guard total > 0 else { return 0 }
        return min(1, max(0, ask.expiresAt.timeIntervalSince(date) / total))
    }

    /// `node (4242) · port 443 · tls`.
    public func detail(for ask: AskRequest) -> String {
        var parts: [String] = []
        if let process = ask.process { parts.append(ask.pid.map { "\(process) (\($0))" } ?? process) }
        parts.append(ask.port.map { "port \($0)" } ?? "DNS lookup")
        parts.append(ask.kind.displayName)
        return parts.joined(separator: " · ")
    }

    public func answer(_ ask: AskRequest, _ decision: AskDecision) async {
        guard !answering.contains(ask.id) else { return }
        answering.insert(ask.id)
        defer { answering.remove(ask.id) }
        let scope = scope(for: ask)
        do {
            try await netd.answer(AskAnswer(id: ask.id, decision: decision, scope: scope))
            scopes[ask.id] = nil
            let saved = decision == .allowAlways || decision == .denyAlways ? " (rule \(rulePattern(for: ask, scope: scope)))" : ""
            message = .success("\(decision.displayName): \(ask.host)\(saved)")
        } catch {
            message = UserMessage(error: error, action: "Answer the request for \(ask.host)")
        }
    }
}
