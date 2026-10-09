import SandvaultCore

/// Keeps the pf anchor's dynamic loopback ports current: when the mode is `open` or `proxyOnly` and
/// `localhost == .sandboxAndHelpers`, it fetches the allowed ports and calls `applyFirewall` only when they
/// changed. Errors are logged once per kind and never stop netd.
public actor LocalPortRefresher {
    public enum Outcome: Sendable, Equatable {
        /// The mode or localhost policy does not use dynamic ports.
        case notApplicable
        case unchanged([UInt16])
        case applied([UInt16])
        case failed(String)
    }

    private let source: LocalPortSource
    private let applier: PolicyApplier
    private let log: @Sendable (String) -> Void
    private var lastApplied: [UInt16]?
    private var reported: Set<String> = []

    public init(source: LocalPortSource, applier: PolicyApplier, log: @escaping @Sendable (String) -> Void) {
        self.source = source
        self.applier = applier
        self.log = log
    }

    public static func applies(to policy: NetworkPolicy) -> Bool {
        (policy.mode == .open || policy.mode == .proxyOnly) && policy.localhost == .sandboxAndHelpers
    }

    @discardableResult
    public func tick(config: AppConfig) async -> Outcome {
        guard Self.applies(to: config.network) else {
            lastApplied = nil
            return .notApplicable
        }
        let ports: [UInt16]
        do {
            ports = Array(Set(try await source.allowedLocalPorts())).sorted()
        } catch {
            return failed("local ports", error)
        }
        if ports == lastApplied { return .unchanged(ports) }
        do {
            let result = try await applier.applyFirewall(AppliedState(config: config, dynamicLocalPorts: ports))
            guard result.ok else { return failed("firewall refresh", SandvaultError.io(result.message)) }
        } catch {
            return failed("firewall refresh", error)
        }
        lastApplied = ports
        reported.removeAll()
        log("firewall refreshed with local ports \(ports.map(String.init).joined(separator: ","))")
        return .applied(ports)
    }

    private func failed(_ stage: String, _ error: Error) -> Outcome {
        let kind = "\(stage): \(Self.kind(of: error))"
        if reported.insert(kind).inserted { log("\(stage) failed: \(error)") }
        return .failed(kind)
    }

    /// The enum case name for errors with associated values, otherwise the type name.
    static func kind(of error: Error) -> String {
        if let label = Mirror(reflecting: error).children.first?.label { return label }
        return String(describing: type(of: error))
    }
}
