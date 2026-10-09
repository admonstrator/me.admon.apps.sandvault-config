import Foundation

// Interfaces between modules that are built in parallel. Each is implemented in one module and
// consumed in another; the composition happens in the executables (svctl, sandvault-netd) and the app.

/// Maps a loopback source port of a proxied connection to the sandbox process that opened it.
/// Implemented by SandvaultObserve (lsof as the sandbox user), consumed by SandvaultNet.
public protocol ProcessAttributor: Sendable {
    func process(forLocalPort port: UInt16, proto: TransportProtocol) async -> (pid: Int32, name: String)?
}

/// Loopback ports the sandbox may reach under `LocalhostPolicy.sandboxAndHelpers`:
/// ports sandbox processes listen on plus sv's host helpers (Chrome CDP, iOS bridge).
/// Implemented by SandvaultObserve, consumed by sandvault-netd to refresh the pf anchor.
public protocol LocalPortSource: Sendable {
    func allowedLocalPorts() async throws -> [UInt16]
}

/// Applies network/sandbox state through the privileged helper.
/// Implemented by SandvaultEnforce, consumed by svctl, sandvault-netd and the app.
public protocol PolicyApplier: Sendable {
    func applyFirewall(_ state: AppliedState) async throws -> HelperResult
    func applyProfile(_ state: AppliedState) async throws -> HelperResult
}

/// Never attributes; the default until a real attributor is wired in.
public struct NoProcessAttributor: ProcessAttributor {
    public init() {}
    public func process(forLocalPort port: UInt16, proto: TransportProtocol) async -> (pid: Int32, name: String)? { nil }
}

/// A module's contribution to `svctl doctor` and the app's overview.
/// Each module exposes one through its factory (`Observe.makeCheckProvider`, `Enforce.makeCheckProvider`,
/// `Net.makeCheckProvider`); the doctor command concatenates them in that order.
public protocol CheckProvider: Sendable {
    func checks() async -> [Check]
}

public struct NoChecks: CheckProvider {
    public init() {}
    public func checks() async -> [Check] { [] }
}
