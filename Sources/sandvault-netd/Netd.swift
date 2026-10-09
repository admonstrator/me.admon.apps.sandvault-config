import ArgumentParser
import Dispatch
import Foundation
import SandvaultCore
import SandvaultEnforce
import SandvaultNet
import SandvaultObserve

/// LaunchAgent entry point: `sandvault-netd run`.
@main
struct Netd: AsyncParsableCommand {
    static let configuration = CommandConfiguration(
        commandName: "sandvault-netd",
        abstract: "Proxy, DNS forwarder and connection log for the sandvault sandbox.",
        version: BundleIdentity.version,
        subcommands: [Run.self]
    )
}

struct Run: AsyncParsableCommand {
    static let configuration = CommandConfiguration(
        abstract: "Run netd in the foreground (logs to stderr; SIGTERM or SIGINT stops it).",
        discussion: "Listens on the ports of the network policy and on the control socket svctl and the app use."
    )

    @Option(help: "Path to config.json (default: ~/Library/Application Support/<bundle id>/config.json).") var config: String?
    @Option(help: "Control socket path (default: the app support directory, or ~/.local/state when that path is too long).") var socket: String?
    @Option(name: .customLong("upstream-dns"), help: "Upstream resolver, `ip` or `ip:port` (default: first nameserver in /etc/resolv.conf).")
    var upstreamDNS: String?
    @Option(help: "Address the listeners bind to.") var bind = "127.0.0.1"

    func run() async throws {
        let environment = SandvaultEnvironment.current()
        let paths = AppPaths(environment: environment)
        let runner = ProcessCommandRunner()
        let options = NetdOptions(paths: paths, configPath: config, socketPath: socket, bindHost: bind, upstreamDNS: upstreamDNS)
        let daemon = try NetDaemon(
            options: options,
            attributor: Observe.makeProcessAttributor(environment: environment, runner: runner),
            localPorts: Observe.makeLocalPortSource(environment: environment, runner: runner),
            applier: Enforce.makePolicyApplier(runner: runner),
            logger: StandardErrorLog.write
        )
        StandardErrorLog.write("starting for \(environment.hostUser) (config \(options.configPath))")
        try await daemon.start()
        let signal = await SignalWaiter.wait(for: [SIGTERM, SIGINT])
        StandardErrorLog.write("received signal \(signal), shutting down")
        await daemon.stop()
    }
}

enum StandardErrorLog {
    @Sendable static func write(_ message: String) {
        let line = "\(ISO8601DateFormatter().string(from: Date())) sandvault-netd: \(message)\n"
        FileHandle.standardError.write(Data(line.utf8))
    }
}

/// Suspends until one of `signals` arrives (default handling is replaced while waiting).
enum SignalWaiter {
    private final class Sources: @unchecked Sendable {
        var sources: [DispatchSourceSignal] = []
    }

    static func wait(for signals: [Int32]) async -> Int32 {
        let queue = DispatchQueue(label: "\(BundleIdentity.bundleID).netd.signals")
        let holder = Sources()
        return await withCheckedContinuation { continuation in
            queue.sync {
                for number in signals {
                    signal(number, SIG_IGN)
                    let source = DispatchSource.makeSignalSource(signal: number, queue: queue)
                    source.setEventHandler {
                        guard !holder.sources.isEmpty else { return }
                        holder.sources.forEach { $0.cancel() }
                        holder.sources.removeAll()
                        continuation.resume(returning: number)
                    }
                    holder.sources.append(source)
                    source.resume()
                }
            }
        }
    }
}
