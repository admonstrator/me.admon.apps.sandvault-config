import ArgumentParser
import Foundation
import SandvaultCore
import SandvaultObserve

struct NetCommand: AsyncParsableCommand {
    static let configuration = CommandConfiguration(
        commandName: "net",
        abstract: "Show the sandbox user's sockets and, optionally, traffic per process.",
        subcommands: [NetDatabaseCommand.self]
    )

    @OptionGroup var global: GlobalOptions

    @Flag(name: .long, help: "Only listening TCP sockets.")
    var listening = false

    @Flag(name: .long, help: "Also show bytes in/out per process (one nettop sample).")
    var traffic = false

    struct NetOutput: Encodable {
        var connections: [SandboxConnection]
        var traffic: [ProcessTraffic]?
        /// ICMP tools (ping, traceroute): no socket of the sandbox user, so lsof cannot list them.
        var icmp: [ICMPActivity]
    }

    func run() async throws {
        try ObservePlatform.require("net")
        let monitor = ConnectionMonitor(environment: global.environment, runner: global.runner)
        var connections = try await monitor.connections()
        if listening { connections = connections.filter(\.isListening) }
        let usage = traffic ? try await monitor.traffic() : nil
        let icmp = listening ? [] : ICMPActivity.find(
            in: try await ProcessMonitor(environment: global.environment, runner: global.runner).sandboxProcesses()
        )
        if global.json { return try Output.json(NetOutput(connections: connections, traffic: usage, icmp: icmp)) }

        if connections.isEmpty {
            Output.line(listening ? "no listening sockets" : "no sockets")
        } else {
            Output.table(["PID", "PROCESS", "PROTO", "LOCAL", "REMOTE", "STATE"], connections.map { c in
                [
                    String(c.pid), c.process, c.proto.rawValue + (c.family == .ipv6 ? "6" : ""),
                    Format.endpoint(c.localAddress, c.localPort, family: c.family),
                    Format.endpoint(c.remoteAddress, c.remotePort, family: c.family), c.state ?? "-",
                ]
            })
        }
        if !icmp.isEmpty {
            Output.line()
            Output.table(["PID", "TOOL", "TARGET", "RUNNING"], icmp.map {
                [String($0.pid), $0.tool, $0.target ?? "-", Format.duration($0.elapsedSeconds)]
            })
        }
        if let usage {
            Output.line()
            if usage.isEmpty {
                Output.line("no traffic data for sandbox processes (nettop may not see other users' processes)")
            } else {
                Output.table(["PID", "PROCESS", "IN", "OUT"], usage.map {
                    [String($0.pid), $0.process, Format.bytes($0.bytesIn), Format.bytes($0.bytesOut)]
                })
            }
        }
    }
}
