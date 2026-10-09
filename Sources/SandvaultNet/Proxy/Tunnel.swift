import NIOCore
import NIOHTTP1
import NIOPosix
import NIOSSL
import SandvaultCore

/// Steps shared by CONNECT and the transparent TLS listener once a tunnel is allowed.
enum Tunnel {
    /// Opens a raw upstream connection with reading paused until the tunnel is glued.
    static func connect(on eventLoop: EventLoop, addresses: [SocketAddress], host: String, port: Int) -> EventLoopFuture<Channel> {
        ClientBootstrap(group: eventLoop)
            .connectTimeout(.seconds(10))
            .channelOption(ChannelOptions.autoRead, value: false)
            .channelOption(ChannelOptions.allowRemoteHalfClosure, value: true)
            .resolver(FixedAddressResolver(eventLoop: eventLoop, addresses: addresses))
            .connect(host: host, port: port)
    }

    /// Adds a matched glue pair (client side at the end of its pipeline) and resumes reading on both channels.
    static func glue(client: Channel, upstream: Channel) throws {
        let (local, remote) = GlueHandler.matchedPair()
        try client.pipeline.syncOperations.addHandler(local)
        try upstream.pipeline.syncOperations.addHandler(remote)
        try client.syncOptions?.setOption(ChannelOptions.allowRemoteHalfClosure, value: true)
        try client.syncOptions?.setOption(ChannelOptions.autoRead, value: true)
        try upstream.syncOptions?.setOption(ChannelOptions.autoRead, value: true)
        client.read()
        upstream.read()
    }

    /// TLS server with a leaf for `host`, an HTTP codec and an inspecting forwarder, appended to `client`.
    static func addInspection(
        to client: Channel, host: String, port: Int, addresses: [SocketAddress], runtime: NetRuntime,
        counter: ByteCounter, tracker: ConnectionTracker
    ) throws {
        let context = try runtime.inspection.serverContext(for: host)
        let sync = client.pipeline.syncOperations
        try sync.addHandler(NIOSSLServerHandler(context: context))
        try sync.addHandler(HTTPResponseEncoder())
        try sync.addHandler(ByteToMessageHandler(HTTPRequestDecoder()))
        try sync.addHandler(
            HTTPForwardHandler(runtime: runtime, mode: .inspected(host: host, port: port, addresses: addresses, tracker: tracker), counter: counter)
        )
        tracker.setInspected()
    }

    /// Finishes the tunnel's record once the client side is closed (and the upstream, when there is one).
    static func finish(_ tracker: ConnectionTracker, counter: ByteCounter, client: Channel, upstream: Channel?) {
        let closed = upstream.map { client.closeFuture.and($0.closeFuture).map { _ in } } ?? client.closeFuture
        closed.whenComplete { _ in
            let totals = counter.totals
            tracker.finish(bytesIn: totals.sent, bytesOut: totals.received)
        }
    }
}
