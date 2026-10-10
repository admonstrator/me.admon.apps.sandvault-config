import NIOCore
import NIOHTTP1
import NIOPosix
import SandvaultCore

/// Binds the proxy listeners. Each accepted connection starts with a byte counter.
enum ProxyListeners {
    enum Kind: Sendable { case explicitProxy, transparentHTTP, transparentTLS, transparentTCP }

    static func bind(_ kind: Kind, host: String, port: Int, group: EventLoopGroup, runtime: NetRuntime) async throws -> Channel {
        try await ServerBootstrap(group: group)
            .serverChannelOption(ChannelOptions.backlog, value: 256)
            .serverChannelOption(ChannelOptions.socketOption(.so_reuseaddr), value: 1)
            // tcpOption, not socketOption: at SOL_SOCKET level the same number means SO_DEBUG, which needs
            // CAP_NET_ADMIN on Linux and made every accepted connection fail without it.
            .childChannelOption(ChannelOptions.tcpOption(.tcp_nodelay), value: 1)
            .childChannelInitializer { channel in
                channel.eventLoop.makeCompletedFuture {
                    let counter = ByteCounter()
                    let sync = channel.pipeline.syncOperations
                    try sync.addHandler(ByteCountingHandler(counter: counter))
                    switch kind {
                    case .explicitProxy:
                        try sync.addHandler(ByteToMessageHandler(HTTPRequestDecoder(leftOverBytesStrategy: .forwardBytes)))
                        try sync.addHandler(HTTPResponseEncoder())
                        try sync.addHandler(ConnectHandler(runtime: runtime, counter: counter))
                        try sync.addHandler(HTTPForwardHandler(runtime: runtime, mode: .explicitProxy, counter: counter))
                    case .transparentHTTP:
                        try sync.addHandler(ByteToMessageHandler(HTTPRequestDecoder()))
                        try sync.addHandler(HTTPResponseEncoder())
                        try sync.addHandler(HTTPForwardHandler(runtime: runtime, mode: .transparent, counter: counter))
                    case .transparentTLS:
                        try sync.addHandler(SNIRouter(runtime: runtime, counter: counter))
                    case .transparentTCP:
                        try sync.addHandler(TCPRouter(runtime: runtime, counter: counter))
                    }
                }
            }
            .bind(host: host, port: port)
            .get()
    }
}
