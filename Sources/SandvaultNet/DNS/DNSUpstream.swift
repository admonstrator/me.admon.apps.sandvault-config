import Foundation
import NIOCore
import NIOPosix
import SandvaultCore

/// Sends one query to the upstream resolver and returns its raw answer.
protocol DNSForwarding: Sendable {
    func forward(_ query: [UInt8], transport: TransportProtocol) async throws -> [UInt8]
}

/// Forwards over UDP (TCP when the client used TCP) to one upstream resolver.
struct DNSUpstream: DNSForwarding {
    let server: SocketAddress
    let group: EventLoopGroup
    var timeout: TimeAmount = .seconds(5)

    /// The first usable `nameserver` line of resolv.conf (zone-scoped IPv6 entries are skipped).
    static func systemResolver(resolvConf: String = "/etc/resolv.conf") -> String? {
        guard let text = try? String(contentsOfFile: resolvConf, encoding: .utf8) else { return nil }
        for line in text.split(separator: "\n") {
            let fields = line.split(whereSeparator: { $0 == " " || $0 == "\t" })
            guard fields.count >= 2, fields[0] == "nameserver" else { continue }
            let address = String(fields[1])
            if AddressRange.parseAddress(address) != nil { return address }
        }
        return nil
    }

    func forward(_ query: [UInt8], transport: TransportProtocol) async throws -> [UInt8] {
        let server = self.server
        switch transport {
        case .udp:
            return try await roundTrip(
                open: { loop, promise in
                    DatagramBootstrap(group: loop)
                        .channelInitializer { channel in
                            channel.eventLoop.makeCompletedFuture {
                                try channel.pipeline.syncOperations.addHandler(DNSUDPResponseCollector(promise: promise))
                            }
                        }
                        .bind(host: server.protocol == .inet6 ? "::" : "0.0.0.0", port: 0)
                },
                send: { channel in
                    channel.writeAndFlush(AddressedEnvelope(remoteAddress: server, data: channel.allocator.buffer(bytes: query)))
                }
            )
        case .tcp:
            return try await roundTrip(
                open: { loop, promise in
                    ClientBootstrap(group: loop)
                        .connectTimeout(timeout)
                        .channelInitializer { channel in
                            channel.eventLoop.makeCompletedFuture {
                                try channel.pipeline.syncOperations.addHandler(ByteToMessageHandler(DNSLengthFrameDecoder()))
                                try channel.pipeline.syncOperations.addHandler(DNSTCPResponseCollector(promise: promise))
                            }
                        }
                        .connect(to: server)
                },
                send: { channel in
                    var frame = channel.allocator.buffer(capacity: query.count + 2)
                    frame.writeInteger(UInt16(query.count))
                    frame.writeBytes(query)
                    return channel.writeAndFlush(frame)
                }
            )
        }
    }

    /// Opens a channel whose collector completes `promise` with the first answer, sends, and waits up to `timeout`.
    private func roundTrip(
        open: (EventLoop, EventLoopPromise<[UInt8]>) -> EventLoopFuture<Channel>,
        send: (Channel) -> EventLoopFuture<Void>
    ) async throws -> [UInt8] {
        let loop = group.next()
        let promise = loop.makePromise(of: [UInt8].self)
        let server = self.server
        let timer = loop.scheduleTask(in: timeout) { promise.fail(SandvaultError.timedOut("DNS query to \(server)")) }
        defer {
            timer.cancel()
            promise.fail(SandvaultError.io("DNS query abandoned"))  // no-op when already answered
        }
        let channel = try await open(loop, promise).get()
        defer { channel.close(promise: nil) }
        try await send(channel).get()
        return try await promise.futureResult.get()
    }
}

/// Two-byte length prefix framing of DNS over TCP (RFC 1035 §4.2.2).
struct DNSLengthFrameDecoder: ByteToMessageDecoder {
    typealias InboundOut = ByteBuffer

    mutating func decode(context: ChannelHandlerContext, buffer: inout ByteBuffer) throws -> DecodingState {
        guard let length = buffer.getInteger(at: buffer.readerIndex, as: UInt16.self),
              buffer.readableBytes >= 2 + Int(length)
        else { return .needMoreData }
        buffer.moveReaderIndex(forwardBy: 2)
        context.fireChannelRead(wrapInboundOut(buffer.readSlice(length: Int(length))!))
        return .continue
    }
}

private final class DNSUDPResponseCollector: ChannelInboundHandler {
    typealias InboundIn = AddressedEnvelope<ByteBuffer>
    private let promise: EventLoopPromise<[UInt8]>

    init(promise: EventLoopPromise<[UInt8]>) {
        self.promise = promise
    }

    func channelRead(context: ChannelHandlerContext, data: NIOAny) {
        promise.succeed(Array(unwrapInboundIn(data).data.readableBytesView))
    }

    func errorCaught(context: ChannelHandlerContext, error: Error) {
        promise.fail(error)
    }
}

private final class DNSTCPResponseCollector: ChannelInboundHandler {
    typealias InboundIn = ByteBuffer
    private let promise: EventLoopPromise<[UInt8]>

    init(promise: EventLoopPromise<[UInt8]>) {
        self.promise = promise
    }

    func channelRead(context: ChannelHandlerContext, data: NIOAny) {
        promise.succeed(Array(unwrapInboundIn(data).readableBytesView))
    }

    func channelInactive(context: ChannelHandlerContext) {
        promise.fail(SandvaultError.io("DNS upstream closed the connection"))
    }

    func errorCaught(context: ChannelHandlerContext, error: Error) {
        promise.fail(error)
    }
}
