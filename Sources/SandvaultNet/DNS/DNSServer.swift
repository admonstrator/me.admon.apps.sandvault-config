import Foundation
import NIOCore
import NIOPosix
import SandvaultCore

/// Answers one DNS query by policy: `deny` → NXDOMAIN, `DnsOverride` → synthesized A/AAAA,
/// `ask` → REFUSED while an ask is raised (its answer applies to the next query), `allow` → upstream.
/// Every query becomes a `.dns` `ConnectionRecord`.
struct DNSService: Sendable {
    let runtime: NetRuntime
    let upstream: DNSForwarding?
    var ttl: UInt32 = 60
    /// Receives the addresses of forwarded answers, so an ask for a bare address can show the name behind it.
    var names: DNSNameCache?

    func answer(_ bytes: [UInt8], transport: TransportProtocol, clientPort: UInt16?) async -> [UInt8]? {
        guard let query = try? DNSMessage(bytes: bytes) else { return DNSMessage.formatError(for: bytes) }
        guard !query.isResponse, query.opcode == 0, query.questions.count == 1 else {
            return DNSMessage.response(to: query, rcode: query.opcode == 0 ? .formatError : .notImplemented).encoded()
        }
        let question = query.questions[0]
        let host = HostName.normalize(question.name)
        let snapshot = runtime.policy.snapshot
        let verdict = snapshot.engine.evaluate(host: host, port: nil)
        let owner = await runtime.owner(ofPort: clientPort, proto: transport)
        let started = DispatchTime.now()

        var decision = ConnectionDecision.allowed
        var response: [UInt8]
        var answers: [String] = []

        if verdict.action == .deny {
            decision = .denied
            response = DNSMessage.response(to: query, rcode: .nameError).encoded()
        } else if let override = snapshot.engine.override(for: host) {
            let record = DNSRecord.address(name: question.name, address: override.address, ttl: ttl)
            let matches = record.map { $0.type == question.type } ?? false
            answers = matches ? [override.address] : []
            response = DNSMessage.response(to: query, rcode: .noError, answers: matches ? [record!] : []).encoded()
        } else {
            var forward = verdict.action == .allow
            if verdict.action == .ask {
                if let resolution = await runtime.asks.raise(host: host, kind: .dns, owner: owner, policy: snapshot.policy) {
                    decision = resolution.decision
                    forward = resolution.allowed
                } else {
                    decision = .denied
                }
            }
            if forward {
                (response, answers) = await forwardUpstream(query: query, bytes: bytes, transport: transport)
                names?.record(name: host, addresses: answers)
            } else {
                let pendingAsk = verdict.action == .ask && decision == .denied
                response = DNSMessage.response(to: query, rcode: pendingAsk ? .refused : .nameError).encoded()
            }
        }

        let elapsed = Int((DispatchTime.now().uptimeNanoseconds - started.uptimeNanoseconds) / 1_000_000)
        runtime.record(ConnectionRecord(
            kind: .dns, host: host, decision: decision, ruleID: verdict.rule?.id, pid: owner?.pid, process: owner?.name,
            bytesIn: Int64(response.count), bytesOut: Int64(bytes.count), durationMs: elapsed, dnsAnswers: answers
        ))
        return response
    }

    private func forwardUpstream(query: DNSMessage, bytes: [UInt8], transport: TransportProtocol) async -> ([UInt8], [String]) {
        guard let upstream else {
            return (DNSMessage.response(to: query, rcode: .serverFailure).encoded(), [])
        }
        do {
            let reply = try await upstream.forward(bytes, transport: transport)
            let addresses = (try? DNSMessage(bytes: reply))?.answerAddresses ?? []
            return (reply, addresses)
        } catch {
            runtime.logger("DNS upstream: \(error)")
            return (DNSMessage.response(to: query, rcode: .serverFailure).encoded(), [])
        }
    }
}

enum DNSListeners {
    static func bindUDP(host: String, port: Int, group: EventLoopGroup, service: DNSService) async throws -> Channel {
        try await DatagramBootstrap(group: group)
            .channelOption(ChannelOptions.socketOption(.so_reuseaddr), value: 1)
            .channelInitializer { channel in
                channel.eventLoop.makeCompletedFuture {
                    try channel.pipeline.syncOperations.addHandler(DNSUDPHandler(service: service))
                }
            }
            .bind(host: host, port: port)
            .get()
    }

    static func bindTCP(host: String, port: Int, group: EventLoopGroup, service: DNSService) async throws -> Channel {
        try await ServerBootstrap(group: group)
            .serverChannelOption(ChannelOptions.socketOption(.so_reuseaddr), value: 1)
            .childChannelInitializer { channel in
                channel.eventLoop.makeCompletedFuture {
                    try channel.pipeline.syncOperations.addHandler(ByteToMessageHandler(DNSLengthFrameDecoder()))
                    try channel.pipeline.syncOperations.addHandler(DNSTCPHandler(service: service))
                }
            }
            .bind(host: host, port: port)
            .get()
    }
}

private final class DNSUDPHandler: ChannelInboundHandler {
    typealias InboundIn = AddressedEnvelope<ByteBuffer>

    private let service: DNSService

    init(service: DNSService) {
        self.service = service
    }

    func channelRead(context: ChannelHandlerContext, data: NIOAny) {
        let envelope = unwrapInboundIn(data)
        let query = Array(envelope.data.readableBytesView)
        let remote = envelope.remoteAddress
        let channel = context.channel
        let service = self.service
        Task {
            let clientPort = remote.port.map { UInt16(truncatingIfNeeded: $0) }
            guard let response = await service.answer(query, transport: .udp, clientPort: clientPort) else { return }
            let buffer = channel.allocator.buffer(bytes: response)
            channel.writeAndFlush(AddressedEnvelope(remoteAddress: remote, data: buffer), promise: nil)
        }
    }

    func errorCaught(context: ChannelHandlerContext, error: Error) {
        // A UDP error (e.g. ICMP port unreachable for one client) must not close the listener.
    }
}

private final class DNSTCPHandler: ChannelInboundHandler {
    typealias InboundIn = ByteBuffer

    private let service: DNSService

    init(service: DNSService) {
        self.service = service
    }

    func channelRead(context: ChannelHandlerContext, data: NIOAny) {
        let query = Array(unwrapInboundIn(data).readableBytesView)
        let channel = context.channel
        let service = self.service
        Task {
            let clientPort = channel.remoteAddress?.port.map { UInt16(truncatingIfNeeded: $0) }
            guard let response = await service.answer(query, transport: .tcp, clientPort: clientPort) else { return }
            var frame = channel.allocator.buffer(capacity: response.count + 2)
            frame.writeInteger(UInt16(response.count))
            frame.writeBytes(response)
            channel.writeAndFlush(frame, promise: nil)
        }
    }

    func errorCaught(context: ChannelHandlerContext, error: Error) {
        context.close(promise: nil)
    }
}
