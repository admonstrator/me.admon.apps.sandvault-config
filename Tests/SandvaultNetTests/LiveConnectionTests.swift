import Foundation
import NIOCore
import NIOPosix
import NIOSSL
import SandvaultCore
import Testing
@testable import SandvaultNet

@Suite struct ConnectionTrackerSnapshotTests {
    func make() -> (ConnectionTracker, Recorded<ConnectionRecord>, Recorded<ConnectionRecord>) {
        let updates = Recorded<ConnectionRecord>()
        let finished = Recorded<ConnectionRecord>()
        let tracker = ConnectionTracker(
            record: ConnectionRecord(kind: .transparentTLS, host: "api.example", port: 443, decision: .allowed),
            sink: { finished.append($0) }, update: { updates.append($0) }
        )
        return (tracker, updates, finished)
    }

    @Test func snapshotsStartWhenTheTunnelOpensAndStopWhenItEnds() {
        let (tracker, updates, finished) = make()
        tracker.add(HTTPSummary(method: "GET", url: "https://api.example/early"))
        #expect(updates.all.isEmpty, "nothing is published before the tunnel is open")

        let counter = ByteCounter()
        counter.add(received: 120)
        counter.add(sent: 900)
        tracker.opened(counter: counter)
        tracker.opened(counter: counter)
        #expect(updates.all.count == 1)
        #expect(updates.all.first?.http.count == 1)
        #expect(updates.all.first?.bytesIn == 900 && updates.all.first?.bytesOut == 120)

        tracker.add(HTTPSummary(method: "POST", url: "https://api.example/v1/messages"))
        #expect(updates.all.map(\.http.count) == [1, 2])
        #expect(Set(updates.all.map(\.id)) == [tracker.id])

        tracker.finish(bytesIn: 1000, bytesOut: 200)
        tracker.add(HTTPSummary(method: "GET", url: "https://api.example/late"))
        #expect(updates.all.count == 2, "no snapshot after the record is finished")
        #expect(finished.all.map(\.id) == [tracker.id])
        #expect(finished.all.first?.http.count == 2, "the finished record is handed over as it was")
    }

    @Test func theRegistryHoldsTheLatestSnapshotOldestFirst() {
        let open = OpenConnections()
        let first = ConnectionRecord(timestamp: Date(timeIntervalSince1970: 10), kind: .explicitProxy, host: "a.example", decision: .allowed)
        var second = ConnectionRecord(timestamp: Date(timeIntervalSince1970: 20), kind: .transparentTLS, host: "b.example", decision: .allowed)
        open.set(second)
        open.set(first)
        second.http = [HTTPSummary(method: "GET", url: "https://b.example/")]
        open.set(second)
        #expect(open.snapshots.map(\.host) == ["a.example", "b.example"])
        #expect(open.snapshots.last?.http.count == 1)
        open.remove(first.id)
        #expect(open.snapshots.map(\.host) == ["b.example"])
    }
}

@Suite(.timeLimit(.minutes(1))) struct LiveConnectionIntegrationTests {
    /// The inspected requests of a keep-alive connection reach `.live` subscribers and `openConnections` while it
    /// is still open; closing it sends the finished record with the same id.
    @Test func inspectedRequestsAreVisibleBeforeTheConnectionCloses() async throws {
        let tls = try OriginTLS()
        let origin = try await TestOrigin.start(name: "secure", tls: try tls.serverContext(for: "secure.test"))
        let config = AppConfig.testing(
            [("secure.test", .allow)], inspect: ["secure.test"], overrides: ["secure.test": "127.0.0.1"], blockPrivate: true, inspection: true
        )
        let netd = try await TestNetd.start(config, transparentTLSPort: origin.port, trustRoots: try tls.trustRoots, createCA: true)
        try await withCleanup({ await origin.stop(); await netd.stop() }) {
            let control = try await ControlClient.connect(socketPath: netd.socketPath)
            defer { control.close() }
            try await control.subscribe([.connections, .live])
            let events = Recorded<ControlEvent>()
            let reader = Task { for await event in control.events { events.append(event) } }
            defer { reader.cancel() }

            var trust = TLSConfiguration.makeClientConfiguration()
            trust.trustRoots = .file(CAStore(paths: netd.layout.paths).certificatePath)
            let client = try await KeepAliveClient.connect(
                port: Int(netd.ports.transparentTLS), tls: try NIOSSLContext(configuration: trust), serverName: "secure.test"
            )
            try await client.send("GET /one HTTP/1.1\r\nHost: secure.test\r\n\r\n")
            try await client.waitFor("secure saw GET /one")
            try await client.send("GET /two HTTP/1.1\r\nHost: secure.test\r\n\r\n")
            try await client.waitFor("secure saw GET /two")

            let live = try await Self.waitFor(events) { event -> ConnectionRecord? in
                guard case .update(let record) = event, record.http.count == 2 else { return nil }
                return record
            }
            #expect(live.inspected && live.host == "secure.test")
            #expect(live.http.map { URL(string: $0.url)?.path } == ["/one", "/two"])
            #expect(live.http.allSatisfy { $0.status == 200 })
            #expect(netd.daemon.runtime.log.recent(limit: 100).allSatisfy { $0.id != live.id }, "the connection is not finished")
            let open = try await control.openConnections()
            #expect(open.map(\.id) == [live.id])
            #expect(open.first?.http.count == 2)

            await client.close()
            let finished = try await Self.waitFor(events) { event -> ConnectionRecord? in
                guard case .connection(let record) = event, record.id == live.id else { return nil }
                return record
            }
            #expect(finished.http.count == 2 && finished.durationMs >= live.durationMs)
            #expect(try await control.openConnections().isEmpty)
        }
    }

    static func waitFor<T>(_ events: Recorded<ControlEvent>, timeout: Double = 5, _ match: (ControlEvent) -> T?) async throws -> T {
        let deadline = Date().addingTimeInterval(timeout)
        while Date() < deadline {
            if let found = events.all.lazy.compactMap(match).first { return found }
            try await Task.sleep(nanoseconds: 20_000_000)
        }
        throw SandvaultError.timedOut("no matching control event; got \(events.all)")
    }
}

/// A client connection that stays open across requests.
struct KeepAliveClient {
    let channel: Channel
    let received: Recorded<UInt8>

    static func connect(port: Int, tls: NIOSSLContext, serverName: String) async throws -> KeepAliveClient {
        let received = Recorded<UInt8>()
        let channel = try await ClientBootstrap(group: MultiThreadedEventLoopGroup.singleton)
            .channelInitializer { channel in
                channel.eventLoop.makeCompletedFuture {
                    try channel.pipeline.syncOperations.addHandler(NIOSSLClientHandler(context: tls, serverHostname: serverName))
                    try channel.pipeline.syncOperations.addHandler(ByteRecorder(received: received))
                }
            }
            .connect(host: "127.0.0.1", port: port)
            .get()
        return KeepAliveClient(channel: channel, received: received)
    }

    func send(_ text: String) async throws {
        try await channel.writeAndFlush(channel.allocator.buffer(string: text)).get()
    }

    func waitFor(_ text: String, timeout: Double = 5) async throws {
        let deadline = Date().addingTimeInterval(timeout)
        while Date() < deadline {
            if String(decoding: received.all, as: UTF8.self).contains(text) { return }
            try await Task.sleep(nanoseconds: 20_000_000)
        }
        throw SandvaultError.timedOut("no \(text) in \(String(decoding: received.all, as: UTF8.self))")
    }

    func close() async {
        try? await channel.close()
    }
}

private final class ByteRecorder: ChannelInboundHandler {
    typealias InboundIn = ByteBuffer

    let received: Recorded<UInt8>

    init(received: Recorded<UInt8>) {
        self.received = received
    }

    func channelRead(context: ChannelHandlerContext, data: NIOAny) {
        for byte in unwrapInboundIn(data).readableBytesView { received.append(byte) }
    }
}
