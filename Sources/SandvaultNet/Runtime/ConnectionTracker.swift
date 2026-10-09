import Foundation
import NIOCore
import SandvaultCore

/// Raw bytes through the client socket: `received` from the sandbox (bytesOut), `sent` to it (bytesIn).
final class ByteCounter: @unchecked Sendable {
    private let lock = NSLock()
    private var receivedTotal: Int64 = 0
    private var sentTotal: Int64 = 0

    func add(received: Int) { lock.withLock { receivedTotal += Int64(received) } }
    func add(sent: Int) { lock.withLock { sentTotal += Int64(sent) } }
    var totals: (received: Int64, sent: Int64) { lock.withLock { (receivedTotal, sentTotal) } }
}

/// First handler of every client pipeline; counts bytes on the wire.
final class ByteCountingHandler: ChannelDuplexHandler, RemovableChannelHandler {
    typealias InboundIn = ByteBuffer
    typealias InboundOut = ByteBuffer
    typealias OutboundIn = IOData
    typealias OutboundOut = IOData

    let counter: ByteCounter

    init(counter: ByteCounter) {
        self.counter = counter
    }

    func channelRead(context: ChannelHandlerContext, data: NIOAny) {
        counter.add(received: unwrapInboundIn(data).readableBytes)
        context.fireChannelRead(data)
    }

    func write(context: ChannelHandlerContext, data: NIOAny, promise: EventLoopPromise<Void>?) {
        counter.add(sent: unwrapOutboundIn(data).readableBytes)
        context.write(data, promise: promise)
    }
}

/// Builds one `ConnectionRecord` and hands it to the log exactly once.
final class ConnectionTracker: @unchecked Sendable {
    static let maxHTTPSummaries = 200

    private let lock = NSLock()
    private var record: ConnectionRecord
    private let start = DispatchTime.now()
    private var finished = false
    private let sink: @Sendable (ConnectionRecord) -> Void

    init(record: ConnectionRecord, sink: @escaping @Sendable (ConnectionRecord) -> Void) {
        self.record = record
        self.sink = sink
    }

    func setInspected() { lock.withLock { record.inspected = true } }

    /// Keeps the first reason an allowed connection failed.
    func fail(_ reason: String) {
        lock.withLock { if record.error == nil { record.error = reason } }
    }

    func add(_ summary: HTTPSummary) {
        lock.withLock {
            if record.http.count < Self.maxHTTPSummaries { record.http.append(summary) }
        }
    }

    /// Bytes as seen from the sandbox: `bytesIn` received by it, `bytesOut` sent by it.
    func finish(bytesIn: Int64, bytesOut: Int64) {
        let done: ConnectionRecord? = lock.withLock {
            guard !finished else { return nil }
            finished = true
            record.bytesIn = bytesIn
            record.bytesOut = bytesOut
            record.durationMs = Int((DispatchTime.now().uptimeNanoseconds - start.uptimeNanoseconds) / 1_000_000)
            return record
        }
        if let done { sink(done) }
    }
}

/// Live counters for `NetdStatus`.
final class NetdCounters: @unchecked Sendable {
    private let lock = NSLock()
    private var active = 0
    private var allowed = 0
    private var denied = 0

    func opened() { lock.withLock { active += 1 } }
    func closed() { lock.withLock { active = max(0, active - 1) } }

    func count(_ decision: ConnectionDecision) {
        lock.withLock {
            if decision.blocked { denied += 1 } else { allowed += 1 }
        }
    }

    var snapshot: (active: Int, allowed: Int, denied: Int) { lock.withLock { (active, allowed, denied) } }
}
