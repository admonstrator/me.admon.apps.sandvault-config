import Foundation
import SandvaultCore

/// Connected control clients and their topic subscriptions.
final class ControlHub: @unchecked Sendable {
    typealias Sink = @Sendable (ControlEvent) -> Void

    private struct Client {
        var topics: Set<ControlTopic> = []
        var sink: Sink
    }

    private let lock = NSLock()
    private var clients: [UUID: Client] = [:]

    func add(_ id: UUID, sink: @escaping Sink) {
        lock.withLock { clients[id] = Client(sink: sink) }
    }

    func remove(_ id: UUID) {
        lock.withLock { _ = clients.removeValue(forKey: id) }
    }

    func subscribe(_ id: UUID, topics: [ControlTopic]) {
        lock.withLock { clients[id]?.topics.formUnion(topics) }
    }

    func hasSubscribers(_ topic: ControlTopic) -> Bool {
        lock.withLock { clients.values.contains { $0.topics.contains(topic) } }
    }

    var count: Int { lock.withLock { clients.count } }

    func publish(_ event: ControlEvent, topic: ControlTopic) {
        let sinks = lock.withLock { clients.values.filter { $0.topics.contains(topic) }.map(\.sink) }
        for sink in sinks { sink(event) }
    }
}
