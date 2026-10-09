import Foundation
import NIOCore
import NIOPosix
#if canImport(Darwin)
import Darwin
#elseif canImport(Glibc)
import Glibc
#endif

/// Resolves a host name to socket addresses without blocking an event loop.
public protocol HostResolver: Sendable {
    func resolve(host: String, port: Int) async throws -> [SocketAddress]
}

/// `getaddrinfo` (the host user's resolver) on NIO's thread pool; every address, in resolver order.
public struct SystemHostResolver: HostResolver {
    public init() {}

    public func resolve(host: String, port: Int) async throws -> [SocketAddress] {
        try await NIOThreadPool.singleton.runIfActive { try Self.lookup(host: host, port: port) }
    }

    static func lookup(host: String, port: Int) throws -> [SocketAddress] {
        var hints = addrinfo()
        #if canImport(Darwin)
        hints.ai_socktype = SOCK_STREAM
        #else
        hints.ai_socktype = Int32(SOCK_STREAM.rawValue)
        #endif
        hints.ai_family = AF_UNSPEC
        var list: UnsafeMutablePointer<addrinfo>?
        let status = getaddrinfo(host, String(port), &hints, &list)
        guard status == 0, let first = list else {
            throw ResolutionError(host: host, detail: String(cString: gai_strerror(status)))
        }
        defer { freeaddrinfo(list) }
        var result: [SocketAddress] = []
        var cursor: UnsafeMutablePointer<addrinfo>? = first
        while let entry = cursor {
            if let address = entry.pointee.ai_addr {
                switch entry.pointee.ai_family {
                case AF_INET:
                    address.withMemoryRebound(to: sockaddr_in.self, capacity: 1) { result.append(SocketAddress($0.pointee, host: host)) }
                case AF_INET6:
                    address.withMemoryRebound(to: sockaddr_in6.self, capacity: 1) { result.append(SocketAddress($0.pointee, host: host)) }
                default:
                    break
                }
            }
            cursor = entry.pointee.ai_next
        }
        var seen = Set<String>()
        return result.filter { seen.insert($0.description).inserted }
    }
}

public struct ResolutionError: Error, CustomStringConvertible {
    public var host: String
    public var detail: String
    public var description: String { "cannot resolve \(host): \(detail)" }
}

/// Fixed answers; used by tests and as a building block.
public struct StaticHostResolver: HostResolver {
    public var table: [String: [String]]

    public init(_ table: [String: [String]]) {
        self.table = table
    }

    public func resolve(host: String, port: Int) async throws -> [SocketAddress] {
        guard let addresses = table[HostName.normalize(host)], !addresses.isEmpty else {
            throw ResolutionError(host: host, detail: "not in the static table")
        }
        return try addresses.map { try SocketAddress(ipAddress: $0, port: port) }
    }
}

/// Hands pre-resolved addresses to `ClientBootstrap`, so its Happy Eyeballs connect uses exactly them.
final class FixedAddressResolver: Resolver, Sendable {
    private let eventLoop: EventLoop
    private let addresses: [SocketAddress]

    init(eventLoop: EventLoop, addresses: [SocketAddress]) {
        self.eventLoop = eventLoop
        self.addresses = addresses
    }

    func initiateAQuery(host: String, port: Int) -> EventLoopFuture<[SocketAddress]> {
        eventLoop.makeSucceededFuture(addresses.filter { $0.protocol == .inet })
    }

    func initiateAAAAQuery(host: String, port: Int) -> EventLoopFuture<[SocketAddress]> {
        eventLoop.makeSucceededFuture(addresses.filter { $0.protocol == .inet6 })
    }

    func cancelQueries() {}
}
