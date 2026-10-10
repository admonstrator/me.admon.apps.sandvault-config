import Foundation
#if canImport(FoundationNetworking)
import FoundationNetworking
#endif
import SandvaultCore

/// One HTTPS GET. A seam, so tests answer with fixtures instead of the network.
public protocol HTTPFetching: Sendable {
    func get(_ url: URL, timeout: Double) async throws -> (status: Int, body: Data)
}

/// `HTTPFetching` on URLSession (follows redirects, honours task cancellation).
public struct URLSessionFetcher: HTTPFetching {
    public init() {}

    public func get(_ url: URL, timeout: Double) async throws -> (status: Int, body: Data) {
        var request = URLRequest(url: url, cachePolicy: .reloadIgnoringLocalCacheData, timeoutInterval: timeout)
        request.setValue("application/rdap+json, application/json", forHTTPHeaderField: "Accept")
        let box = TaskBox()
        return try await withTaskCancellationHandler {
            try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<(status: Int, body: Data), Error>) in
                let task = URLSession.shared.dataTask(with: request) { data, response, error in
                    if let error {
                        continuation.resume(throwing: error)
                    } else {
                        continuation.resume(returning: ((response as? HTTPURLResponse)?.statusCode ?? 0, data ?? Data()))
                    }
                }
                box.set(task)
                task.resume()
            }
        } onCancel: {
            box.cancel()
        }
    }

    private final class TaskBox: @unchecked Sendable {
        private let lock = NSLock()
        private var task: URLSessionDataTask?
        private var cancelled = false

        func set(_ task: URLSessionDataTask) {
            let cancel = lock.withLock {
                self.task = task
                return cancelled
            }
            if cancel { task.cancel() }
        }

        func cancel() {
            let task = lock.withLock {
                cancelled = true
                return self.task
            }
            task?.cancel()
        }
    }
}

/// Network owner and country from RDAP (`https://rdap.org/ip/<address>` redirects to the registry, RFC 9083).
/// Reveals the address to rdap.org and the registry (D39).
public struct RDAPClient: Sendable {
    public var fetcher: HTTPFetching
    public var timeout: Double
    public var base: URL

    public init(fetcher: HTTPFetching = URLSessionFetcher(), timeout: Double = 1.2, base: URL = URL(string: "https://rdap.org/ip/")!) {
        self.fetcher = fetcher
        self.timeout = timeout
        self.base = base
    }

    public struct Result: Sendable, Equatable {
        public var asn: UInt32?
        public var owner: String?
        public var country: String?
    }

    public func lookup(_ address: String) async throws -> Result? {
        guard HostName.isIPLiteral(address) else { return nil }
        let (status, body) = try await fetcher.get(base.appendingPathComponent(address), timeout: timeout)
        guard status == 200 else { return nil }
        return Self.parse(body)
    }

    /// Reads an RDAP `ip network` object: `country`, the registrant's vCard `fn` (else `name`), and the ASN from
    /// ARIN's `arin_originas0_originautnums` extension when present.
    public static func parse(_ data: Data) -> Result? {
        guard let object = (try? JSONSerialization.jsonObject(with: data)) as? [String: Any] else { return nil }
        let entities = object["entities"] as? [[String: Any]] ?? []
        let registrant = entities.first { ($0["roles"] as? [String])?.contains("registrant") == true }
        let owner = registrant.flatMap(vcardName) ?? object["name"] as? String
        let country = (object["country"] as? String).map { $0.uppercased() }.flatMap { $0.count == 2 ? $0 : nil }
        let asn = (object["arin_originas0_originautnums"] as? [Any])?.first.flatMap { value -> UInt32? in
            if let number = value as? NSNumber { return number.uint32Value }
            return (value as? String).flatMap { UInt32($0) }
        }
        guard owner != nil || country != nil || asn != nil else { return nil }
        return Result(asn: asn, owner: owner, country: country)
    }

    private static func vcardName(_ entity: [String: Any]) -> String? {
        guard let vcard = entity["vcardArray"] as? [Any], vcard.count > 1, let properties = vcard[1] as? [[Any]] else { return nil }
        for property in properties where property.count >= 4 && property[0] as? String == "fn" {
            if let name = property[3] as? String, !name.isEmpty { return name }
        }
        return nil
    }
}
