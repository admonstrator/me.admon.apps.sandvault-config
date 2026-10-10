import Foundation
import NIOCore
import NIOHTTP1
import SandvaultCore

/// Counts one request or response body and, with a `limit`, keeps its first bytes (D43). NIO's HTTP decoders hand
/// over the payload without chunked framing, so size and kept bytes are the body after the transfer encoding.
struct BodyCapture {
    /// Body bytes seen so far.
    private(set) var size: Int64 = 0
    private var kept = Data()
    /// Bytes to keep; `nil` counts only.
    let limit: Int?
    let contentType: String?
    /// A `Content-Encoding` netd does not decode (gzip, br, ...).
    let encoded: Bool

    init(headers: HTTPHeaders, limit: Int?) {
        self.limit = limit.map { max(0, $0) }
        contentType = headers.first(name: "content-type")
        let encoding = headers[canonicalForm: "content-encoding"].map { $0.lowercased() }
        encoded = encoding.contains { !$0.isEmpty && $0 != "identity" }
    }

    mutating func append(_ buffer: ByteBuffer) {
        size += Int64(buffer.readableBytes)
        guard let limit, kept.count < limit else { return }
        kept.append(contentsOf: buffer.readableBytesView.prefix(limit - kept.count))
    }

    /// The kept bytes and their description; `nil` when nothing is kept (counting only, or an empty body).
    /// `complete` is false when the stream ended before the body did.
    func stored(complete: Bool) -> (StoredContent, Data)? {
        guard limit != nil, !kept.isEmpty else { return nil }
        let binary = encoded || Self.isBinary(contentType: contentType, sample: kept)
        let meta = StoredContent(contentType: contentType, size: complete ? size : nil, storedBytes: kept.count, binary: binary)
        return (meta, kept)
    }

    /// Text media types (`text/*`, JSON, XML, JavaScript, forms and their `+json`/`+xml` relatives) are not binary;
    /// without a type the bytes decide: UTF-8 without NUL is text.
    static func isBinary(contentType: String?, sample: Data) -> Bool {
        let type = contentType?.split(separator: ";").first?.trimmingCharacters(in: .whitespaces).lowercased() ?? ""
        guard !type.isEmpty else { return !looksLikeText(sample) }
        if type.hasPrefix("text/") || type.hasSuffix("+json") || type.hasSuffix("+xml") { return false }
        return !textTypes.contains(type)
    }

    static let textTypes: Set<String> = [
        "application/json", "application/xml", "application/javascript", "application/x-javascript", "application/ecmascript",
        "application/x-www-form-urlencoded", "application/graphql", "application/x-ndjson", "application/jsonl", "application/yaml",
        "application/x-yaml", "application/toml", "application/sql",
    ]

    /// Valid UTF-8 (a character cut off at the end is allowed) without NUL bytes.
    static func looksLikeText(_ data: Data) -> Bool {
        let sample = data.prefix(64 << 10)
        guard !sample.contains(0) else { return false }
        for trim in 0...min(3, sample.count) where String(data: sample.dropLast(trim), encoding: .utf8) != nil {
            return true
        }
        return false
    }
}
