import NIOHTTP1
import SandvaultCore

/// Header and URL handling for forwarded HTTP/1.1 messages.
enum HTTPRewrite {
    /// RFC 9110 §7.6.1 connection-specific fields. Transfer-Encoding and Content-Length stay: NIO decodes
    /// the body framing and re-encodes it from them.
    static let hopByHop: Set<String> = ["connection", "keep-alive", "proxy-connection", "te", "trailer", "upgrade"]

    /// Removes hop-by-hop fields, fields named in `Connection`, and every `Proxy-*` field.
    static func stripHopByHop(_ headers: HTTPHeaders) -> HTTPHeaders {
        var named = hopByHop
        for value in headers["connection"] {
            for token in value.split(separator: ",") {
                named.insert(token.trimmingCharacters(in: .whitespaces).lowercased())
            }
        }
        named.remove("transfer-encoding")
        named.remove("content-length")
        var result = HTTPHeaders()
        for (name, value) in headers {
            let lower = name.lowercased()
            if named.contains(lower) || lower.hasPrefix("proxy-") { continue }
            result.add(name: name, value: value)
        }
        return result
    }

    /// Header pairs for `HTTPSummary`, values of `redact` (lowercase names) replaced by `<redacted>`.
    static func summarize(_ headers: HTTPHeaders, redact: Set<String>) -> [[String]] {
        headers.map { name, value in [name, redact.contains(name.lowercased()) ? "<redacted>" : value] }
    }

    struct AbsoluteURL: Equatable {
        var host: String
        var port: Int
        /// `host[:port]` as it should appear in a `Host` header.
        var authority: String
        /// Path and query (`/` at least).
        var originForm: String
        /// The URL without user info and fragment, for logs.
        var display: String
    }

    /// Parses `http://[user@]host[:port][/path][?query][#fragment]`; `nil` for anything else.
    static func parseAbsolute(_ uri: String) -> AbsoluteURL? {
        guard uri.lowercased().hasPrefix("http://") else { return nil }
        var rest = Substring(uri.dropFirst(7))
        if let hash = rest.firstIndex(of: "#") { rest = rest[..<hash] }
        let authorityEnd = rest.firstIndex { $0 == "/" || $0 == "?" } ?? rest.endIndex
        var authority = String(rest[..<authorityEnd])
        var path = String(rest[authorityEnd...])
        if let at = authority.lastIndex(of: "@") { authority = String(authority[authority.index(after: at)...]) }
        if path.isEmpty { path = "/" } else if path.hasPrefix("?") { path = "/" + path }
        guard let (rawHost, rawPort) = HostName.splitHostPort(authority) else { return nil }
        let host = HostName.normalize(rawHost)
        guard HostName.isValid(host) else { return nil }
        let port = rawPort ?? 80
        return AbsoluteURL(host: host, port: port, authority: authority, originForm: path, display: "http://\(authority)\(path)")
    }

    /// `host[:port]` of a CONNECT request target; the port defaults to 443.
    static func parseAuthority(_ target: String) -> (host: String, port: Int)? {
        guard let (rawHost, rawPort) = HostName.splitHostPort(target) else { return nil }
        let host = HostName.normalize(rawHost)
        guard HostName.isValid(host) else { return nil }
        return (host, rawPort ?? 443)
    }

    /// A short plain-text response that closes the connection.
    static func errorResponse(_ status: HTTPResponseStatus, body: String) -> (HTTPResponseHead, String) {
        var headers = HTTPHeaders()
        headers.add(name: "Content-Type", value: "text/plain; charset=utf-8")
        headers.add(name: "Content-Length", value: String(body.utf8.count))
        headers.add(name: "Connection", value: "close")
        return (HTTPResponseHead(version: .http1_1, status: status, headers: headers), body)
    }
}
