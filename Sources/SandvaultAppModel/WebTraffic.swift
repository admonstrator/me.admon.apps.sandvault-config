import Foundation
import SandvaultCore

/// One line of Activity > Web traffic (D42): one `HTTPSummary`, or one web connection whose requests netd did not
/// see (HTTPS without inspection, blocked before a request, requests not recorded).
public struct WebRequestRow: Identifiable, Sendable, Equatable {
    public enum Visibility: Sendable, Equatable {
        /// Method, address and headers are known (plain HTTP, or HTTPS with inspection).
        case visible
        /// HTTPS without inspection: name, size and duration only.
        case encrypted
        /// A web connection without a request summary (blocked before the request, or requests not recorded).
        case connectionOnly
    }

    /// `<record id>/<index>`, or `<record id>` for a connection without summaries.
    public var id: String
    public var recordID: UUID
    public var time: Date
    public var process: String
    public var host: String
    public var port: UInt16?
    public var kind: ConnectionKind
    public var decision: ConnectionDecision
    /// The `DomainRule` that decided the connection.
    public var ruleID: UUID?
    public var error: String?
    public var summary: HTTPSummary?
    public var visibility: Visibility
    public var bytesIn: Int64
    public var bytesOut: Int64
    public var connectionDurationMs: Int

    public var blocked: Bool { decision.blocked }
    public var method: String? { summary?.method }

    /// `/v1/messages?beta=true`; `nil` without a summary.
    public var path: String? { summary.map { Self.path(of: $0.url) } }

    /// The connection was encrypted between the program and netd (inspected or not).
    public var isTLS: Bool {
        if let url = summary?.url { return url.lowercased().hasPrefix("https://") }
        return kind == .transparentTLS || (kind == .explicitProxy && port != 80)
    }

    /// Records of the web listeners only; DNS and plain TCP are not web traffic.
    public static func isWeb(_ kind: ConnectionKind) -> Bool {
        switch kind {
        case .explicitProxy, .transparentHTTP, .transparentTLS: true
        case .dns, .transparentTCP: false
        }
    }

    /// Newest first; `filter` matches host and path, case-insensitively.
    public static func rows(_ records: [ConnectionRecord], filter: String = "") -> [WebRequestRow] {
        let wanted = filter.trimmingCharacters(in: .whitespaces).lowercased()
        var rows: [WebRequestRow] = []
        for record in records where isWeb(record.kind) {
            rows += make(record)
        }
        if !wanted.isEmpty {
            rows = rows.filter { $0.host.lowercased().contains(wanted) || ($0.path?.lowercased().contains(wanted) ?? false) }
        }
        return rows.sorted { ($0.time, $1.id) > ($1.time, $0.id) }
    }

    static func make(_ record: ConnectionRecord) -> [WebRequestRow] {
        func row(id: String, time: Date, summary: HTTPSummary?, visibility: Visibility) -> WebRequestRow {
            WebRequestRow(
                id: id, recordID: record.id, time: time, process: record.process ?? "unknown", host: record.host, port: record.port,
                kind: record.kind, decision: record.decision, ruleID: record.ruleID, error: record.error, summary: summary,
                visibility: visibility, bytesIn: record.bytesIn, bytesOut: record.bytesOut, connectionDurationMs: record.durationMs
            )
        }
        guard record.http.isEmpty else {
            return record.http.enumerated().map { index, summary in
                // Without a start time, later requests of one connection still sort after earlier ones.
                let time = summary.startedAt ?? record.timestamp.addingTimeInterval(Double(index) / 1000)
                return row(id: "\(record.id.uuidString)/\(index)", time: time, summary: summary, visibility: .visible)
            }
        }
        let tls = record.kind == .transparentTLS || (record.kind == .explicitProxy && record.port != 80)
        let visibility: Visibility = tls && !record.decision.blocked && !record.inspected ? .encrypted : .connectionOnly
        return [row(id: record.id.uuidString, time: record.timestamp, summary: nil, visibility: visibility)]
    }

    /// Path and query of an absolute URL, `/` when it has none.
    static func path(of url: String) -> String {
        guard let scheme = url.range(of: "://") else { return url }
        let rest = url[scheme.upperBound...]
        guard let slash = rest.firstIndex(where: { $0 == "/" || $0 == "?" }) else { return "/" }
        let path = String(rest[slash...])
        return path.hasPrefix("?") ? "/" + path : path
    }

    // MARK: Display

    /// The pill on the right: Blocked, Encrypted, Failed, the status code, or No answer.
    public var statusText: String {
        if blocked { return "Blocked" }
        if let status = summary?.status { return String(status) }
        if error != nil { return "Failed" }
        switch visibility {
        case .encrypted: return "Encrypted"
        case .connectionOnly: return "Connected"
        case .visible: return "No answer"
        }
    }

    public var statusTint: Tint {
        if blocked { return .red }
        if let status = summary?.status { return status >= 500 ? .red : status >= 400 ? .orange : .green }
        if error != nil { return .orange }
        return .gray
    }

    /// `18.4 kB`: the response body, or both directions of a connection without summaries.
    public var sizeText: String {
        guard let summary else { return Format.bytes(bytesIn + bytesOut) }
        return summary.responseBytes.map(Format.bytes) ?? "–"
    }

    public var durationText: String {
        guard let ms = summary == nil ? connectionDurationMs : summary?.durationMs else { return "–" }
        return Format.milliseconds(ms)
    }

    /// `claude · plain HTTP`, `git · contents not visible`.
    public var subtitle: String {
        var parts = [process]
        if !isTLS { parts.append("plain HTTP") }
        if visibility == .encrypted { parts.append("contents not visible") }
        return parts.joined(separator: " · ")
    }

    /// The Result tile: `200 OK`, `Blocked by rule`, `Connected`, or why it failed.
    public var resultText: String {
        if blocked {
            switch decision {
            case .denied: return ruleID == nil ? "Blocked" : "Blocked by rule"
            case .askedDenied: return "Blocked by your answer"
            case .timedOut: return "Blocked, no answer in time"
            case .allowed, .askedAllowed: return "Blocked"
            }
        }
        if let status = summary?.status {
            return HTTPStatus.reason(status).map { "\(status) \($0)" } ?? String(status)
        }
        if let error { return error }
        return summary == nil ? "Connected" : "No answer"
    }

    /// The Size tile: response size for a request, both directions for a connection.
    public var sizeDetail: String {
        guard let summary else { return "\(Format.bytes(bytesIn)) in, \(Format.bytes(bytesOut)) out" }
        let received = summary.responseBytes.map(Format.bytes) ?? "–"
        guard let sent = summary.requestBytes, sent > 0 else { return received }
        return "\(received), sent \(Format.bytes(sent))"
    }

    /// `curl` with the recorded method, URL and headers; `nil` when netd did not see the request or blocked it.
    public func curl(body: String? = nil) -> String? {
        guard let summary, !blocked else { return nil }
        return CurlCommand.make(summary, body: body)
    }
}

/// Reason phrases of the common status codes.
public enum HTTPStatus {
    public static func reason(_ status: Int) -> String? {
        switch status {
        case 100: "Continue"
        case 101: "Switching Protocols"
        case 200: "OK"
        case 201: "Created"
        case 202: "Accepted"
        case 204: "No Content"
        case 206: "Partial Content"
        case 301: "Moved Permanently"
        case 302: "Found"
        case 303: "See Other"
        case 304: "Not Modified"
        case 307: "Temporary Redirect"
        case 308: "Permanent Redirect"
        case 400: "Bad Request"
        case 401: "Unauthorized"
        case 403: "Forbidden"
        case 404: "Not Found"
        case 405: "Method Not Allowed"
        case 408: "Request Timeout"
        case 409: "Conflict"
        case 410: "Gone"
        case 413: "Content Too Large"
        case 415: "Unsupported Media Type"
        case 422: "Unprocessable Content"
        case 429: "Too Many Requests"
        case 500: "Internal Server Error"
        case 501: "Not Implemented"
        case 502: "Bad Gateway"
        case 503: "Service Unavailable"
        case 504: "Gateway Timeout"
        default: nil
        }
    }
}

/// Copy as curl: method, URL and the recorded headers; redacted values stay `<redacted>` for the user to fill in.
public enum CurlCommand {
    /// Headers curl sets itself or that describe the original connection.
    static let skipped: Set<String> = ["host", "content-length", "connection", "proxy-connection", "keep-alive", "transfer-encoding", "te", "upgrade"]

    public static func make(_ summary: HTTPSummary, body: String? = nil) -> String {
        var parts = ["curl"]
        let method = summary.method.uppercased()
        if method == "HEAD" {
            parts.append("--head")
        } else if method != "GET" || body != nil {
            parts += ["-X", method]
        }
        parts.append(AdministratorScript.shellQuote(summary.url))
        var compressed = false
        for header in summary.requestHeaders where header.count == 2 {
            let name = header[0].lowercased()
            if skipped.contains(name) || name.hasPrefix(":") { continue }
            if name == "accept-encoding" {
                compressed = true
                continue
            }
            parts += ["-H", AdministratorScript.shellQuote("\(header[0]): \(header[1])")]
        }
        if compressed { parts.append("--compressed") }
        if let body { parts += ["--data-binary", AdministratorScript.shellQuote(body)] }
        return parts.joined(separator: " ")
    }
}

/// A stored request or response body as the detail pane shows it (D43).
public enum ContentLoad: Sendable, Equatable {
    case loading
    case text(StoredContent, String)
    /// Not text: the pane shows a note with type and size.
    case binary(StoredContent)
    case failed(String)

    /// Text when the bytes are UTF-8 and netd did not mark them binary.
    public static func make(_ meta: StoredContent, _ data: Data) -> ContentLoad {
        guard !meta.binary, let text = String(data: data, encoding: .utf8) else { return .binary(meta) }
        return .text(meta, text)
    }

    /// `Binary (image/png), 1.9 MB. Not shown.`
    public static func binaryNote(_ meta: StoredContent) -> String {
        let type = meta.contentType.map { " (\($0))" } ?? ""
        let size = meta.size.map { ", \(Format.bytes($0))" } ?? ""
        return "Binary\(type)\(size). Not shown."
    }

    /// `Showing the first 1.0 MB of 3.2 MB.`; `nil` when everything was kept.
    public static func truncationNote(_ meta: StoredContent) -> String? {
        guard meta.truncated else { return nil }
        guard let size = meta.size else { return "The transfer ended early; this is what arrived (\(Format.bytes(Int64(meta.storedBytes))))." }
        return "Showing the first \(Format.bytes(Int64(meta.storedBytes))) of \(Format.bytes(size))."
    }
}

extension Format {
    /// `88 ms`, `2.31 s`, `14.2 s`, `3m 05s`.
    public static func milliseconds(_ ms: Int) -> String {
        let value = max(0, ms)
        if value < 1000 { return "\(value) ms" }
        if value < 10_000 { return String(format: "%.2f s", Double(value) / 1000) }
        if value < 60_000 { return String(format: "%.1f s", Double(value) / 1000) }
        return duration(value / 1000)
    }
}
