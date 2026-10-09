import Foundation
import SandvaultCore

/// Host name handling shared by rules, overrides and every listener.
/// Names are compared lowercased without a trailing dot; IDNA labels are taken as given (`xn--...`).
public enum HostName {
    /// Lowercased, trimmed, without IPv6 brackets and trailing dots.
    public static func normalize(_ host: String) -> String {
        var value = host.trimmingCharacters(in: .whitespaces).lowercased()
        if value.hasPrefix("["), value.hasSuffix("]") { value = String(value.dropFirst().dropLast()) }
        while value.hasSuffix(".") { value.removeLast() }
        return value
    }

    public static func isIPLiteral(_ host: String) -> Bool {
        AddressRange.parseAddress(host) != nil
    }

    /// A normalized host is a name of labels (letters, digits, `-`, `_`, or non-ASCII as given) or an IP literal.
    public static func isValid(_ host: String) -> Bool {
        if isIPLiteral(host) { return true }
        guard !host.isEmpty, host.utf8.count <= 253 else { return false }
        for label in host.split(separator: ".", omittingEmptySubsequences: false) {
            guard !label.isEmpty, label.utf8.count <= 63 else { return false }
            for scalar in label.unicodeScalars {
                let ok = scalar.value > 0x7F
                    || ("a"..."z").contains(scalar) || ("0"..."9").contains(scalar)
                    || scalar == "-" || scalar == "_"
                guard ok else { return false }
            }
        }
        return true
    }

    /// Splits `host[:port]` or `[v6]:port`. `nil` when a port is present but not a number in 1...65535.
    public static func splitHostPort(_ authority: String) -> (host: String, port: Int?)? {
        if authority.hasPrefix("[") {
            guard let close = authority.firstIndex(of: "]") else { return nil }
            let host = String(authority[authority.index(after: authority.startIndex)..<close])
            let rest = authority[authority.index(after: close)...]
            if rest.isEmpty { return (host, nil) }
            guard rest.hasPrefix(":"), let port = Int(rest.dropFirst()), (1...65535).contains(port) else { return nil }
            return (host, port)
        }
        let colons = authority.filter { $0 == ":" }.count
        // A bare IPv6 literal has several colons and no port.
        if colons > 1 { return (authority, nil) }
        if colons == 1, let colon = authority.firstIndex(of: ":") {
            guard let port = Int(authority[authority.index(after: colon)...]), (1...65535).contains(port) else { return nil }
            return (String(authority[..<colon]), port)
        }
        return (authority, nil)
    }
}
