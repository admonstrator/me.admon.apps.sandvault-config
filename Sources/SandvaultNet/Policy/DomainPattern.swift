import SandvaultCore

/// The parsed form of `DomainRule.pattern` and `DnsOverride.pattern`.
public enum DomainPattern: Sendable, Equatable, Hashable, CustomStringConvertible {
    /// `*`: every host.
    case any
    /// `example.com` or an IP literal: exactly this host.
    case exact(String)
    /// `*.example.com`: subdomains and the apex `example.com`.
    case suffix(String)

    /// Parses and normalizes; throws `invalidInput` for anything that is not a host, `*.<host>` or `*`.
    public init(_ text: String) throws {
        let value = HostName.normalize(text)
        if value == "*" {
            self = .any
        } else if value.hasPrefix("*.") {
            let base = String(value.dropFirst(2))
            guard HostName.isValid(base), !HostName.isIPLiteral(base) else {
                throw SandvaultError.invalidInput("'\(text)' is not a valid domain pattern")
            }
            self = .suffix(base)
        } else {
            guard HostName.isValid(value) else {
                throw SandvaultError.invalidInput("'\(text)' is not a valid host name, '*.<domain>' or '*'")
            }
            self = .exact(value)
        }
    }

    public var description: String {
        switch self {
        case .any: "*"
        case .exact(let host): host
        case .suffix(let base): "*." + base
        }
    }

    /// `host` must already be normalized.
    public func matches(_ host: String) -> Bool {
        switch self {
        case .any: true
        case .exact(let name): host == name
        case .suffix(let base): host == base || host.hasSuffix("." + base)
        }
    }

    /// Exact beats any wildcard, a longer suffix beats a shorter one, `*` comes last.
    var specificity: Int {
        switch self {
        case .any: 0
        case .suffix(let base): 1 + base.split(separator: ".").count
        case .exact: 1_000
        }
    }
}
