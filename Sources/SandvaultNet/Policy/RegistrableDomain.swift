import SandvaultCore

/// Approximates the registrable domain ("eTLD+1") without the full public suffix list:
/// the last two labels, or three when the last two form a known multi-part public suffix (`co.uk`).
public enum RegistrableDomain {
    static let multiPartSuffixes: Set<String> = [
        "co.uk", "org.uk", "ac.uk", "gov.uk", "me.uk", "ltd.uk", "plc.uk", "net.uk",
        "com.au", "net.au", "org.au", "edu.au", "gov.au",
        "co.nz", "org.nz", "net.nz",
        "co.jp", "ne.jp", "or.jp", "ac.jp", "go.jp",
        "co.kr", "or.kr",
        "co.in", "net.in", "org.in",
        "co.za", "org.za",
        "com.br", "net.br", "org.br",
        "com.cn", "net.cn", "org.cn",
        "com.mx", "com.tr", "com.tw", "com.hk", "com.sg", "com.ar", "com.co",
        "co.il", "co.id", "or.at", "co.at",
    ]

    /// `api.github.com` → `github.com`, `www.bbc.co.uk` → `bbc.co.uk`; IP literals and single labels unchanged.
    public static func of(_ rawHost: String) -> String {
        let host = HostName.normalize(rawHost)
        guard !HostName.isIPLiteral(host) else { return host }
        let labels = host.split(separator: ".")
        guard labels.count > 2 else { return host }
        let lastTwo = labels.suffix(2).joined(separator: ".")
        let keep = multiPartSuffixes.contains(lastTwo) ? 3 : 2
        return labels.suffix(keep).joined(separator: ".")
    }

    /// The `DomainRule.pattern` an `*Always` answer persists for `host`.
    public static func rulePattern(for rawHost: String, scope: AskScope) -> String {
        let host = HostName.normalize(rawHost)
        switch scope {
        case .host, .hostAndPort:
            return host
        case .domain:
            let domain = of(host)
            if HostName.isIPLiteral(domain) || !domain.contains(".") { return domain }
            return "*." + domain
        }
    }
}
