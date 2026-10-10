import Foundation
import SandvaultCore

/// Heuristics that sort a network into `AskNetwork.Kind`. All lists live here; they are hand-picked and incomplete
/// on purpose: a well-known address or AS number gets a kind, everything else falls back to keywords of the AS
/// description, then to `other`. Order: known address, known AS, CDN, hosting.
public enum NetworkCatalog {
    public struct KnownAddress: Sendable, Equatable {
        public var owner: String
        public var asn: UInt32?
        public var country: String?
    }

    /// Public DNS resolvers the sandbox may use directly.
    public static let knownAddresses: [String: KnownAddress] = {
        var table: [String: KnownAddress] = [:]
        func add(_ addresses: [String], _ owner: String, _ asn: UInt32?, _ country: String?) {
            for address in addresses { table[address] = KnownAddress(owner: owner, asn: asn, country: country) }
        }
        add(["8.8.8.8", "8.8.4.4", "2001:4860:4860::8888", "2001:4860:4860::8844"], "Google Public DNS", 15169, "US")
        add(["1.1.1.1", "1.0.0.1", "2606:4700:4700::1111", "2606:4700:4700::1001"], "Cloudflare DNS", 13335, "US")
        add(["9.9.9.9", "149.112.112.112", "2620:fe::fe", "2620:fe::9"], "Quad9", 19281, "CH")
        add(["208.67.222.222", "208.67.220.220"], "OpenDNS", 36692, "US")
        add(["94.140.14.14", "94.140.15.15"], "AdGuard DNS", nil, nil)
        add(["194.242.2.2"], "Mullvad DNS", nil, "SE")
        return table
    }()

    /// Networks of large services a developer Mac talks to all the time.
    public static let knownServiceASNs: [UInt32: String] = [
        714: "Apple", 6185: "Apple", 36459: "GitHub", 15169: "Google", 8075: "Microsoft", 32934: "Meta",
        62371: "Proton", 41231: "Canonical",
    ]

    /// Content delivery networks many services share. Amazon's AS16509 also carries EC2; it counts as CloudFront here.
    public static let cdnASNs: [UInt32: String] = [
        13335: "Cloudflare", 209242: "Cloudflare", 20940: "Akamai", 16625: "Akamai", 21342: "Akamai", 54113: "Fastly",
        16509: "Amazon CloudFront", 15133: "Edgecast", 60068: "CDN77", 200325: "Bunny CDN",
    ]

    /// Rented servers: VPS, cloud compute, data centres.
    public static let hostingASNs: [UInt32: String] = [
        14061: "DigitalOcean", 24940: "Hetzner", 213230: "Hetzner", 16276: "OVH", 63949: "Linode", 20473: "Vultr (Choopa)",
        51167: "Contabo", 9009: "M247", 60781: "Leaseweb", 28753: "Leaseweb", 12876: "Scaleway", 396982: "Google Cloud",
        45102: "Alibaba Cloud", 132203: "Tencent Cloud", 31898: "Oracle Cloud", 47583: "Hostinger", 8560: "IONOS",
        40676: "Psychz", 8100: "QuadraNet", 36352: "ColoCrossing", 49505: "Selectel", 9123: "Timeweb", 48282: "VDSINA",
        53667: "FranTech", 14618: "Amazon EC2", 197540: "netcup", 202425: "IP Volume", 210644: "Aeza",
    ]

    /// Lower-case fragments of an AS description that suggest a CDN.
    public static let cdnKeywords = ["cloudflare", "akamai", "fastly", "cloudfront", "edgecast", "cdn"]

    /// Lower-case fragments of an AS description that suggest rented servers.
    public static let hostingKeywords = [
        "hosting", "server", "vps", "cloud", "datacenter", "data center", "colo", "dedicated", "ovh", "hetzner",
        "digitalocean", "linode", "vultr", "contabo", "choopa", "m247", "leaseweb", "scaleway", "vdsina",
    ]

    public static func kind(address: String?, asn: UInt32?, owner: String?) -> AskNetwork.Kind {
        if let address, knownAddresses[address.lowercased()] != nil { return .knownService }
        if let asn {
            if knownServiceASNs[asn] != nil { return .knownService }
            if cdnASNs[asn] != nil { return .cdn }
            if hostingASNs[asn] != nil { return .hosting }
        }
        let text = owner?.lowercased() ?? ""
        if cdnKeywords.contains(where: text.contains) { return .cdn }
        if hostingKeywords.contains(where: text.contains) { return .hosting }
        return .other
    }
}
