import Foundation

extension AskDetails {
    /// `reverseName` when the PTR lookup ran and found no name (`nil` means: not looked up, failed or late).
    public static let noReverseName = ""

    /// True when the reverse lookup answered without a name.
    public var reverseLookupFoundNothing: Bool { reverseName == AskDetails.noReverseName }
}

/// Judges `AskDetails` with points per signal (D40). Pure: netd, the app and svctl get the same result.
/// Only details that are present and turned on in the settings count.
public enum AskAssessor {
    public typealias Signal = AskAssessment.Signal

    public static func assess(details: AskDetails, port: UInt16?, settings: AskDetailSettings) -> AskAssessment {
        var signals: [Signal] = []
        let target = details.name?.name == nil ? "address" : "host"

        if settings.name, let name = details.name, name.source == .none, name.name == nil {
            signals.append(Signal(detail: .name, effect: .minus, points: 2, text: "The program never looked up a name for this address."))
        }

        if settings.reverseDNS, details.reverseLookupFoundNothing {
            signals.append(Signal(detail: .reverseName, effect: .minus, points: 1, text: "The address has no reverse DNS name."))
        }

        if settings.port, let port {
            if matchesProtocol(port: port, encryption: details.encryption) {
                signals.append(Signal(detail: .port, effect: .plus, points: -2, text: protocolText(port)))
            } else if let service = details.service, service.port == port, service.name == nil {
                signals.append(Signal(detail: .port, effect: .minus, points: 2, text: "Port \(port) is in no list of known services."))
            }
        }

        var networkMinus: Signal?
        if settings.network != .off, let network = details.network {
            let asn = network.asn.map { " (AS\($0))" } ?? ""
            let owner = network.owner ?? "This network"
            switch network.kind {
            case .knownService:
                signals.append(Signal(detail: .network, effect: .plus, points: -2, text: "\(owner), a known service\(asn)."))
            case .cdn:
                signals.append(Signal(detail: .network, effect: .info, points: 0, text: "\(owner)\(asn), a CDN. Many services share it."))
            case .hosting:
                networkMinus = Signal(detail: .network, effect: .minus, points: 1, text: "Rented servers\(asn): hosting, VPS or cloud.")
            case .other:
                break
            }
        }

        if settings.program, let program = details.program {
            let path = program.path ?? "The program"
            if program.inTemporaryFolder {
                signals.append(Signal(detail: .program, effect: .minus, points: 1, text: "\(path) runs from a temporary folder."))
            } else if program.signature == .unsigned {
                signals.append(Signal(detail: .program, effect: .minus, points: 1, text: "\(path) is not signed."))
            } else if program.signature == .adHoc {
                signals.append(Signal(detail: .program, effect: .minus, points: 1, text: "\(path) has only an ad hoc signature."))
            }
        }

        if settings.history, let history = details.history {
            if history.allowed > 0 {
                signals.append(Signal(detail: .history, effect: .plus, points: -2, text: "Allowed \(times(history.allowed)) before."))
            } else if history.denied > 0 {
                signals.append(Signal(detail: .history, effect: .info, points: 0, text: "Denied \(times(history.denied)) before, never allowed."))
            } else {
                signals.append(Signal(detail: .history, effect: .info, points: 0, text: "The sandbox has not reached this \(target) before."))
            }
        }

        if details.encryption == .unknown {
            signals.append(Signal(detail: .encryption, effect: .info, points: 0, text: "netd cannot tell what protocol this is."))
        } else if details.encryption == .plain, port == 53 {
            signals.append(Signal(detail: .encryption, effect: .info, points: 0, text: "Classic DNS is unencrypted. Normal for port 53."))
        }

        // A marked country adds points only next to another signal against the destination, never alone (D40).
        let country = details.network?.country?.uppercased()
        let marked = settings.network != .off && country.map { code in settings.markedCountries.contains { $0.uppercased() == code } } == true
        let othersAgainst = signals.contains { $0.points > 0 } || networkMinus != nil
        if marked, othersAgainst, let country {
            if networkMinus != nil {
                let asn = details.network?.asn.map { " (AS\($0))" } ?? ""
                networkMinus = Signal(detail: .network, effect: .minus, points: 3, text: "Rented servers in a country you marked (\(country))\(asn).")
            } else {
                networkMinus = Signal(detail: .network, effect: .minus, points: 2, text: "The network is in a country you marked (\(country)).")
            }
        }
        if let networkMinus { signals.append(networkMinus) }

        let order = AskDetailKind.allCases
        signals.sort { order.firstIndex(of: $0.detail)! < order.firstIndex(of: $1.detail)! }
        let score = signals.reduce(0) { $0 + $1.points }
        return AskAssessment(level: AskAssessment.level(for: score), score: score, signals: signals)
    }

    /// 443 with TLS, 53 with classic DNS, 80 with plain HTTP.
    static func matchesProtocol(port: UInt16, encryption: AskEncryption?) -> Bool {
        switch (port, encryption) {
        case (443, .tls?), (53, .plain?), (80, .plain?): true
        default: false
        }
    }

    private static func protocolText(_ port: UInt16) -> String {
        switch port {
        case 443: "Port 443 with TLS, as expected."
        case 53: "Port 53 carries DNS, as expected."
        default: "Port 80 with plain HTTP, as expected."
        }
    }

    private static func times(_ count: Int) -> String { count == 1 ? "once" : "\(count) times" }
}
