import Foundation
import Observation
import SandvaultCore
import SandvaultNet

/// Pending connection asks from netd (ask panel and notifications). netd raises asks only while the app's
/// `NetdLink` is subscribed; otherwise the configured fallback applies at once (D22).
@MainActor @Observable
public final class AsksModel {
    public private(set) var answering: Set<UUID> = []
    public var message: UserMessage?
    /// The "Always" choice per ask; missing means just once.
    private var remembered: [UUID: AskScope] = [:]

    @ObservationIgnored private let netd: NetdLink
    @ObservationIgnored private let editor: ConfigEditor

    public init(netd: NetdLink, editor: ConfigEditor) {
        self.netd = netd
        self.editor = editor
    }

    /// Oldest first.
    public var pending: [AskRequest] {
        netd.pendingAsks.sorted { ($0.createdAt, $0.id.uuidString) < ($1.createdAt, $1.id.uuidString) }
    }

    /// Whether netd can raise asks at all right now.
    public var isListening: Bool { netd.isConnected }

    /// What happens when nobody answers in time.
    public var fallback: DomainAction { editor.config.network.askFallback }

    // MARK: How long the answer counts (D41)

    /// The rule scope chosen in the panel's menu; `nil` means just once.
    public func rememberedScope(for ask: AskRequest) -> AskScope? {
        remembered[ask.id]
    }

    public func setRememberedScope(_ scope: AskScope?, for ask: AskRequest) {
        remembered[ask.id] = scope
    }

    /// The scopes the menu offers, most specific first (`AskScope.options`).
    public func scopes(for ask: AskRequest) -> [AskScope] {
        AskScope.options(port: ask.port, hasDomain: AskFormat.hasDomain(ask.host))
    }

    /// "Just once", then one "Always: ..." entry per offered scope.
    public func rememberOptions(for ask: AskRequest) -> [AskRememberOption] {
        [.justOnce] + scopes(for: ask).map { scope in
            AskRememberOption(scope: scope, label: "Always: " + AskFormat.scopeLabel(scope, host: ask.host, port: ask.port), target: target(for: ask, scope: scope))
        }
    }

    /// The closed menu shows one short word; the target is in the open menu and the tooltip.
    public func rememberTitle(for ask: AskRequest) -> String {
        rememberedScope(for: ask) == nil ? "Just once" : "Always"
    }

    public func rememberHelp(for ask: AskRequest) -> String {
        rememberedScope(for: ask).map { "Rule: " + target(for: ask, scope: $0) } ?? "Answer only this request"
    }

    /// The rule pattern an `*Always` answer saves: the host, or `*.<registrable domain>`.
    public func rulePattern(for ask: AskRequest, scope: AskScope) -> String {
        RegistrableDomain.rulePattern(for: ask.host, scope: scope)
    }

    /// What a rule covers, as the menu shows it: `*.npmjs.org`, `185.142.236.41:8947`.
    public func target(for ask: AskRequest, scope: AskScope) -> String {
        let pattern = rulePattern(for: ask, scope: scope)
        return scope == .hostAndPort ? AskFormat.endpoint(pattern, ask.port) : pattern
    }

    /// Menu choice plus button: just once gives `allowOnce`/`denyOnce`, a rule `allowAlways`/`denyAlways`.
    public static func decision(allow: Bool, remembered scope: AskScope?) -> AskDecision {
        switch (allow, scope != nil) {
        case (true, false): .allowOnce
        case (true, true): .allowAlways
        case (false, false): .denyOnce
        case (false, true): .denyAlways
        }
    }

    /// The safer default (D41): Deny is the default button for a suspicious request when the user wants that.
    public func prefersDeny(_ ask: AskRequest) -> Bool {
        editor.config.network.askDetails.saferDefault && ask.details?.assessment?.level == .suspicious
    }

    // MARK: Countdown

    /// Whole seconds left until netd applies the fallback.
    public func remainingSeconds(_ ask: AskRequest, at date: Date) -> Int {
        max(0, Int(ask.expiresAt.timeIntervalSince(date).rounded(.up)))
    }

    /// 1 when the ask was raised, 0 when it expires.
    public func fractionRemaining(_ ask: AskRequest, at date: Date) -> Double {
        let total = ask.expiresAt.timeIntervalSince(ask.createdAt)
        guard total > 0 else { return 0 }
        return min(1, max(0, ask.expiresAt.timeIntervalSince(date) / total))
    }

    /// The number inside the ring: seconds, or minutes from 100 seconds on.
    public func ringLabel(_ ask: AskRequest, at date: Date) -> String {
        let seconds = remainingSeconds(ask, at: date)
        return seconds < 100 ? "\(seconds)" : "\(seconds / 60)m"
    }

    /// `0:27 left, then deny`.
    public func ringHelp(_ ask: AskRequest, at date: Date) -> String {
        "\(Format.countdown(remainingSeconds(ask, at: date))) left, then \(fallback.displayName.lowercased())"
    }

    // MARK: Panel and notification text

    /// `node (4242) · port 443 · tls`.
    public func detail(for ask: AskRequest) -> String {
        var parts: [String] = []
        if let process = ask.process { parts.append(ask.pid.map { "\(process) (\($0))" } ?? process) }
        parts.append(ask.port.map { "port \($0)" } ?? "DNS lookup")
        parts.append(ask.kind.displayName)
        return parts.joined(separator: " · ")
    }

    /// Everything the panel shows for one ask; `date` only dates the history tile.
    public func presentation(for ask: AskRequest, at date: Date) -> AskPresentation {
        AskPresentation(
            ask: ask, at: date, options: rememberOptions(for: ask), prefersDeny: prefersDeny(ask)
        )
    }

    /// `Allow 185.142.236.41:8947?`
    public func notificationTitle(for ask: AskRequest) -> String {
        "Allow \(AskFormat.destination(ask))?"
    }

    /// `Suspicious · python3 (4242) · port 8947 · tls`.
    public func notificationBody(for ask: AskRequest) -> String {
        let verdict = ask.details?.assessment.map { AskVerdict(assessment: $0).title }
        return ([verdict].compactMap { $0 } + [detail(for: ask)]).joined(separator: " · ")
    }

    // MARK: Answering

    /// The panel's buttons: the menu choice decides once or always.
    public func answer(_ ask: AskRequest, allow: Bool) async {
        let scope = rememberedScope(for: ask)
        await send(ask, decision: Self.decision(allow: allow, remembered: scope), scope: scope ?? scopes(for: ask)[0])
    }

    /// A decision given directly (notification actions); an `*Always` without a menu choice uses the most specific scope.
    public func answer(_ ask: AskRequest, _ decision: AskDecision) async {
        await send(ask, decision: decision, scope: rememberedScope(for: ask) ?? scopes(for: ask)[0])
    }

    private func send(_ ask: AskRequest, decision: AskDecision, scope: AskScope) async {
        guard !answering.contains(ask.id) else { return }
        answering.insert(ask.id)
        defer { answering.remove(ask.id) }
        do {
            try await netd.answer(AskAnswer(id: ask.id, decision: decision, scope: scope))
            remembered[ask.id] = nil
            let saved = decision == .allowAlways || decision == .denyAlways ? " (rule \(target(for: ask, scope: scope)))" : ""
            message = .success("\(decision.displayName): \(ask.host)\(saved)")
        } catch {
            message = UserMessage(error: error, action: "Answer the request for \(ask.host)")
        }
    }
}

// MARK: - Presentation

/// One entry of the panel's menu: just once, or a rule for one scope with its target.
public struct AskRememberOption: Sendable, Equatable, Identifiable {
    /// `nil` for just once.
    public var scope: AskScope?
    public var label: String
    /// Small monospaced second line.
    public var target: String

    public var id: String { scope?.rawValue ?? "once" }

    public init(scope: AskScope?, label: String, target: String) {
        self.scope = scope
        self.label = label
        self.target = target
    }

    public static let justOnce = AskRememberOption(scope: nil, label: "Just once", target: "this request only")
}

/// The strip above the tiles.
public struct AskVerdict: Sendable, Equatable {
    public var level: AskAssessment.Level
    public var title: String
    public var symbolName: String
    public var tint: Tint
    /// Right-aligned hint, only when something speaks against the destination.
    public var hint: String?
    /// Tooltip with the points.
    public var help: String

    public init(assessment: AskAssessment) {
        level = assessment.level
        switch assessment.level {
        case .normal:
            title = "Looks normal"
            symbolName = "checkmark.shield"
            tint = .green
        case .unusual:
            title = "Unusual"
            symbolName = "exclamationmark.shield"
            tint = .orange
        case .suspicious:
            title = "Suspicious"
            symbolName = "xmark.shield"
            tint = .red
        }
        let against = assessment.signals.contains { $0.effect == .minus }
        hint = assessment.level != .normal && against ? "Tap a red tile for the reason" : nil
        help = "Score \(assessment.score): unusual from \(AskAssessment.unusualFrom), suspicious from \(AskAssessment.suspiciousFrom)"
    }
}

/// One detail tile: an SF Symbol and two short lines; the sentence appears below the grid when it is tapped.
public struct AskTile: Sendable, Equatable, Identifiable {
    public enum Tone: String, Sendable {
        /// Green symbol: speaks for the destination.
        case plus
        /// Red background: speaks against it.
        case minus
        case neutral
    }

    public var kind: AskDetailKind
    public var symbolName: String
    public var title: String
    public var subtitle: String
    public var tone: Tone
    public var explanation: String

    public var id: AskDetailKind { kind }

    public init(kind: AskDetailKind, symbolName: String, title: String, subtitle: String, tone: Tone, explanation: String) {
        self.kind = kind
        self.symbolName = symbolName
        self.title = title
        self.subtitle = subtitle
        self.tone = tone
        self.explanation = explanation
    }
}

/// The program's signature as a seal on its icon.
public struct AskSeal: Sendable, Equatable {
    public var symbolName: String
    public var tint: Tint
    public var help: String
}

/// Everything the panel lays out. Missing details leave their tile out; without any details only the header,
/// the ring and the buttons remain.
public struct AskPresentation: Sendable, Equatable {
    public var process: String
    /// The file whose icon the header shows: the enclosing `.app` bundle, else the executable; `nil` for a generic symbol.
    public var iconPath: String?
    public var seal: AskSeal?
    /// `185.142.236.41:8947`, `registry.npmjs.org:443`, the name alone for a DNS lookup.
    public var destination: String
    /// Small line below: the address when the destination is a name, and the reverse name.
    public var subtitle: String?
    public var verdict: AskVerdict?
    /// At most six, in the order name, port, network, encryption, history, program.
    public var tiles: [AskTile]
    public var options: [AskRememberOption]
    public var prefersDeny: Bool

    public init(ask: AskRequest, at date: Date, options: [AskRememberOption], prefersDeny: Bool) {
        let details = ask.details
        let path = details?.program?.path
        process = ask.process ?? path.map { ($0 as NSString).lastPathComponent } ?? "Unknown program"
        iconPath = path.map(AskFormat.iconPath)
        seal = details?.program.map(AskFormat.seal)
        destination = AskFormat.destination(ask)
        subtitle = details.flatMap { AskFormat.subtitle(host: ask.host, details: $0) }
        verdict = details?.assessment.map(AskVerdict.init(assessment:))
        tiles = details.map { AskFormat.tiles(for: ask, details: $0, at: date) } ?? []
        self.options = options
        self.prefersDeny = prefersDeny
    }
}

/// Tile, header and menu text for an ask; the panel only places it.
public enum AskFormat {
    /// `host:port` without spaces, IPv6 addresses in brackets; the host alone without a port.
    public static func endpoint(_ host: String, _ port: UInt16?) -> String {
        let shown = host.contains(":") && !host.hasPrefix("[") ? "[\(host)]" : host
        return port.map { "\(shown):\($0)" } ?? shown
    }

    /// The header line: what the program connects to.
    public static func destination(_ ask: AskRequest) -> String {
        endpoint(ask.host, ask.port)
    }

    /// The reverse name and, when the destination is a name, the address it resolved to. An empty reverse name
    /// (asked, nothing found) shows nothing here; its signal says so.
    public static func subtitle(host: String, details: AskDetails) -> String? {
        let normalized = HostName.normalize(host)
        var parts: [String] = []
        if let address = details.address, HostName.normalize(address) != normalized { parts.append(address) }
        if let reverse = details.reverseName, !details.reverseLookupFoundNothing, HostName.normalize(reverse) != normalized {
            parts.append(reverse)
        }
        return parts.isEmpty ? nil : parts.joined(separator: " · ")
    }

    /// Whether a "Whole domain" rule makes sense: a name with a registrable domain, not an address.
    public static func hasDomain(_ host: String) -> Bool {
        let normalized = HostName.normalize(host)
        return !HostName.isIPLiteral(normalized) && RegistrableDomain.rulePattern(for: normalized, scope: .domain).hasPrefix("*.")
    }

    /// Menu labels, by address or by name; for a non-web port the wider choice says "any port".
    public static func scopeLabel(_ scope: AskScope, host: String, port: UInt16?) -> String {
        let address = HostName.isIPLiteral(HostName.normalize(host))
        let otherPort = AskScope.options(port: port, hasDomain: false).contains(.hostAndPort)
        switch scope {
        case .host: return (address ? "This address" : "This host") + (otherPort ? ", any port" : "")
        case .domain: return "Whole domain"
        case .hostAndPort: return address ? "This address and port" : "This host and port"
        }
    }

    /// `/Applications/Foo.app/Contents/MacOS/foo` becomes the bundle; any other path stays.
    public static func iconPath(_ executable: String) -> String {
        guard let range = executable.range(of: ".app/") else { return executable }
        return String(executable[..<range.lowerBound]) + ".app"
    }

    public static func seal(_ program: AskProgram) -> AskSeal {
        switch (program.signature, program.inTemporaryFolder) {
        case (.apple, false): AskSeal(symbolName: "checkmark.seal.fill", tint: .blue, help: "Signed by Apple")
        case (.developer(let team), false): AskSeal(symbolName: "checkmark.seal.fill", tint: .blue, help: "Signed" + (team.map { " (team \($0))" } ?? ""))
        case (.unknown, false): AskSeal(symbolName: "questionmark.circle.fill", tint: .gray, help: "Signature not checked")
        case (_, true): AskSeal(symbolName: "exclamationmark.circle.fill", tint: .orange, help: "Runs from a temporary folder")
        case (.adHoc, false): AskSeal(symbolName: "exclamationmark.circle.fill", tint: .orange, help: "Signed ad hoc, without an identity")
        case (.unsigned, false): AskSeal(symbolName: "exclamationmark.circle.fill", tint: .orange, help: "Not signed")
        }
    }

    // MARK: Tiles

    public static func tiles(for ask: AskRequest, details: AskDetails, at date: Date) -> [AskTile] {
        let signals = details.assessment?.signals ?? []
        func tile(_ kind: AskDetailKind, _ symbol: String, _ title: String, _ subtitle: String, _ fallback: String) -> AskTile {
            // The reverse name has no tile; its signals belong to the name.
            let own = signals.filter { $0.detail == kind || (kind == .name && $0.detail == .reverseName) }
            let tone: AskTile.Tone = own.contains { $0.effect == .minus } ? .minus : own.contains { $0.effect == .plus } ? .plus : .neutral
            let text = own.map(\.text).joined(separator: " ")
            return AskTile(kind: kind, symbolName: symbol, title: title, subtitle: subtitle, tone: tone, explanation: text.isEmpty ? fallback : text)
        }

        var tiles: [AskTile] = []
        if let name = details.name {
            let (title, subtitle, fallback) = nameLines(name, ask: ask)
            tiles.append(tile(.name, "globe", title, subtitle, fallback))
        }
        if let service = details.service {
            tiles.append(tile(.port, "number", "\(service.port)", service.name ?? "unknown",
                              service.name.map { "Port \(service.port) is \($0)." } ?? "Port \(service.port) is in no list of known services."))
        }
        if let network = details.network {
            let (title, subtitle, fallback) = networkLines(network)
            tiles.append(tile(.network, "server.rack", title, subtitle, fallback))
        }
        if let encryption = details.encryption {
            let (symbol, title, subtitle, fallback) = encryptionLines(encryption, ask: ask, service: details.service)
            tiles.append(tile(.encryption, symbol, title, subtitle, fallback))
        }
        if let history = details.history {
            let (title, subtitle, fallback) = historyLines(history, at: date)
            tiles.append(tile(.history, "clock", title, subtitle, fallback))
        }
        if let program = details.program {
            let (symbol, title, subtitle, fallback) = programLines(program)
            tiles.append(tile(.program, symbol, title, subtitle, fallback))
        }
        return tiles
    }

    static func nameLines(_ name: AskName, ask: AskRequest) -> (String, String, String) {
        guard let host = name.name, name.source != .none else {
            return ("No name", "IP only", "The program never looked up a name for this address.")
        }
        let domain = RegistrableDomain.of(host)
        let subtitle: String = switch name.source {
        case .dns: ask.kind == .dns ? "asked for" : "from DNS"
        case .tls: "from TLS"
        case .http: "from HTTP"
        case .none: "IP only"
        }
        let via: String = switch name.source {
        case .dns: ask.kind == .dns ? "The lookup is for \(host)." : "The name \(host) came from a DNS answer."
        case .tls: "The name \(host) came from TLS."
        case .http: "The name \(host) came from the HTTP request."
        case .none: ""
        }
        return (domain, subtitle, via)
    }

    static func networkLines(_ network: AskNetwork) -> (String, String, String) {
        let owner = network.owner.map(shortOwner)
        let kind: String = switch network.kind {
        case .knownService: "known service"
        case .cdn: "CDN"
        case .hosting: "hosting"
        case .other: network.asn.map { "AS\($0)" } ?? "network"
        }
        let title = owner ?? (network.kind == .hosting ? "Hosting" : network.asn.map { "AS\($0)" } ?? "Unknown")
        var subtitle = [network.country, kind].compactMap { $0 }.joined(separator: " · ")
        if network.source == .online { subtitle += " · RDAP" }
        let asn = network.asn.map { " (AS\($0))" } ?? ""
        let place = network.country.map { " in \(countryName($0))" } ?? ""
        let what: String = switch network.kind {
        case .knownService: "a well-known service"
        case .cdn: "a content delivery network many services share"
        case .hosting: "rented servers"
        case .other: "a network"
        }
        return (title, subtitle, "\(network.owner ?? "Unknown owner")\(asn): \(what)\(place).")
    }

    static func encryptionLines(_ encryption: AskEncryption, ask: AskRequest, service: KnownService?) -> (String, String, String, String) {
        switch encryption {
        case .tls:
            return ("lock", "Encrypted", "TLS", "The connection uses TLS.")
        case .plain:
            let dns = ask.kind == .dns || service?.port == 53
            return ("lock.open", "Plain", dns ? "DNS" : "unencrypted",
                    dns ? "Classic DNS is unencrypted." : "netd saw plain text; anyone on the path can read it.")
        case .unknown:
            return ("lock.slash", "Unknown", "no TLS seen", "netd cannot tell what protocol this is.")
        }
    }

    static func historyLines(_ history: AskHistory, at date: Date) -> (String, String, String) {
        guard history.allowed + history.denied > 0 else {
            return ("New", "first time", "The sandbox has not reached this destination before.")
        }
        let title = history.allowed > 0 ? "\(history.allowed)×" : "\(history.denied)× denied"
        let ago = history.lastSeen.map { Format.ago(Int(date.timeIntervalSince($0))) }
        let subtitle = history.allowed > 0 && history.denied > 0 ? "\(history.denied)× denied" : ago ?? "before"
        var sentence = history.allowed > 0 ? "Allowed \(Format.count(history.allowed, "time")) before" : "Denied \(Format.count(history.denied, "time")) before"
        if history.allowed > 0 && history.denied > 0 { sentence += ", denied \(Format.count(history.denied, "time"))" }
        if let ago { sentence += ", last \(ago)" }
        return (title, subtitle, sentence + ".")
    }

    static func programLines(_ program: AskProgram) -> (String, String, String, String) {
        let signature: (title: String, short: String, good: Bool) = switch program.signature {
        case .apple: ("Apple", "Apple", true)
        case .developer(let team): ("Signed", team ?? "developer", true)
        case .adHoc: ("Ad hoc", "ad hoc", false)
        case .unsigned: ("Unsigned", "unsigned", false)
        case .unknown: ("Unknown", "not checked", false)
        }
        let path = program.path ?? "The program"
        if program.inTemporaryFolder {
            return ("exclamationmark.triangle", "Temp folder", signature.short, "\(path) runs from a temporary folder.")
        }
        let subtitle: String = switch program.signature {
        case .apple: program.path.map { $0.hasPrefix("/System/") || $0.hasPrefix("/usr/") } == true ? "system" : "signed"
        case .developer(let team): team ?? "developer"
        case .adHoc: "no identity"
        case .unsigned: "no signature"
        case .unknown: "not checked"
        }
        let sentence: String = switch program.signature {
        case .apple: "\(path), signed by Apple."
        case .developer(let team): "\(path), validly signed" + (team.map { " (team \($0))" } ?? "") + "."
        case .adHoc: "\(path) is signed ad hoc, without a developer identity."
        case .unsigned: "\(path) is not signed."
        case .unknown: "netd could not check the signature of \(path)."
        }
        return (signature.good ? "checkmark.seal" : "exclamationmark.triangle", signature.title, subtitle, sentence)
    }

    /// `GOOGLE - Google LLC` becomes `Google`, `CLOUDFLARENET` stays (iptoasn and RDAP owner strings).
    public static func shortOwner(_ owner: String) -> String {
        var text = owner
        if let range = text.range(of: " - ") { text = String(text[range.upperBound...]) }
        if let comma = text.firstIndex(of: ",") { text = String(text[..<comma]) }
        let suffixes = [" Inc.", " Inc", " LLC", " L.L.C.", " Ltd.", " Ltd", " GmbH", " AG", " B.V.", " S.A.", " SAS", " Corporation", " Corp."]
        for suffix in suffixes where text.hasSuffix(suffix) {
            text = String(text.dropLast(suffix.count))
        }
        let trimmed = text.trimmingCharacters(in: .whitespaces)
        return trimmed.isEmpty ? owner : trimmed
    }

    /// `RU` becomes `Russia` where the system knows the code, else stays as given.
    public static func countryName(_ code: String) -> String {
        Locale(identifier: "en_US").localizedString(forRegionCode: code) ?? code
    }
}
