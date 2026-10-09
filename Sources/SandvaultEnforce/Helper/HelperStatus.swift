import Foundation
import SandvaultCore

/// Typed view of `svctl-helper status`: current hashes and what changed since the last apply.
/// Travels as `HelperResult.details` (string values); `init(details:)` reads it back on the unprivileged side.
public struct HelperStatus: Codable, Sendable, Equatable {
    public var hostUser: String?
    /// Anchor mode as last loaded by the helper.
    public var firewallMode: FirewallMode?
    public var panicActive = false
    /// `nil` when pfctl could not be asked.
    public var pfEnabled: Bool?
    public var pfTokenHeld = false

    public var helperSHA256: String?
    public var sudoersSHA256: String?
    public var svSudoersSHA256: String?
    public var profileSHA256: String?
    public var profileBlockSHA256: String?
    public var svPartSHA256: String?
    public var anchorSHA256: String?

    /// Helper binary differs from the installed one (only root can write it).
    public var helperChanged = false
    /// Our sudoers rule differs from what install wrote.
    public var sudoersChanged = false
    /// sv rewrote its sudoers file (informational).
    public var svSudoersChanged = false
    /// A managed block is present but is not the one we wrote.
    public var profileBlockChanged = false
    /// The block we wrote is gone (typically `sv --rebuild`).
    public var profileBlockMissing = false
    /// sv rewrote its part of the profile since our last apply.
    public var svPartChanged = false
    /// The loaded anchor differs from what we loaded (edited, flushed, or not restored after a reboot).
    public var anchorChanged = false

    public init() {}

    /// Changes only root could have made to things we own.
    public var tampered: Bool { helperChanged || sudoersChanged || profileBlockChanged || anchorChanged }

    public var tamperFindings: [String] {
        [
            (helperChanged, "helper binary changed"),
            (sudoersChanged, "helper sudoers rule changed"),
            (profileBlockChanged, "managed profile block edited"),
            (anchorChanged, "pf anchor differs from the last apply"),
        ].filter(\.0).map(\.1)
    }

    public var summary: String {
        tampered ? "integrity: " + tamperFindings.joined(separator: ", ") : "integrity ok"
    }

    // MARK: - details encoding

    public var details: [String: String] {
        var details: [String: String] = [:]
        let strings: [(String, String?)] = [
            ("hostUser", hostUser), ("firewallMode", firewallMode?.rawValue),
            ("helperSHA256", helperSHA256), ("sudoersSHA256", sudoersSHA256), ("svSudoersSHA256", svSudoersSHA256),
            ("profileSHA256", profileSHA256), ("profileBlockSHA256", profileBlockSHA256), ("svPartSHA256", svPartSHA256),
            ("anchorSHA256", anchorSHA256), ("pfEnabled", pfEnabled.map { String($0) }),
        ]
        for (key, value) in strings { details[key] = value }
        for (key, flag) in flags { details[key] = String(flag) }
        details["tampered"] = String(tampered)
        return details
    }

    public init(details: [String: String]) {
        hostUser = details["hostUser"]
        firewallMode = details["firewallMode"].flatMap(FirewallMode.init(rawValue:))
        pfEnabled = details["pfEnabled"].flatMap(Bool.init)
        helperSHA256 = details["helperSHA256"]
        sudoersSHA256 = details["sudoersSHA256"]
        svSudoersSHA256 = details["svSudoersSHA256"]
        profileSHA256 = details["profileSHA256"]
        profileBlockSHA256 = details["profileBlockSHA256"]
        svPartSHA256 = details["svPartSHA256"]
        anchorSHA256 = details["anchorSHA256"]
        func flag(_ key: String) -> Bool { details[key] == "true" }
        panicActive = flag("panicActive")
        pfTokenHeld = flag("pfTokenHeld")
        helperChanged = flag("helperChanged")
        sudoersChanged = flag("sudoersChanged")
        svSudoersChanged = flag("svSudoersChanged")
        profileBlockChanged = flag("profileBlockChanged")
        profileBlockMissing = flag("profileBlockMissing")
        svPartChanged = flag("svPartChanged")
        anchorChanged = flag("anchorChanged")
    }

    private var flags: [(String, Bool)] {
        [
            ("panicActive", panicActive), ("pfTokenHeld", pfTokenHeld), ("helperChanged", helperChanged),
            ("sudoersChanged", sudoersChanged), ("svSudoersChanged", svSudoersChanged),
            ("profileBlockChanged", profileBlockChanged), ("profileBlockMissing", profileBlockMissing),
            ("svPartChanged", svPartChanged), ("anchorChanged", anchorChanged),
        ]
    }
}
