import Foundation
import SandvaultCore

/// What the helper remembers between runs, root-owned in `AppPaths.rootStateDir`.
/// Mode 0644: it holds hashes and the pf token only, so the host user can read it for drift detection.
public struct HelperRecord: Codable, Sendable, Equatable {
    /// Host user whose firewall state is persisted (used by `restore` and to keep one owner of the shared anchor).
    public var hostUser: String?
    public var sandboxUID: UInt32?
    public var pfToken: String?
    /// Set by `panic`; `pf-apply` refuses to leave `blocked` until a caller passes `--release-panic`.
    public var panicActive: Bool?
    /// Mode of the anchor as last loaded (or flushed).
    public var firewallMode: FirewallMode?
    public var helperSHA256: String?
    public var sudoersSHA256: String?
    public var svSudoersSHA256: String?
    /// sv's part of the profile (text outside our block) at the last profile-apply or reset.
    public var svPartSHA256: String?
    public var profileSHA256: String?
    /// The block body we wrote; `nil` when we wrote none.
    public var profileBlockSHA256: String?
    /// Generated anchor text at the last pf-apply (idempotence).
    public var anchorTextSHA256: String?
    /// `pfctl -a <anchor> -sn` plus `-sr` output after the last pf-apply (tamper detection).
    public var anchorSHA256: String?
    public var profileAppliedAt: Date?
    public var firewallAppliedAt: Date?

    public init() {}
}

/// Files in the root state directory. Paths are passed in, so tests run against a temporary root.
public enum RootState {
    public static let recordName = "helper-record.json"
    public static let stateName = "applied-state.json"

    public static func recordPath(in directory: String) -> String { "\(directory)/\(recordName)" }
    public static func statePath(in directory: String) -> String { "\(directory)/\(stateName)" }
    public static func backupPath(in directory: String, svPartSHA256: String) -> String {
        "\(directory)/profile-backup-\(svPartSHA256.prefix(16)).sb"
    }

    /// The record, or `nil` when it is missing or unreadable (callers treat that as "never applied").
    public static func readRecord(at path: String) -> HelperRecord? {
        guard let data = FileManager.default.contents(atPath: path) else { return nil }
        return try? JSONCoding.decoder.decode(HelperRecord.self, from: data)
    }
}
