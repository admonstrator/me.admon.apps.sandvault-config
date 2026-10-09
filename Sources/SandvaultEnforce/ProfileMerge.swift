import Foundation
import SandvaultCore

/// How sv's profile relates to what the current configuration generates.
public enum ProfileDrift: String, Codable, Sendable, CaseIterable {
    /// The block matches the configuration (or none is needed and none is present).
    case inSync
    /// The configuration needs a block but the profile has none (typically after `sv --rebuild`).
    case missing
    /// A block is present but differs from what the configuration generates.
    case outdated
    /// A block is present although the configuration needs none.
    case unexpected
    /// sv's profile does not exist (sandvault not installed, or not on macOS).
    case profileMissing
}

/// Pure text operations on sv's profile; the managed block is `ManagedBlock.sandboxProfile`.
public enum ProfileMerge {
    static let block = ManagedBlock.sandboxProfile

    /// The profile with the block for `body` (or without any block when `body` is `nil`).
    public static func candidate(profile: String, body: String?) -> String {
        guard let body else { return block.remove(from: profile) }
        return block.replace(in: profile, with: body)
    }

    public static func drift(profile: String?, body: String?) -> ProfileDrift {
        guard let profile else { return .profileMissing }
        switch (block.extract(from: profile), body) {
        case (nil, nil): return .inSync
        case (nil, _?): return .missing
        case (_?, nil): return .unexpected
        case let (present?, expected?): return present == expected ? .inSync : .outdated
        }
    }

    /// sv's own text: the profile without our block.
    public static func svPart(of profile: String) -> String {
        block.remove(from: profile)
    }

    public static func svPartSHA256(of profile: String) -> String {
        Fingerprint.sha256(svPart(of: profile))
    }
}

/// Everything the CLI and the app show before `rules apply`: current text, candidate, diff and drift.
public struct ProfilePlan: Codable, Sendable, Equatable {
    public var profilePath: String
    /// `nil` when the profile does not exist.
    public var current: String?
    public var candidate: String?
    /// The generated block body; `nil` when the configuration needs no block.
    public var body: String?
    public var drift: ProfileDrift
    public var diff: [DiffLine]
    /// SHA-256 of sv's part of the profile as it is now.
    public var svPartSHA256: String?
    /// SHA-256 of sv's part at our last apply (from the helper's root-owned record), when known.
    public var appliedSvPartSHA256: String?

    /// sv rewrote its part (e.g. `sv --rebuild`) since our last apply.
    public var svPartChanged: Bool {
        guard let svPartSHA256, let appliedSvPartSHA256 else { return false }
        return svPartSHA256 != appliedSvPartSHA256
    }

    public var hasChanges: Bool { current != nil && current != candidate }

    /// `diff -u` text between the current profile and the candidate.
    public var unifiedDiff: String {
        guard let current, let candidate else { return "" }
        return LineDiff.unified(old: current, new: candidate, oldName: profilePath, newName: "\(profilePath) (candidate)")
    }
}

/// Reads sv's profile (mode 0444, readable without root) and the helper's record to build a `ProfilePlan`.
public struct ProfileInspector: Sendable {
    public var profilePath: String
    public var recordPath: String

    public init(profilePath: String, recordPath: String = RootState.recordPath(in: AppPaths.rootStateDir)) {
        self.profilePath = profilePath
        self.recordPath = recordPath
    }

    public init(environment: SandvaultEnvironment) {
        self.init(profilePath: environment.sandboxProfilePath)
    }

    /// Throws `invalidInput` when a configured rule fails validation, or `io` when the profile cannot be read.
    public func plan(for settings: SandboxSettings) throws -> ProfilePlan {
        let body = try SBPLGenerator.block(for: settings)
        let current = try readProfile()
        let candidate = current.map { ProfileMerge.candidate(profile: $0, body: body) }
        let diff = current.flatMap { current in candidate.map { LineDiff.lines(old: current, new: $0) } } ?? []
        return ProfilePlan(
            profilePath: profilePath,
            current: current,
            candidate: candidate,
            body: body,
            drift: ProfileMerge.drift(profile: current, body: body),
            diff: diff,
            svPartSHA256: current.map(ProfileMerge.svPartSHA256(of:)),
            appliedSvPartSHA256: RootState.readRecord(at: recordPath)?.svPartSHA256
        )
    }

    func readProfile() throws -> String? {
        guard FileManager.default.fileExists(atPath: profilePath) else { return nil }
        do {
            return try String(contentsOfFile: profilePath, encoding: .utf8)
        } catch {
            throw SandvaultError.io("cannot read \(profilePath): \(error)")
        }
    }
}
