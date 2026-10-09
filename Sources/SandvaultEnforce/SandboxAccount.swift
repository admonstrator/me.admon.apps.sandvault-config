import Foundation
import SandvaultCore

/// Numeric uid of the sandbox user; pf rules always name the uid, never the account name.
public enum SandboxAccount {
    public static let dsclPath = "/usr/bin/dscl"
    public static let idPath = "/usr/bin/id"
    /// sv allocates ids from 600 up (`SV_MIN_ID`); below 500 are macOS service accounts, which must never be matched.
    public static let minimumUID: UInt32 = 500

    /// `dscl . -read /Users/<sandbox> UniqueID`, falling back to `id -u <sandbox>`.
    public static func resolveUID(environment: SandvaultEnvironment, runner: CommandRunner) async throws -> UInt32 {
        let user = environment.sandvaultUser
        if let result = try? await runner.run(CommandInvocation(dsclPath, [".", "-read", "/Users/\(user)", "UniqueID"])),
           result.succeeded, let uid = parseDsclUniqueID(result.stdoutString) {
            try validate(uid: uid)
            return uid
        }
        let result: CommandResult
        do {
            result = try await runner.run(CommandInvocation(idPath, ["-u", user]))
        } catch {
            throw SandvaultError.notInstalled("cannot resolve the uid of \(user): \(error)")
        }
        guard result.succeeded, let uid = parseID(result.stdoutString) else {
            throw SandvaultError.notInstalled("account \(user) (neither dscl nor id knows its uid)")
        }
        try validate(uid: uid)
        return uid
    }

    /// Parses `UniqueID: 601` (or the two-line form `UniqueID:\n 601` dscl uses for long values).
    public static func parseDsclUniqueID(_ output: String) -> UInt32? {
        let lines = output.split(whereSeparator: \.isNewline).map { $0.trimmingCharacters(in: .whitespaces) }
        guard let index = lines.firstIndex(where: { $0.hasPrefix("UniqueID:") }) else { return nil }
        let inline = lines[index].dropFirst("UniqueID:".count).trimmingCharacters(in: .whitespaces)
        let value = inline.isEmpty && index + 1 < lines.count ? lines[index + 1] : inline
        return UInt32(value)
    }

    public static func parseID(_ output: String) -> UInt32? {
        UInt32(output.trimmingCharacters(in: .whitespacesAndNewlines))
    }

    public static func validate(uid: UInt32) throws {
        guard uid >= minimumUID, uid < 0x7FFF_FFFF else {
            throw SandvaultError.invalidInput("uid \(uid) is not a plausible sandbox account (expected \(minimumUID) or above)")
        }
    }
}
