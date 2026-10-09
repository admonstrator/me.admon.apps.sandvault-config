import ArgumentParser
import Foundation
#if canImport(Darwin)
import Darwin
#elseif canImport(Glibc)
import Glibc
#endif
import SandvaultCore
import SandvaultEnforce
import SandvaultObserve

/// Shared pieces of the enforce commands (rules, firewall, panic, helper).
enum EnforceCLI {
    static func requireMacOS(_ what: String) throws {
        guard EnforcePlatform.isMacOS else {
            throw SandvaultError.unsupportedPlatform("\(what) needs macOS (sandbox-exec, pf and the root helper); preview, diff and list work here")
        }
    }

    /// Asks on the terminal unless `--yes`; refuses to guess when there is no terminal or JSON output is wanted.
    static func confirm(_ question: String, yes: Bool, json: Bool) throws -> Bool {
        if yes { return true }
        if json { throw ValidationError("--json needs --yes for commands that change the system") }
        guard isatty(STDIN_FILENO) != 0 else { throw ValidationError("stdin is not a terminal; pass --yes to confirm") }
        FileHandle.standardOutput.write(Data("\(question) [y/N] ".utf8))
        let answer = readLine()?.trimmingCharacters(in: .whitespaces).lowercased()
        return answer == "y" || answer == "yes"
    }

    static func applier(_ global: GlobalOptions) -> HelperPolicyApplier {
        HelperPolicyApplier(runner: global.runner)
    }

    /// Prints a helper result and fails the command when it is not ok.
    static func report(_ result: HelperResult, json: Bool) throws {
        if json {
            try Output.json(result)
        } else {
            Output.line(result.message)
        }
        if !result.ok { throw ExitCode.failure }
    }

    /// The sandbox user's uid: `--uid` when given, else dscl / id.
    static func uid(_ override: UInt32?, _ global: GlobalOptions) async throws -> UInt32 {
        if let override {
            try SandboxAccount.validate(uid: override)
            return override
        }
        do {
            return try await SandboxAccount.resolveUID(environment: global.environment, runner: global.runner)
        } catch SandvaultError.notInstalled(let what) {
            throw SandvaultError.notInstalled("\(what); pass --uid <n> to preview without the account")
        }
    }

    /// Loopback ports for `LocalhostPolicy.sandboxAndHelpers`; empty (with a note on stderr) when unavailable.
    static func dynamicLocalPorts(_ global: GlobalOptions) async -> [UInt16] {
        do {
            return try await Observe.makeLocalPortSource(environment: global.environment, runner: global.runner).allowedLocalPorts()
        } catch {
            FileHandle.standardError.write(Data("note: sandbox listening ports unknown (\(error)); none allowed on loopback\n".utf8))
            return []
        }
    }

    static func shortID(_ id: UUID) -> String {
        String(id.uuidString.lowercased().prefix(8))
    }
}

// Argument types, nested so they cannot collide with other areas' names in the svctl module.
extension EnforceCLI {
    enum AccessArgument: String, ExpressibleByArgument, CaseIterable {
        case read, write, rw

        var access: FileAccess {
            switch self {
            case .read: .read
            case .write: .write
            case .rw: .readWrite
            }
        }
    }

    enum EffectArgument: String, ExpressibleByArgument, CaseIterable {
        case allow, deny

        var effect: RuleEffect { self == .allow ? .allow : .deny }
    }

    enum PresetArgument: String, ExpressibleByArgument, CaseIterable {
        case standard, hardened

        var preset: SandboxPreset { self == .standard ? .standard : .hardened }
    }

    enum ModeArgument: String, ExpressibleByArgument, CaseIterable {
        case off, open
        case proxyOnly = "proxy-only"
        case blocked

        var mode: FirewallMode {
            switch self {
            case .off: .off
            case .open: .open
            case .proxyOnly: .proxyOnly
            case .blocked: .blocked
            }
        }
    }

    enum SwitchArgument: String, ExpressibleByArgument, CaseIterable {
        case on, off
    }

    enum LocalhostArgument: String, ExpressibleByArgument, CaseIterable {
        case sandboxAndHelpers = "sandbox-and-helpers"
        case allowAll = "allow-all"
        case blockAll = "block-all"

        var policy: LocalhostPolicy {
            switch self {
            case .sandboxAndHelpers: .sandboxAndHelpers
            case .allowAll: .allowAll
            case .blockAll: .blockAll
            }
        }
    }

    enum ProtoArgument: String, ExpressibleByArgument, CaseIterable {
        case tcp, udp

        var proto: TransportProtocol { self == .tcp ? .tcp : .udp }
    }

    enum MatchFlag: String, EnumerableFlag {
        case subpath, literal, prefix

        var match: PathMatch {
            switch self {
            case .subpath: .subpath
            case .literal: .literal
            case .prefix: .prefix
            }
        }

        static func help(for value: MatchFlag) -> ArgumentHelp? {
            switch value {
            case .subpath: "Match the directory tree (default)."
            case .literal: "Match exactly this path."
            case .prefix: "Match every path starting with this string."
            }
        }
    }
}
