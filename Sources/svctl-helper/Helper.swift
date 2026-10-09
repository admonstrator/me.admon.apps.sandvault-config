import ArgumentParser
import Foundation
#if canImport(Darwin)
import Darwin
#elseif canImport(Glibc)
import Glibc
#endif
import SandvaultCore
import SandvaultEnforce

/// Root helper entry point. Runs only through sudo; see HelperProtocol.swift for the rules.
/// Typed state arrives as `AppliedState` JSON on stdin; the result is one `HelperResult` on stdout; exit 0 iff ok.
@main
struct Helper: AsyncParsableCommand {
    static let configuration = CommandConfiguration(
        commandName: "svctl-helper",
        abstract: "Privileged helper for Sandvault Config (run through sudo).",
        discussion: "Subcommands: \(HelperSubcommand.allCases.map(\.rawValue).joined(separator: ", ")).",
        version: BundleIdentity.version
    )

    @Argument(help: "The subcommand to run.")
    var subcommand: String

    @Flag(name: .long, help: "Print the result as one JSON line.")
    var json = false

    @Option(name: .long, help: "install/uninstall only: the host user (default: SUDO_USER).")
    var user: String?

    @Option(name: .long, help: "install only: the svctl-helper binary to copy (default: this binary).")
    var source: String?

    @Flag(name: .customLong("release-panic"), help: "pf-apply only: a user action that may leave the panic state.")
    var releasePanic = false

    func run() async throws {
        let result = await execute()
        if json {
            FileHandle.standardOutput.write((try? JSONCoding.lineEncoder.encode(result)) ?? Data())
            FileHandle.standardOutput.write(Data("\n".utf8))
        } else {
            print(result.message)
            for key in result.details.keys.sorted() { print("  \(key): \(result.details[key] ?? "")") }
        }
        if !result.ok { throw ExitCode.failure }
    }

    func execute() async -> HelperResult {
        guard let command = HelperSubcommand(rawValue: subcommand) else {
            return HelperResult(ok: false, message: "unknown subcommand '\(subcommand)'")
        }
        #if os(macOS)
        guard geteuid() == 0 else { return HelperResult(ok: false, message: "svctl-helper must run as root (through sudo)") }
        let context = HelperContext(
            runner: ProcessCommandRunner(),
            processEnvironment: ProcessInfo.processInfo.environment,
            executablePath: Bundle.main.executableURL?.resolvingSymlinksInPath().path
        )
        let input = [.profileApply, .pfApply, .panic].contains(command) ? Self.readStandardInput() : nil
        let options = HelperOptions(user: user, source: source, releasePanic: releasePanic)
        return await PrivilegedHelper(context: context).run(command, options: options, input: input)
        #else
        return HelperResult(ok: false, message: SandvaultError.unsupportedPlatform("svctl-helper runs on macOS only (\(command.rawValue))").description)
        #endif
    }

    /// Reads at most one byte more than the limit, so oversized input is rejected instead of truncated.
    /// A terminal on stdin means no input (`sudo svctl-helper panic` typed by hand).
    static func readStandardInput() -> Data? {
        guard isatty(STDIN_FILENO) == 0 else { return nil }
        var data = Data()
        while data.count <= PrivilegedHelper.maxInputBytes,
              let chunk = try? FileHandle.standardInput.read(upToCount: 64 * 1024), !chunk.isEmpty {
            data.append(chunk)
        }
        return data
    }
}
