import Foundation
import SandvaultCore
#if canImport(Darwin)
import Darwin
#elseif canImport(Glibc)
import Glibc
#endif

/// The LaunchAgent that keeps sandvault-netd running for the host user
/// (`~/Library/LaunchAgents/<AppPaths.netdLabel>.plist`, `launchctl bootstrap|bootout gui/<uid>`).
public struct NetdLaunchAgent: Sendable {
    public struct Status: Codable, Sendable, Equatable {
        public var installed: Bool
        public var loaded: Bool
        /// launchd's state (`running`, `waiting`, ...), when loaded.
        public var state: String?
        public var pid: Int32?
        public var lastExitCode: String?
        public var plistPath: String
        public var executable: String?
    }

    public var paths: AppPaths
    public var runner: CommandRunner
    public var uid: UInt32
    /// launchd exists only on macOS; tests override this.
    public var platformSupported: Bool

    public init(paths: AppPaths, runner: CommandRunner, uid: UInt32 = getuid()) {
        self.paths = paths
        self.runner = runner
        self.uid = uid
        #if canImport(Darwin)
        platformSupported = true
        #else
        platformSupported = false
        #endif
    }

    public static let launchctl = "/bin/launchctl"

    public var plistPath: String { "\(paths.environment.hostHome)/Library/LaunchAgents/\(AppPaths.netdLabel).plist" }
    public var domain: String { "gui/\(uid)" }
    public var service: String { "\(domain)/\(AppPaths.netdLabel)" }
    public var logPath: String { "\(paths.logDir)/netd.log" }

    /// The property list: run `<executable> run`, keep it alive, log to `logs/netd.log`.
    public static func propertyList(executable: String, paths: AppPaths) throws -> Data {
        let plist: [String: Any] = [
            "Label": AppPaths.netdLabel,
            "ProgramArguments": [executable, "run"],
            "RunAtLoad": true,
            "KeepAlive": true,
            "ProcessType": "Background",
            "StandardOutPath": "\(paths.logDir)/netd.log",
            "StandardErrorPath": "\(paths.logDir)/netd.log",
        ]
        return try PropertyListSerialization.data(fromPropertyList: plist, format: .xml, options: 0)
    }

    public func install(executable: String) async throws {
        try requirePlatform()
        guard FileManager.default.isExecutableFile(atPath: executable) else {
            throw SandvaultError.notInstalled("sandvault-netd executable at \(executable)")
        }
        let directory = (plistPath as NSString).deletingLastPathComponent
        try FileManager.default.createDirectory(atPath: directory, withIntermediateDirectories: true)
        try FileManager.default.createDirectory(atPath: paths.logDir, withIntermediateDirectories: true, attributes: [.posixPermissions: 0o700])
        // Replacing a loaded agent: boot it out first so launchd picks up the new plist.
        _ = try? await runner.run(CommandInvocation(Self.launchctl, ["bootout", service]))
        try AtomicFile.write(try Self.propertyList(executable: executable, paths: paths), to: plistPath, permissions: 0o644)
        _ = try await runner.checked(CommandInvocation(Self.launchctl, ["bootstrap", domain, plistPath]))
    }

    public func uninstall() async throws {
        try requirePlatform()
        let result = try await runner.run(CommandInvocation(Self.launchctl, ["bootout", service]))
        // Exit 3 / 113: not loaded; nothing to stop.
        if !result.succeeded, ![3, 113].contains(result.exitCode) {
            throw SandvaultError.commandFailed("launchctl bootout \(service)", result.exitCode, result.stderrString)
        }
        if FileManager.default.fileExists(atPath: plistPath) { try FileManager.default.removeItem(atPath: plistPath) }
    }

    public func restart() async throws {
        try requirePlatform()
        _ = try await runner.checked(CommandInvocation(Self.launchctl, ["kickstart", "-k", service]))
    }

    public func status() async throws -> Status {
        try requirePlatform()
        let installed = FileManager.default.fileExists(atPath: plistPath)
        let result = try await runner.run(CommandInvocation(Self.launchctl, ["print", service]))
        var status = Self.parsePrint(result.succeeded ? result.stdoutString : "")
        status.installed = installed
        status.loaded = result.succeeded
        status.plistPath = plistPath
        return status
    }

    /// Parses `launchctl print gui/<uid>/<label>` (top-level `key = value` lines of the service block).
    public static func parsePrint(_ text: String) -> Status {
        var status = Status(installed: false, loaded: !text.isEmpty, state: nil, pid: nil, lastExitCode: nil, plistPath: "", executable: nil)
        for line in text.split(separator: "\n") {
            // Only the service's own properties: one tab of indentation.
            guard line.hasPrefix("\t"), !line.hasPrefix("\t\t") else { continue }
            let parts = line.dropFirst().components(separatedBy: " = ")
            guard parts.count == 2 else { continue }
            let value = parts[1].trimmingCharacters(in: .whitespaces)
            switch parts[0].trimmingCharacters(in: .whitespaces) {
            case "state": status.state = value
            case "pid": status.pid = Int32(value)
            case "last exit code": status.lastExitCode = value
            case "program": status.executable = value
            default: break
            }
        }
        return status
    }

    private func requirePlatform() throws {
        guard platformSupported else { throw SandvaultError.unsupportedPlatform("LaunchAgents (launchd) exist only on macOS") }
    }
}
