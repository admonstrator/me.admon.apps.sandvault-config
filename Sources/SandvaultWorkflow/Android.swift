import Foundation
#if canImport(Darwin)
import Darwin
#elseif canImport(Glibc)
import Glibc
#endif
import SandvaultCore

/// Copy-on-write copy of a directory tree into a directory given by descriptor.
public protocol TreeCloning: Sendable {
    func clone(_ source: String, into directory: Int32, name: String) throws
}

/// `clonefileat(2)`: APFS clones a whole tree in one call and the copy shares the host's blocks. Source and
/// destination must be on the same APFS volume (`/Users/<host>` and `/Users/Shared` are on the Data volume).
public struct APFSTreeClone: TreeCloning {
    public init() {}

    public func clone(_ source: String, into directory: Int32, name: String) throws {
        #if os(macOS)
        let noFollow: UInt32 = 0x0001 // CLONE_NOFOLLOW
        guard clonefileat(AT_FDCWD, source, directory, name, noFollow) == 0 else {
            let code = errno
            if code == EXDEV || code == ENOTSUP {
                throw SandvaultError.io("cannot clone \(source): it is not on the same APFS volume as the shared workspace (errno \(code))")
            }
            throw SandvaultError.io("clone \(source) failed (errno \(code))")
        }
        #else
        throw SandvaultError.unsupportedPlatform("cloning the Android SDK needs APFS on macOS")
        #endif
    }
}

/// The host's Android SDK for the sandbox. The sandbox cannot read `~/Library/Android/sdk` (sv's profile denies
/// the host home), so the SDK is cloned to `$SHARED_WORKSPACE/android/sdk`, host-owned and read-only for the
/// sandbox. Virtual devices live in `$SHARED_WORKSPACE/android/avd`, which the sandbox writes; a host device is
/// brought over as configuration only, so its user data and snapshots stay on the host.
/// The sandbox's shells get `ANDROID_HOME`, `ANDROID_AVD_HOME` and `PATH` from a managed block in
/// `$SHARED_WORKSPACE/user/.zshenv`.
public struct AndroidSharing: AndroidService {
    public let layout: SharedLayout
    public let paths: AppPaths
    public let runner: CommandRunner
    public let cloner: TreeCloning
    /// The host's environment (`ANDROID_HOME`, `ANDROID_SDK_ROOT`, `ANDROID_AVD_HOME`, `ANDROID_USER_HOME`).
    public let hostVariables: [String: String]
    /// Homebrew's `android-commandlinetools` and the like, after the host home.
    public let extraSDKCandidates: [String]

    public static let block = ManagedBlock(name: "android", commentPrefix: "#")
    static let maxConfigBytes = 256 << 10

    public init(
        environment: SandvaultEnvironment, runner: CommandRunner, shared: SharedFiles? = nil, cloner: TreeCloning = APFSTreeClone(),
        hostVariables: [String: String] = ProcessInfo.processInfo.environment,
        extraSDKCandidates: [String] = ["/opt/homebrew/share/android-commandlinetools", "/usr/local/share/android-commandlinetools"]
    ) {
        layout = SharedLayout(environment: environment, shared: shared)
        paths = AppPaths(environment: environment)
        self.runner = runner
        self.cloner = cloner
        self.hostVariables = hostVariables
        self.extraSDKCandidates = extraSDKCandidates
    }

    var androidRelative: String { layout.relative(paths.androidDir) }
    var sdkRelative: String { layout.relative(paths.androidSDK) }
    var deviceHomeRelative: String { layout.relative(paths.androidAVDHome) }

    // MARK: - Status

    public func status() async throws -> AndroidStatus {
        let host = hostSDK()
        let sharedImages = sharedSystemImages()
        let shared = sharedEmulatorVersion()
        let present = (try? layout.shared.list(sdkRelative)) != nil
        let hostDevices = self.hostDevices().map { device -> AndroidDevice in
            var device = device
            device.imageShared = device.systemImage.map { sharedImages.contains(Self.imageKey($0)) } ?? false
            return device
        }
        return AndroidStatus(
            hostSDK: host, hostEmulatorVersion: host.flatMap { Self.revision(try? String(contentsOfFile: $0 + "/emulator/source.properties", encoding: .utf8)) },
            hostSystemImages: host.map(Self.hostSystemImages) ?? [], hostDevices: hostDevices,
            sharedSDK: paths.androidSDK, sharedSDKPresent: present, sharedEmulatorVersion: shared, sharedSystemImages: sharedImages,
            sandboxDevices: sandboxDevices(images: sharedImages), environmentCurrent: (try? environmentState()) == .current
        )
    }

    /// The first candidate with an `emulator` or `platform-tools` directory, resolved.
    func hostSDK() -> String? {
        let home = layout.environment.hostHome
        let candidates = [hostVariables["ANDROID_HOME"], hostVariables["ANDROID_SDK_ROOT"]].compactMap { $0 }.filter { !$0.isEmpty }
            + [home + "/Library/Android/sdk"] + extraSDKCandidates
        for candidate in candidates {
            let path = HostPath.absolute(candidate, home: home)
            guard let real = HostPath.resolved(path), FileKind.of(real) == .directory, !layout.isSandboxWritable(real) else { continue }
            if FileKind.of(real + "/emulator") == .directory || FileKind.of(real + "/platform-tools") == .directory { return real }
        }
        return nil
    }

    var hostDeviceHome: String {
        let home = layout.environment.hostHome
        if let explicit = hostVariables["ANDROID_AVD_HOME"], !explicit.isEmpty { return HostPath.absolute(explicit, home: home) }
        if let user = hostVariables["ANDROID_USER_HOME"], !user.isEmpty { return HostPath.absolute(user, home: home) + "/avd" }
        return home + "/.android/avd"
    }

    func hostDevices() -> [AndroidDevice] {
        let home = hostDeviceHome
        let names = ((try? FileManager.default.contentsOfDirectory(atPath: home)) ?? [])
            .filter { $0.hasSuffix(".ini") }.map { String($0.dropLast(4)) }.filter(Self.isValidName).sorted()
        return names.compactMap { name in
            guard let pointer = try? String(contentsOfFile: "\(home)/\(name).ini", encoding: .utf8) else { return nil }
            let values = Self.properties(pointer)
            let directory = values["path"].flatMap { FileKind.of($0) == .directory ? $0 : nil } ?? "\(home)/\(name).avd"
            let config = Self.properties((try? String(contentsOfFile: directory + "/config.ini", encoding: .utf8)) ?? "")
            return AndroidDevice(name: name, displayName: config["avd.ini.displayname"], target: values["target"], systemImage: config["image.sysdir.1"].map(Self.imageKey))
        }
    }

    func sandboxDevices(images: [String]) -> [AndroidDevice] {
        let entries = (try? layout.shared.list(deviceHomeRelative)) ?? []
        return entries.filter { $0.hasSuffix(".ini") }.map { String($0.dropLast(4)) }.filter(Self.isValidName).map { name in
            let pointer = try? layout.shared.read("\(deviceHomeRelative)/\(name).ini", maxBytes: Self.maxConfigBytes)
            let config = try? layout.shared.read("\(deviceHomeRelative)/\(name).avd/config.ini", maxBytes: Self.maxConfigBytes)
            let values = Self.properties(pointer.map { String(decoding: $0, as: UTF8.self) } ?? "")
            let settings = Self.properties(config.map { String(decoding: $0, as: UTF8.self) } ?? "")
            let image = settings["image.sysdir.1"].map(Self.imageKey)
            return AndroidDevice(name: name, displayName: settings["avd.ini.displayname"], target: values["target"], systemImage: image,
                                 imageShared: image.map(images.contains) ?? false)
        }
    }

    func sharedEmulatorVersion() -> String? {
        guard let data = try? layout.shared.read("\(sdkRelative)/emulator/source.properties", maxBytes: Self.maxConfigBytes) else { return nil }
        return Self.revision(String(decoding: data, as: UTF8.self))
    }

    func sharedSystemImages() -> [String] {
        let root = "\(sdkRelative)/system-images"
        var result: [String] = []
        for api in (try? layout.shared.list(root)) ?? [] {
            for tag in (try? layout.shared.list("\(root)/\(api)")) ?? [] {
                for abi in (try? layout.shared.list("\(root)/\(api)/\(tag)")) ?? [] {
                    result.append("system-images/\(api)/\(tag)/\(abi)")
                }
            }
        }
        return result
    }

    static func hostSystemImages(_ sdk: String) -> [String] {
        let manager = FileManager.default
        let root = sdk + "/system-images"
        var result: [String] = []
        for api in ((try? manager.contentsOfDirectory(atPath: root)) ?? []).sorted() where !api.hasPrefix(".") {
            for tag in ((try? manager.contentsOfDirectory(atPath: "\(root)/\(api)")) ?? []).sorted() where !tag.hasPrefix(".") {
                for abi in ((try? manager.contentsOfDirectory(atPath: "\(root)/\(api)/\(tag)")) ?? []).sorted() where !abi.hasPrefix(".") {
                    if FileKind.of("\(root)/\(api)/\(tag)/\(abi)") == .directory { result.append("system-images/\(api)/\(tag)/\(abi)") }
                }
            }
        }
        return result
    }

    // MARK: - Sharing

    public func shareSDK() async throws -> AndroidStatus {
        guard let source = hostSDK() else {
            throw SandvaultError.notInstalled("an Android SDK on this Mac (Android Studio puts it in ~/Library/Android/sdk; or set ANDROID_HOME)")
        }
        try layout.requireWorkspace()
        let token = UUID().uuidString
        let fresh = "sdk.new-\(token)"
        let old = "sdk.old-\(token)"
        try layout.shared.withDirectory(androidRelative, create: true, permissions: 0o755) { directory in
            try cloner.clone(source, into: directory, name: fresh)
        }
        do {
            do {
                try layout.shared.rename(sdkRelative, to: "\(androidRelative)/\(old)")
            } catch SandvaultError.io(let message) where message.hasSuffix("(errno \(ENOENT))") {}
            try layout.shared.rename("\(androidRelative)/\(fresh)", to: sdkRelative)
        } catch {
            try? layout.shared.removeTree("\(androidRelative)/\(fresh)")
            throw error
        }
        try layout.shared.removeTree("\(androidRelative)/\(old)")
        try layout.shared.withDirectory(deviceHomeRelative, create: true, permissions: 0o770) { _ in }
        try writeEnvironment(enabled: true)
        return try await status()
    }

    public func unshare() async throws -> AndroidStatus {
        try writeEnvironment(enabled: false)
        try layout.shared.removeTree(sdkRelative)
        return try await status()
    }

    // MARK: - Devices

    public func importDevice(_ name: String) async throws -> AndroidDevice {
        try Self.validate(name: name)
        let current = try await status()
        guard current.sharedSDKPresent else { throw SandvaultError.invalidInput("share the Android SDK first (svctl android share)") }
        guard let device = current.hostDevices.first(where: { $0.name == name }) else {
            throw SandvaultError.invalidInput("no device \(name) in \(hostDeviceHome)")
        }
        guard !current.sandboxDevices.contains(where: { $0.name == name }),
              try layout.shared.list("\(deviceHomeRelative)/\(name).avd") == nil
        else { throw SandvaultError.invalidInput("the sandbox already has a device \(name); remove it first") }
        guard device.imageShared, let image = device.systemImage else {
            throw SandvaultError.invalidInput("\(name) uses \(device.systemImage ?? "an unknown system image"), which the SDK copy does not have; share the SDK again")
        }
        let home = hostDeviceHome
        let pointer = Self.properties((try? String(contentsOfFile: "\(home)/\(name).ini", encoding: .utf8)) ?? "")
        let hostDirectory = pointer["path"].flatMap { FileKind.of($0) == .directory ? $0 : nil } ?? "\(home)/\(name).avd"
        guard FileKind.size(hostDirectory + "/config.ini").map({ $0 <= Self.maxConfigBytes }) == true,
              let config = try? String(contentsOfFile: hostDirectory + "/config.ini", encoding: .utf8)
        else { throw SandvaultError.io("cannot read \(hostDirectory)/config.ini") }

        let directory = "\(paths.androidAVDHome)/\(name).avd"
        let hostSDKs = [hostSDK(), current.hostSDK].compactMap { $0 } + [layout.environment.hostHome + "/Library/Android/sdk"]
        let rewritten = Self.sandboxConfig(
            config, name: name, sdkPrefixes: hostSDKs, sharedSDK: paths.androidSDK,
            devicePrefixes: [hostDirectory, HostPath.resolved(hostDirectory) ?? hostDirectory], sharedDevice: directory,
            hostHome: layout.environment.hostHome
        )
        try layout.shared.withDirectory(deviceHomeRelative, create: true, permissions: 0o770) { _ in }
        try layout.shared.withDirectory("\(deviceHomeRelative)/\(name).avd", create: true, permissions: 0o770) { _ in }
        try layout.shared.write(Data(rewritten.utf8), to: "\(deviceHomeRelative)/\(name).avd/config.ini")
        var ini = ["avd.ini.encoding=UTF-8", "path=\(directory)", "path.rel=avd/\(name).avd"]
        if let target = device.target, !Text.hasControlCharacters(target) { ini.append("target=\(target)") }
        try layout.shared.write(Data((ini.joined(separator: "\n") + "\n").utf8), to: "\(deviceHomeRelative)/\(name).ini")
        return AndroidDevice(name: name, displayName: device.displayName, target: device.target, systemImage: image, imageShared: true)
    }

    public func removeDevice(_ name: String) async throws {
        try Self.validate(name: name)
        try layout.shared.remove("\(deviceHomeRelative)/\(name).ini")
        try layout.shared.removeTree("\(deviceHomeRelative)/\(name).avd")
    }

    /// The host device's `config.ini` for the sandbox: SDK and device paths point at the shared copies, lines
    /// still naming the host home are dropped, and the SD card (a host file holding host data) is left out.
    static func sandboxConfig(
        _ config: String, name: String, sdkPrefixes: [String], sharedSDK: String, devicePrefixes: [String], sharedDevice: String, hostHome: String
    ) -> String {
        var lines: [String] = []
        for line in config.split(omittingEmptySubsequences: false, whereSeparator: \.isNewline).map(String.init) {
            guard let equals = line.firstIndex(of: "=") else {
                if !line.trimmingCharacters(in: .whitespaces).isEmpty { lines.append(line) }
                continue
            }
            let key = line[..<equals].trimmingCharacters(in: .whitespaces)
            var value = line[line.index(after: equals)...].trimmingCharacters(in: .whitespaces)
            switch key {
            case "sdcard.size", "sdcard.path": continue
            case "hw.sdCard": value = "no"
            case "AvdId": value = name
            default:
                for (prefixes, replacement) in [(sdkPrefixes, sharedSDK), (devicePrefixes, sharedDevice)] {
                    if let prefix = prefixes.first(where: { HostPath.isInside(value, $0) }) {
                        value = replacement + value.dropFirst(prefix.count)
                        break
                    }
                }
                if HostPath.isInside(value, hostHome) || Text.hasControlCharacters(value) { continue }
            }
            lines.append("\(key)=\(value)")
        }
        return lines.joined(separator: "\n") + "\n"
    }

    // MARK: - Environment block

    /// zsh lines for the managed block in `$SHARED_WORKSPACE/user/.zshenv`.
    public static func environmentBody(_ paths: AppPaths) -> String {
        let sdk = paths.androidSDK
        let quoted = { (value: String) in "'" + value.replacingOccurrences(of: "'", with: "'\\''") + "'" }
        return [
            "export ANDROID_HOME=\(quoted(sdk))",
            "export ANDROID_SDK_ROOT=\(quoted(sdk))",
            "export ANDROID_AVD_HOME=\(quoted(paths.androidAVDHome))",
            "path=(\(quoted(sdk + "/emulator")) \(quoted(sdk + "/platform-tools")) \(quoted(sdk + "/cmdline-tools/latest/bin")) $path)",
        ].joined(separator: "\n")
    }

    enum EnvironmentState { case current, missing, stale }

    func environmentState() throws -> EnvironmentState {
        let text = try layout.shared.read(layout.relative(paths.sharedZshenv)).map { String(decoding: $0, as: UTF8.self) } ?? ""
        guard let body = Self.block.extract(from: text) else { return .missing }
        return body == Self.environmentBody(paths) ? .current : .stale
    }

    /// Only the android block changes; the network block and everything else in the file stay.
    func writeEnvironment(enabled: Bool) throws {
        let relative = layout.relative(paths.sharedZshenv)
        let current = try layout.shared.read(relative).map { String(decoding: $0, as: UTF8.self) }
        let updated: String
        if enabled {
            updated = Self.block.replace(in: current ?? "", with: Self.environmentBody(paths))
        } else {
            guard let current, Self.block.contains(in: current) else { return }
            updated = Self.block.remove(from: current)
        }
        guard updated != current else { return }
        try layout.shared.write(Data(updated.utf8), to: relative, permissions: 0o640)
    }

    // MARK: - Check inside the sandbox

    public func checkSandbox() async throws -> AndroidSandboxCheck {
        guard try layout.shared.list(sdkRelative) != nil else { throw SandvaultError.invalidInput("share the Android SDK first (svctl android share)") }
        let emulator = paths.androidSDK + "/emulator/emulator"
        let version = try await sandboxed([emulator, "-version"])
        let devices = try await sandboxed([emulator, "-list-avds"])
        let acceleration = try await sandboxed([emulator, "-accel-check"])
        let writable = try await sandboxed(["/bin/test", "-w", paths.androidAVDHome])
        let adb = try await sandboxed([paths.androidSDK + "/platform-tools/adb", "version"])
        let versionLine = version.succeeded ? Self.meaningfulLines(version.stdoutString).first : nil
        return AndroidSandboxCheck(
            emulatorVersion: versionLine,
            emulatorError: version.succeeded ? nil : Self.failure(version),
            acceleration: acceleration.succeeded,
            accelerationDetail: Self.meaningfulLines(acceleration.stdoutString + "\n" + acceleration.stderrString).filter { $0 != "accel" && $0 != "accel:" }
                .joined(separator: " "),
            devices: devices.succeeded ? Self.meaningfulLines(devices.stdoutString).filter(Self.isValidName) : [],
            deviceHomeWritable: writable.succeeded,
            adbVersion: adb.succeeded ? Self.meaningfulLines(adb.stdoutString).first : nil
        )
    }

    /// As the sandbox user inside sv's profile, with the variables the environment block sets.
    public static func sandboxInvocation(_ environment: SandvaultEnvironment, _ command: [String]) -> CommandInvocation {
        let paths = AppPaths(environment: environment)
        return SandboxedCommand.invocation(environment, variables: [
            "ANDROID_HOME=\(paths.androidSDK)", "ANDROID_SDK_ROOT=\(paths.androidSDK)", "ANDROID_AVD_HOME=\(paths.androidAVDHome)",
        ], command, timeout: 60)
    }

    private func sandboxed(_ command: [String]) async throws -> CommandResult {
        do {
            return try await runner.run(Self.sandboxInvocation(layout.environment, command))
        } catch {
            return CommandResult(exitCode: 127, stdout: "", stderr: "\(error)")
        }
    }

    // MARK: - Parsing

    public static func validate(name: String) throws {
        guard isValidName(name) else {
            throw SandvaultError.invalidInput("'\(name)' is not a device name ([A-Za-z0-9._-], at most 100 characters)")
        }
    }

    static func isValidName(_ name: String) -> Bool {
        Text.matches(name, "^[A-Za-z0-9][A-Za-z0-9._-]{0,99}$")
    }

    /// `key=value` lines (`.ini`, `config.ini`, `source.properties`); later keys win.
    static func properties(_ text: String) -> [String: String] {
        var result: [String: String] = [:]
        for line in Text.lines(text) {
            guard let equals = line.firstIndex(of: "="), !line.hasPrefix("#") else { continue }
            result[line[..<equals].trimmingCharacters(in: .whitespaces)] = line[line.index(after: equals)...].trimmingCharacters(in: .whitespaces)
        }
        return result
    }

    /// `Pkg.Revision` of a `source.properties`.
    static func revision(_ text: String?) -> String? {
        text.flatMap { properties($0)["Pkg.Revision"] }.flatMap { $0.isEmpty ? nil : $0 }
    }

    /// `system-images/android-35/google_apis/arm64-v8a/` -> `system-images/android-35/google_apis/arm64-v8a`.
    static func imageKey(_ sysdir: String) -> String {
        var key = sysdir.replacingOccurrences(of: "\\", with: "/")
        while key.hasSuffix("/") { key.removeLast() }
        return key
    }

    /// Output lines without emulator log lines (`INFO    | ...`, `WARNING | ...`) and blanks.
    static func meaningfulLines(_ text: String) -> [String] {
        Text.lines(text).map { $0.trimmingCharacters(in: .whitespaces) }.filter { !$0.isEmpty && !$0.contains("| ") }
    }

    static func failure(_ result: CommandResult) -> String {
        let lines = meaningfulLines(result.stderrString) + meaningfulLines(result.stdoutString)
        return lines.first ?? "exit \(result.exitCode)"
    }
}
