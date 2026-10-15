import Foundation
#if canImport(Glibc)
import Glibc
#endif
import SandvaultCore
import Testing
@testable import SandvaultWorkflow

/// Copies instead of cloning (Linux has no `clonefileat`), through the descriptor as the real clone does.
struct CopyClone: TreeCloning {
    func clone(_ source: String, into directory: Int32, name: String) throws {
        #if os(Linux)
        let parent = (try? FileManager.default.destinationOfSymbolicLink(atPath: "/proc/self/fd/\(directory)")) ?? ""
        #else
        var buffer = [CChar](repeating: 0, count: Int(MAXPATHLEN))
        _ = fcntl(directory, F_GETPATH, &buffer)
        let parent = String(cString: buffer)
        #endif
        try FileManager.default.copyItem(atPath: source, toPath: parent + "/" + name)
    }
}

@Suite struct AndroidTests {
    /// A host SDK with an emulator, adb and one system image, and one host device that uses it.
    func hostSetup(_ sandbox: Sandbox, emulator: String = "36.1.9") throws -> String {
        let sdk = sandbox.home + "/Library/Android/sdk"
        try sandbox.write("Pkg.Desc=Android Emulator\nPkg.Revision=\(emulator)\n", to: sdk + "/emulator/source.properties")
        try sandbox.write("#!/bin/sh\n", to: sdk + "/emulator/emulator", mode: 0o755)
        try sandbox.write("#!/bin/sh\n", to: sdk + "/platform-tools/adb", mode: 0o755)
        try sandbox.write("Pkg.Revision=7\n", to: sdk + "/system-images/android-35/google_apis/arm64-v8a/source.properties")
        let avd = sandbox.home + "/.android/avd"
        try sandbox.write("avd.ini.encoding=UTF-8\npath=\(avd)/Pixel_8.avd\npath.rel=avd/Pixel_8.avd\ntarget=android-35\n", to: avd + "/Pixel_8.ini")
        try sandbox.write("""
            AvdId=Pixel_8
            avd.ini.displayname=Pixel 8
            hw.sdCard=yes
            sdcard.size=512M
            image.sysdir.1=system-images/android-35/google_apis/arm64-v8a/
            skin.path=\(sdk)/skins/pixel_8
            hw.ramSize=2048

            """, to: avd + "/Pixel_8.avd/config.ini")
        try sandbox.write("host data\n", to: avd + "/Pixel_8.avd/userdata-qemu.img")
        return sdk
    }

    func service(_ sandbox: Sandbox, _ runner: CommandRunner = FakeCommandRunner()) -> AndroidSharing {
        AndroidSharing(environment: sandbox.environment, runner: runner, shared: sandbox.shared, cloner: CopyClone(),
                       hostVariables: [:], extraSDKCandidates: [])
    }

    @Test func nothingOnTheHost() async throws {
        let sandbox = try Sandbox()
        defer { sandbox.cleanup() }
        let status = try await service(sandbox).status()
        #expect(status.hostSDK == nil)
        #expect(!status.sharedSDKPresent && !status.sharedOutdated && status.hostDevices.isEmpty)
        await #expect(throws: SandvaultError.self) { try await service(sandbox).shareSDK() }
    }

    @Test func shareImportUpdateAndUnshare() async throws {
        let sandbox = try Sandbox()
        defer { sandbox.cleanup() }
        let sdk = try hostSetup(sandbox)
        // The network block written by netd must survive.
        try sandbox.shared.write(Data("# mine\n\(ManagedBlock.zshenv.begin)\nexport HTTPS_PROXY=x\n\(ManagedBlock.zshenv.end)\n".utf8), to: "user/.zshenv")

        let android = service(sandbox)
        let before = try await android.status()
        #expect(before.hostSDK == HostPath.resolved(sdk))
        #expect(before.hostEmulatorVersion == "36.1.9")
        #expect(before.hostSystemImages == ["system-images/android-35/google_apis/arm64-v8a"])
        #expect(before.hostDevices.map(\.name) == ["Pixel_8"])
        #expect(before.hostDevices.first?.imageShared == false)
        await #expect(throws: SandvaultError.self) { try await android.importDevice("Pixel_8") }

        let shared = try await android.shareSDK()
        #expect(shared.sharedSDKPresent && !shared.sharedOutdated && shared.environmentCurrent)
        #expect(shared.sharedEmulatorVersion == "36.1.9")
        #expect(shared.hostDevices.first?.imageShared == true)
        #expect(FileKind.of(sandbox.workspace + "/android/sdk/platform-tools/adb") == .regular)
        #expect(FileKind.mode(sandbox.workspace + "/android") == 0o755)
        #expect(FileKind.mode(sandbox.workspace + "/android/avd") == 0o770)
        let zshenv = try sandbox.read(sandbox.workspace + "/user/.zshenv")
        #expect(zshenv.contains("export HTTPS_PROXY=x"))
        #expect(zshenv.contains("export ANDROID_HOME='/Users/Shared/sv-alice/android/sdk'"))
        #expect(zshenv.contains("export ANDROID_AVD_HOME='/Users/Shared/sv-alice/android/avd'"))
        #expect(zshenv.contains("path=('/Users/Shared/sv-alice/android/sdk/emulator' '/Users/Shared/sv-alice/android/sdk/platform-tools'"))

        let device = try await android.importDevice("Pixel_8")
        #expect(device.systemImage == "system-images/android-35/google_apis/arm64-v8a")
        let ini = try sandbox.read(sandbox.workspace + "/android/avd/Pixel_8.ini")
        #expect(ini.contains("path=/Users/Shared/sv-alice/android/avd/Pixel_8.avd\n") && ini.contains("target=android-35"))
        let config = try sandbox.read(sandbox.workspace + "/android/avd/Pixel_8.avd/config.ini")
        #expect(config.contains("hw.sdCard=no") && !config.contains("sdcard.size"))
        #expect(config.contains("skin.path=/Users/Shared/sv-alice/android/sdk/skins/pixel_8"))
        #expect(!config.contains(sandbox.home))
        // Settings only: the host's data stays.
        #expect(FileKind.of(sandbox.workspace + "/android/avd/Pixel_8.avd/userdata-qemu.img") == .missing)
        await #expect(throws: SandvaultError.self) { try await android.importDevice("Pixel_8") }
        #expect(try await android.status().sandboxDevices.map(\.name) == ["Pixel_8"])
        #expect(try await android.status().importableDevices.isEmpty)

        // A newer host SDK makes the copy outdated; sharing again replaces it and keeps the devices.
        try sandbox.write("Pkg.Revision=36.2.0\n", to: sdk + "/emulator/source.properties")
        #expect(try await android.status().sharedOutdated)
        let updated = try await android.shareSDK()
        #expect(updated.sharedEmulatorVersion == "36.2.0" && !updated.sharedOutdated)
        #expect(try FileManager.default.contentsOfDirectory(atPath: sandbox.workspace + "/android").sorted() == ["avd", "sdk"])
        #expect(updated.sandboxDevices.map(\.name) == ["Pixel_8"])

        let unshared = try await android.unshare()
        #expect(!unshared.sharedSDKPresent && !unshared.environmentCurrent)
        #expect(unshared.sandboxDevices.map(\.name) == ["Pixel_8"])
        let after = try sandbox.read(sandbox.workspace + "/user/.zshenv")
        #expect(after.contains("export HTTPS_PROXY=x") && !after.contains("ANDROID_HOME"))

        try await android.removeDevice("Pixel_8")
        #expect(try FileManager.default.contentsOfDirectory(atPath: sandbox.workspace + "/android/avd").isEmpty)
        await #expect(throws: SandvaultError.self) { try await android.removeDevice("../x") }
    }

    @Test func plantedSymlinksAreReplacedNotFollowed() async throws {
        let sandbox = try Sandbox()
        defer { sandbox.cleanup() }
        _ = try hostSetup(sandbox)
        let victim = sandbox.base + "/victim"
        try sandbox.write("keep\n", to: victim + "/file")
        try FileManager.default.createDirectory(atPath: sandbox.workspace + "/android", withIntermediateDirectories: true)
        try FileManager.default.createSymbolicLink(atPath: sandbox.workspace + "/android/sdk", withDestinationPath: victim)

        let status = try await service(sandbox).shareSDK()
        #expect(status.sharedSDKPresent)
        #expect(FileKind.of(sandbox.workspace + "/android/sdk") == .directory)
        #expect(try sandbox.read(victim + "/file") == "keep\n")
    }

    @Test func sandboxSDKIsNotTakenForTheHostSDK() async throws {
        let sandbox = try Sandbox()
        defer { sandbox.cleanup() }
        try sandbox.write("", to: sandbox.workspace + "/android/sdk/platform-tools/adb")
        let android = AndroidSharing(environment: sandbox.environment, runner: FakeCommandRunner(), shared: sandbox.shared, cloner: CopyClone(),
                                     hostVariables: ["ANDROID_HOME": sandbox.workspace + "/android/sdk"], extraSDKCandidates: [])
        #expect(try await android.status().hostSDK == nil)
    }

    @Test func checkRunsTheEmulatorSandboxed() async throws {
        let sandbox = try Sandbox()
        defer { sandbox.cleanup() }
        try sandbox.write("", to: sandbox.workspace + "/android/sdk/emulator/emulator")
        let emulator = "/Users/Shared/sv-alice/android/sdk/emulator/emulator"
        let fake = FakeCommandRunner()
        let invocation = { (command: [String]) in AndroidSharing.sandboxInvocation(sandbox.environment, command).argv }
        fake.on(invocation([emulator, "-version"]), stdout: "INFO    | Android emulator version 36.1.9.0 (build_id 13823996) (CL:N/A)\nAndroid emulator version 36.1.9.0 (build_id 13823996) (CL:N/A)\n")
        fake.on(invocation([emulator, "-list-avds"]), stdout: "INFO    | Storing crashdata in: /tmp/x\nPixel_8\n")
        fake.on(invocation([emulator, "-accel-check"]), stdout: "accel:\n0\nHypervisor.Framework OS X Version 26.0\naccel\n")
        fake.on(invocation(["/bin/test", "-w", "/Users/Shared/sv-alice/android/avd"]), stdout: "")
        fake.on(invocation(["/Users/Shared/sv-alice/android/sdk/platform-tools/adb", "version"]), stdout: "", exitCode: 127, stderr: "no such file")

        let check = try await service(sandbox, fake).checkSandbox()
        #expect(check.emulatorVersion == "Android emulator version 36.1.9.0 (build_id 13823996) (CL:N/A)")
        #expect(check.acceleration && check.accelerationDetail == "0 Hypervisor.Framework OS X Version 26.0")
        #expect(check.devices == ["Pixel_8"])
        #expect(check.deviceHomeWritable && check.adbVersion == nil)
        #expect(check.ready)
        let argv = invocation([emulator, "-version"])
        #expect(argv.starts(with: ["/usr/bin/sudo", "-n", "-u", "sandvault-alice", "/usr/bin/env", "-i"]))
        #expect(argv.contains("ANDROID_AVD_HOME=/Users/Shared/sv-alice/android/avd"))
        #expect(argv.contains("/usr/bin/sandbox-exec"))
    }

    @Test func readinessNamesTheMissingSDK() async throws {
        let sandbox = try Sandbox()
        defer { sandbox.cleanup() }
        let repo = sandbox.base + "/src/app"
        try await TestGit.repository(at: repo, files: [
            "app/src/main/AndroidManifest.xml": "<manifest/>\n", "local.properties": "sdk.dir=\(sandbox.home)/Library/Android/sdk\n",
        ])
        let handoff = RepositoryHandoff(environment: sandbox.environment, runner: ProcessCommandRunner(), configStore: sandbox.configStore,
                                        shared: sandbox.shared)
        let report = try await handoff.readiness(of: repo)
        let android = report.findings.filter { $0.kind == .androidSDK }
        #expect(android.count == 2)
        #expect(android.allSatisfy { $0.severity == .warning })
        #expect(android.contains { $0.path == "local.properties" })

        try FileManager.default.createDirectory(atPath: sandbox.workspace + "/android/sdk", withIntermediateDirectories: true)
        let shared = try await handoff.readiness(of: repo)
        #expect(shared.findings.filter { $0.kind == .androidSDK }.map(\.path) == ["local.properties"])
    }

    @Test func configRewrite() {
        let config = "AvdId=Old\nhw.sdCard=yes\nsdcard.path=/Users/alice/.android/avd/Old.avd/sdcard.img\n"
            + "skin.path=/Users/alice/Library/Android/sdk/skins/p\nfoo=/Users/alice/private/thing\nimage.sysdir.1=system-images/a/b/c/\n"
            + "snapshot.present=/Users/alice/.android/avd/Old.avd/snapshots\n"
        let result = AndroidSharing.sandboxConfig(
            config, name: "New", sdkPrefixes: ["/Users/alice/Library/Android/sdk"], sharedSDK: "/S/sdk",
            devicePrefixes: ["/Users/alice/.android/avd/Old.avd"], sharedDevice: "/S/avd/New.avd", hostHome: "/Users/alice"
        )
        #expect(result == "AvdId=New\nhw.sdCard=no\nskin.path=/S/sdk/skins/p\nimage.sysdir.1=system-images/a/b/c/\nsnapshot.present=/S/avd/New.avd/snapshots\n")
    }

    @Test func parsing() {
        #expect(AndroidSharing.revision("Pkg.Desc=x\nPkg.Revision = 35.1.2\n") == "35.1.2")
        #expect(AndroidSharing.revision(nil) == nil)
        #expect(AndroidSharing.imageKey("system-images\\android-35\\default\\x86_64\\") == "system-images/android-35/default/x86_64")
        #expect(AndroidSharing.isValidName("Pixel_8_API_35") && AndroidSharing.isValidName("a.b-c"))
        #expect(!AndroidSharing.isValidName("../x") && !AndroidSharing.isValidName(".hidden") && !AndroidSharing.isValidName("a b"))
        #expect(ReadinessCheck.sdkDirectory("#c\nsdk.dir=/Users/alice/Library/Android/sdk\n") == "/Users/alice/Library/Android/sdk")
        #expect(ReadinessCheck.sdkDirectory("sdk.dir=C\\:\\\\Android\\\\sdk") == "C:\\Android\\sdk")
    }
}
