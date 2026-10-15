import Foundation
import SandvaultCore
import Testing
@testable import SandvaultAppModel

final class FakeAndroid: AndroidService, @unchecked Sendable {
    var current = AndroidStatus(hostSDK: "/Users/alice/Library/Android/sdk", hostEmulatorVersion: "36.1.9",
                                hostDevices: [AndroidDevice(name: "Pixel_8", systemImage: "system-images/android-35/google_apis/arm64-v8a")],
                                sharedSDK: "/Users/Shared/sv-alice/android/sdk")
    var failShare = false

    func status() async throws -> AndroidStatus { current }
    func shareSDK() async throws -> AndroidStatus {
        if failShare { throw SandvaultError.io("cannot clone") }
        current.sharedSDKPresent = true
        current.sharedEmulatorVersion = current.hostEmulatorVersion
        current.environmentCurrent = true
        current.hostDevices = current.hostDevices.map { var device = $0; device.imageShared = true; return device }
        return current
    }
    func unshare() async throws -> AndroidStatus {
        current.sharedSDKPresent = false
        current.environmentCurrent = false
        return current
    }
    func importDevice(_ name: String) async throws -> AndroidDevice {
        let device = AndroidDevice(name: name, imageShared: true)
        current.sandboxDevices.append(device)
        return device
    }
    func removeDevice(_ name: String) async throws { current.sandboxDevices.removeAll { $0.name == name } }
    func checkSandbox() async throws -> AndroidSandboxCheck {
        AndroidSandboxCheck(emulatorVersion: "Android emulator version 36.1.9.0", acceleration: false, accelerationDetail: "HVF disabled",
                            devices: current.sandboxDevices.map(\.name), deviceHomeWritable: true)
    }
}

@MainActor @Suite struct AndroidModelTests {
    @Test func shareAddDeviceAndCheck() async {
        let fake = FakeAndroid()
        let model = AndroidModel(service: fake)
        #expect(model.hostSummary == "Not checked yet.")
        await model.refresh()
        #expect(model.hostSummary == "/Users/alice/Library/Android/sdk · emulator 36.1.9")
        #expect(model.sandboxSummary.hasPrefix("Not shared"))
        #expect(model.shareTitle == "Share SDK")

        await model.share()
        #expect(model.sandboxSummary == "Shared · emulator 36.1.9")
        #expect(model.shareTitle == "Update Copy")
        #expect(model.status?.importableDevices.map(\.name) == ["Pixel_8"])

        await model.importDevice(model.status!.importableDevices[0])
        #expect(model.status?.importableDevices.isEmpty == true)
        #expect(model.startCommand == "emulator -avd Pixel_8 -no-window -no-audio")

        await model.runCheck()
        #expect(model.checkLines.map(\.ok) == [true, false, true, true, false])
        #expect(model.checkLines[1].text == "No hardware acceleration: HVF disabled")
        #expect(!model.isBusy)
    }

    @Test func failuresBecomeMessagesAndMissingServiceIsNotAvailable() async {
        let fake = FakeAndroid()
        fake.failShare = true
        let model = AndroidModel(service: fake)
        await model.share()
        #expect(model.message != nil)
        #expect(model.status == nil)

        let missing = AndroidModel(service: UnavailableAndroid())
        await missing.refresh()
        #expect(!missing.availability.isAvailable)
    }
}
