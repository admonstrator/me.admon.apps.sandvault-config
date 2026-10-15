import Foundation
import Observation
import SandvaultCore

/// Tools > Android emulator: the host SDK as a copy for the sandbox, its devices and a check inside the sandbox.
@MainActor @Observable
public final class AndroidModel {
    public private(set) var status: AndroidStatus?
    public private(set) var check: AndroidSandboxCheck?
    public private(set) var availability = Availability.unknown
    /// What runs right now ("Sharing the SDK..."), `nil` when idle.
    public private(set) var activity: String?
    public var message: UserMessage?

    @ObservationIgnored private let service: AndroidService

    public init(service: AndroidService) {
        self.service = service
    }

    public var isBusy: Bool { activity != nil }

    public func refresh() async {
        guard !isBusy else { return }
        await perform("Read the Android setup", busy: nil) {
            self.status = try await self.service.status()
        }
    }

    public func share() async {
        let replacing = status?.sharedSDKPresent == true
        await perform(replacing ? "Update the SDK copy" : "Share the SDK", busy: "Cloning the SDK...") {
            self.status = try await self.service.shareSDK()
            self.check = nil
            self.message = .success(replacing ? "Updated the sandbox's SDK copy" : "Shared the Android SDK with the sandbox",
                                    detail: "New sandbox sessions get ANDROID_HOME and the emulator on their PATH.")
        }
    }

    public func unshare() async {
        await perform("Stop sharing the SDK", busy: "Removing the SDK copy...") {
            self.status = try await self.service.unshare()
            self.check = nil
            self.message = .info("The sandbox no longer has an Android SDK", detail: "Its devices stay in the shared workspace.")
        }
    }

    public func importDevice(_ device: AndroidDevice) async {
        await perform("Add \(device.name)", busy: "Adding \(device.name)...") {
            _ = try await self.service.importDevice(device.name)
            self.status = try await self.service.status()
            self.message = .success("\(device.name) is in the sandbox", detail: "Settings only; its data and snapshots stay on this Mac.")
        }
    }

    public func removeDevice(_ device: AndroidDevice) async {
        await perform("Remove \(device.name)", busy: "Removing \(device.name)...") {
            try await self.service.removeDevice(device.name)
            self.status = try await self.service.status()
        }
    }

    public func runCheck() async {
        await perform("Check the emulator in the sandbox", busy: "Starting the emulator in the sandbox...") {
            self.check = try await self.service.checkSandbox()
        }
    }

    // MARK: - Display

    public var hostSummary: String {
        guard let status else { return "Not checked yet." }
        guard let sdk = status.hostSDK else { return "No Android SDK on this Mac. Android Studio installs one in ~/Library/Android/sdk." }
        return sdk + (status.hostEmulatorVersion.map { " · emulator \($0)" } ?? " · no emulator installed")
    }

    public var sandboxSummary: String {
        guard let status else { return "" }
        guard status.sharedSDKPresent else { return "Not shared. The sandbox cannot read the SDK in your home folder." }
        if status.sharedOutdated { return "Shared, but older than the SDK on this Mac. Update it to bring new versions and system images over." }
        if !status.environmentCurrent { return "Shared, but the sandbox's shells do not set ANDROID_HOME yet. Share again to fix it." }
        return "Shared" + (status.sharedEmulatorVersion.map { " · emulator \($0)" } ?? "")
    }

    public var shareTitle: String { status?.sharedSDKPresent == true ? "Update Copy" : "Share SDK" }

    /// Start line for an agent, with the first sandbox device.
    public var startCommand: String {
        "emulator -avd \(status?.sandboxDevices.first?.name ?? "<device>") -no-window -no-audio"
    }

    /// One line per part of the check.
    public var checkLines: [AndroidCheckLine] {
        guard let check else { return [] }
        return [
            (check.emulatorVersion != nil, check.emulatorVersion ?? "The emulator does not start: \(check.emulatorError ?? "unknown reason")"),
            (check.acceleration, check.acceleration ? "Hardware acceleration works" : "No hardware acceleration" + (check.accelerationDetail.isEmpty ? "" : ": \(check.accelerationDetail)")),
            (!check.devices.isEmpty, check.devices.isEmpty ? "No devices; add one below" : "Devices: " + check.devices.joined(separator: ", ")),
            (check.deviceHomeWritable, check.deviceHomeWritable ? "The sandbox can write its device folder" : "The sandbox cannot write its device folder"),
            (check.adbVersion != nil, check.adbVersion ?? "adb does not start"),
        ].map { AndroidCheckLine(ok: $0.0, text: $0.1) }
    }

    private func perform(_ action: String, busy: String?, _ body: () async throws -> Void) async {
        activity = busy
        defer { activity = nil }
        switch await WorkflowCall.run(action, body) {
        case .value:
            availability = .available
        case .notAvailable(let note):
            availability = .notAvailableYet(note)
        case .failed(let failure):
            message = failure
        }
    }
}

public struct AndroidCheckLine: Sendable, Hashable, Identifiable {
    public var ok: Bool
    public var text: String
    public var id: String { text }
}

/// Stand-in until a build wires `AndroidSharing`; every call reports that the feature is missing.
public struct UnavailableAndroid: AndroidService {
    public init() {}

    private func missing() -> SandvaultError { .notImplemented("Android SDK sharing") }
    public func status() async throws -> AndroidStatus { throw missing() }
    public func shareSDK() async throws -> AndroidStatus { throw missing() }
    public func unshare() async throws -> AndroidStatus { throw missing() }
    public func importDevice(_ name: String) async throws -> AndroidDevice { throw missing() }
    public func removeDevice(_ name: String) async throws { throw missing() }
    public func checkSandbox() async throws -> AndroidSandboxCheck { throw missing() }
}
