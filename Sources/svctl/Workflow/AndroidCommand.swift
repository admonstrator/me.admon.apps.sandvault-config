import ArgumentParser
import Foundation
import SandvaultCore
import SandvaultWorkflow

struct AndroidCommand: AsyncParsableCommand {
    static let configuration = CommandConfiguration(
        commandName: "android",
        abstract: "Share the host's Android SDK and virtual devices with the sandbox.",
        subcommands: [Status.self, Share.self, Unshare.self, Device.self, Check.self],
        defaultSubcommand: Status.self
    )

    static func service(_ global: GlobalOptions) -> AndroidSharing {
        AndroidSharing(environment: global.environment, runner: global.runner)
    }

    static func show(_ status: AndroidStatus) {
        Output.line("host SDK: " + (status.hostSDK.map { "\($0) (emulator \(status.hostEmulatorVersion ?? "missing"))" } ?? "not found"))
        if status.sharedSDKPresent {
            Output.line("sandbox SDK: \(status.sharedSDK) (emulator \(status.sharedEmulatorVersion ?? "missing"))"
                + (status.sharedOutdated ? ", older than the host's: run svctl android share" : ""))
        } else {
            Output.line("sandbox SDK: not shared (svctl android share)")
        }
        Output.line("environment block: " + (status.environmentCurrent ? "current" : "missing or stale (svctl android share writes it)"))
        let rows = status.hostDevices.map { ["host", $0.name, $0.systemImage ?? "-", $0.imageShared ? "yes" : "no"] }
            + status.sandboxDevices.map { ["sandbox", $0.name, $0.systemImage ?? "-", $0.imageShared ? "yes" : "no"] }
        if rows.isEmpty {
            Output.line("no virtual devices")
        } else {
            Output.table(["WHERE", "DEVICE", "SYSTEM IMAGE", "IMAGE IN COPY"], rows)
        }
    }

    struct Status: AsyncParsableCommand {
        static let configuration = CommandConfiguration(abstract: "Host SDK, the sandbox's copy, environment block and devices.")
        @OptionGroup var global: GlobalOptions

        func run() async throws {
            let status = try await AndroidCommand.service(global).status()
            if global.json { return try Output.json(status) }
            AndroidCommand.show(status)
        }
    }

    struct Share: AsyncParsableCommand {
        static let configuration = CommandConfiguration(
            abstract: "Clone the host SDK to $SHARED_WORKSPACE/android/sdk (APFS, no extra space) and set ANDROID_HOME in the sandbox."
        )
        @OptionGroup var global: GlobalOptions

        func run() async throws {
            try WorkflowCLI.requireMacOS("cloning the SDK needs APFS")
            let status = try await AndroidCommand.service(global).shareSDK()
            if global.json { return try Output.json(status) }
            AndroidCommand.show(status)
            Output.line("new sandbox sessions get ANDROID_HOME, ANDROID_AVD_HOME and PATH; add a device with svctl android device add <name>")
        }
    }

    struct Unshare: AsyncParsableCommand {
        static let configuration = CommandConfiguration(abstract: "Remove the SDK copy and the environment block; the sandbox's devices stay.")
        @OptionGroup var global: GlobalOptions

        func run() async throws {
            let status = try await AndroidCommand.service(global).unshare()
            if global.json { return try Output.json(status) }
            AndroidCommand.show(status)
        }
    }

    struct Device: AsyncParsableCommand {
        static let configuration = CommandConfiguration(
            commandName: "device",
            abstract: "Virtual devices of the sandbox.",
            subcommands: [Add.self, Remove.self]
        )

        struct Add: AsyncParsableCommand {
            static let configuration = CommandConfiguration(
                abstract: "Create a sandbox device from a host device's configuration (its data and snapshots stay on the host)."
            )
            @OptionGroup var global: GlobalOptions
            @Argument(help: "Host device name (emulator -list-avds on the host).") var name: String

            func run() async throws {
                let device = try await AndroidCommand.service(global).importDevice(name)
                if global.json { return try Output.json(device) }
                Output.line("\(device.name) is in the sandbox; start it there with: emulator -avd \(device.name) -no-window -no-audio")
            }
        }

        struct Remove: AsyncParsableCommand {
            static let configuration = CommandConfiguration(abstract: "Delete a sandbox device with its data.")
            @OptionGroup var global: GlobalOptions
            @Argument(help: "Sandbox device name.") var name: String

            func run() async throws {
                try await AndroidCommand.service(global).removeDevice(name)
                if !global.json { Output.line("removed \(name)") }
            }
        }
    }

    struct Check: AsyncParsableCommand {
        static let configuration = CommandConfiguration(abstract: "Run emulator and adb as the sandbox user inside sv's profile.")
        @OptionGroup var global: GlobalOptions

        func run() async throws {
            try WorkflowCLI.requireMacOS("the check runs the emulator as the sandbox user")
            let check = try await AndroidCommand.service(global).checkSandbox()
            if global.json { return try Output.json(check) }
            Output.line("emulator: " + (check.emulatorVersion ?? "does not run (\(check.emulatorError ?? "unknown"))"))
            Output.line("acceleration: " + (check.acceleration ? "ok" : "not available") + (check.accelerationDetail.isEmpty ? "" : " (\(check.accelerationDetail))"))
            Output.line("devices: " + (check.devices.isEmpty ? "none (svctl android device add <name>)" : check.devices.joined(separator: ", ")))
            Output.line("device folder writable: " + (check.deviceHomeWritable ? "yes" : "no"))
            Output.line("adb: " + (check.adbVersion ?? "does not run"))
            Output.line(check.ready ? "ready: the sandbox can start the emulator without a window" : "not ready")
        }
    }
}
