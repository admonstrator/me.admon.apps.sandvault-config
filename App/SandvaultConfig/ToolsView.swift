import SandvaultAppModel
import SandvaultCore
import SwiftUI

struct ToolsView: View {
    @Bindable var tools: ToolsModel
    @Bindable var android: AndroidModel

    var body: some View {
        VStack(spacing: 0) {
            MessageArea(message: tools.message) { tools.message = nil }
            MessageArea(message: android.message) { android.message = nil }
            Form {
                if case .notAvailableYet(let note) = tools.availability {
                    Section {
                        NotAvailableView(title: "Tool checks are not available yet", note: note)
                    }
                }
                Section("Check a command") {
                    HStack {
                        TextField("Command name, e.g. jq", text: $tools.query)
                            .onSubmit { Task { await tools.check() } }
                        Button("Check") { Task { await tools.check() } }
                            .disabled(tools.query.isEmpty || tools.isBusy)
                    }
                    if let status = tools.status {
                        ToolStatusView(status: status) { method in
                            Task { await tools.grant(method) }
                        }
                    }
                }
                AndroidSection(android: android)
                Section("Granted") {
                    if tools.grants.isEmpty {
                        Text("Nothing granted yet.")
                            .foregroundStyle(.secondary)
                    }
                    ForEach(tools.grants) { grant in
                        LabeledContent(grant.name, value: "\(grant.method.displayName) · \(grant.source)")
                    }
                }
            }
            .formStyle(.grouped)
        }
        .navigationTitle(Screen.tools.title)
    }
}

struct ToolStatusView: View {
    let status: ToolStatus
    let grant: (ToolGrantMethod) -> Void

    var body: some View {
        VStack(alignment: .leading, spacing: 6) {
            Label(status.name, systemImage: status.reachableInSandbox ? "checkmark.circle.fill" : "xmark.circle")
                .foregroundStyle(status.reachableInSandbox ? Color.green : Color.orange)
                .font(.headline)
            Text(status.summary)
                .font(.callout)
                .textSelection(.enabled)
            if let kind = status.kind {
                Text(kind)
                    .font(.callout)
                    .foregroundStyle(.secondary)
            }
            Text(status.reason)
                .font(.callout)
                .foregroundStyle(.secondary)
            if !status.reachableInSandbox {
                HStack {
                    ForEach(status.options.filter { $0 != .available }, id: \.self) { method in
                        Button(method.displayName) { grant(method) }
                    }
                }
            }
        }
    }
}

/// The host's Android SDK as a copy for the sandbox, its devices and a check inside the sandbox.
struct AndroidSection: View {
    let android: AndroidModel
    @State private var confirmUnshare = false

    var body: some View {
        Section {
            if case .notAvailableYet(let note) = android.availability {
                Text(note).foregroundStyle(.secondary)
            } else {
                LabeledContent("This Mac", value: android.hostSummary)
                LabeledContent("Sandbox") {
                    Text(android.sandboxSummary)
                        .multilineTextAlignment(.trailing)
                }
                HStack {
                    if let activity = android.activity {
                        ProgressView().controlSize(.small)
                        Text(activity).foregroundStyle(.secondary)
                    }
                    Spacer()
                    if android.status?.sharedSDKPresent == true {
                        Button("Stop Sharing...") { confirmUnshare = true }
                        Button("Check in Sandbox") { Task { await android.runCheck() } }
                    }
                    Button(android.shareTitle) { Task { await android.share() } }
                        .disabled(android.status?.hostSDK == nil)
                }
                .disabled(android.isBusy)
                ForEach(android.checkLines) { line in
                    Label(line.text, systemImage: line.ok ? "checkmark.circle.fill" : "xmark.circle")
                        .foregroundStyle(line.ok ? Color.green : Color.orange)
                        .font(.callout)
                }
                if let status = android.status, status.sharedSDKPresent {
                    devices(status)
                }
            }
        } header: {
            Text("Android emulator")
        } footer: {
            Text("The SDK is cloned into the shared workspace, so it takes no extra space. In the sandbox the emulator runs without a window; an agent starts it with \(android.startCommand) and uses adb.")
        }
        .confirmationDialog("Stop sharing the Android SDK?", isPresented: $confirmUnshare) {
            Button("Stop Sharing", role: .destructive) { Task { await android.unshare() } }
        } message: {
            Text("The sandbox loses ANDROID_HOME and the SDK copy. Its devices stay.")
        }
    }

    @ViewBuilder
    private func devices(_ status: AndroidStatus) -> some View {
        ForEach(status.sandboxDevices) { device in
            LabeledContent {
                Button("Remove") { Task { await android.removeDevice(device) } }
                    .disabled(android.isBusy)
            } label: {
                Text(device.displayName ?? device.name)
                Text("In the sandbox · \(device.systemImage ?? "unknown system image")")
            }
        }
        ForEach(status.importableDevices) { device in
            LabeledContent {
                Button("Add to Sandbox") { Task { await android.importDevice(device) } }
                    .disabled(android.isBusy || !device.imageShared)
                    .help(device.imageShared ? "Copies the settings, not the data." : "Its system image is not in the copy yet. Update the copy first.")
            } label: {
                Text(device.displayName ?? device.name)
                Text("On this Mac · \(device.systemImage ?? "unknown system image")")
            }
        }
        if status.sandboxDevices.isEmpty && status.importableDevices.isEmpty {
            Text("No virtual devices on this Mac. Create one in Android Studio's Device Manager, then add it here.")
                .foregroundStyle(.secondary)
        }
    }
}
