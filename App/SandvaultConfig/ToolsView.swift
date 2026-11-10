import SandvaultAppModel
import SandvaultCore
import SwiftUI

struct ToolsView: View {
    @Bindable var tools: ToolsModel
    @Bindable var android: AndroidModel
    @Bindable var programs: ProgramsModel

    var body: some View {
        VStack(spacing: 0) {
            MessageArea(message: tools.message) { tools.message = nil }
            MessageArea(message: android.message) { android.message = nil }
            MessageArea(message: programs.message) { programs.message = nil }
            Form {
                if case .notAvailableYet(let note) = tools.availability {
                    Section {
                        NotAvailableView(title: "Tool checks are not available yet", note: note)
                    }
                }
                Section {
                    HStack {
                        TextField("Command", text: $tools.query, prompt: Text("Command name or path, e.g. jq"))
                            .labelsHidden()
                            .onSubmit { Task { await tools.check() } }
                        Button("Check") { Task { await tools.check() } }
                            .disabled(tools.query.isEmpty || tools.isBusy)
                    }
                    if tools.isBusy {
                        ProgressView()
                            .controlSize(.small)
                    }
                    if let status = tools.status {
                        ToolStatusView(status: status) { method in
                            Task { await tools.grant(method) }
                        }
                    }
                } header: {
                    Text("Check a command")
                } footer: {
                    Text("Use this when an agent says a program is missing.")
                }
                Section {
                    if tools.grants.isEmpty {
                        Text("Nothing granted yet.")
                            .foregroundStyle(.secondary)
                    }
                    ForEach(tools.grants) { grant in
                        LabeledContent {
                            Text(verbatim: grant.source)
                        } label: {
                            Text(verbatim: grant.name)
                            Text(grant.method.displayName)
                        }
                    }
                } header: {
                    Text("Granted")
                } footer: {
                    Text("Programs you made available to the sandbox.")
                }
                ProgramsSection(programs: programs)
                AndroidSection(android: android)
            }
            .formStyle(.grouped)
        }
        .navigationTitle(Screen.tools.title)
        .navigationSubtitle("Apps and commands in the sandbox")
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

/// Custom programs (D54): a host program with its helpers, files and loopback ports, started like an agent.
struct ProgramsSection: View {
    @Bindable var programs: ProgramsModel
    @State private var removing: CustomProgram?

    var body: some View {
        Section {
            if case .notAvailableYet(let note) = programs.availability {
                Text(note).foregroundStyle(.secondary)
            }
            HStack {
                TextField("Program", text: $programs.query, prompt: Text("Command name or path, e.g. claude-lm or ~/.local/bin/claude-lm"))
                    .labelsHidden()
                    .onSubmit { Task { await programs.suggest() } }
                Button("Look at It") { Task { await programs.suggest() } }
                    .disabled(programs.query.isEmpty || programs.isBusy)
            }
            ForEach(programs.programs) { program in
                LabeledContent {
                    HStack {
                        Button("Edit") { programs.edit(program) }
                        Button("Remove…") { removing = program }
                    }
                    .disabled(programs.isBusy)
                } label: {
                    Text(verbatim: program.name)
                    Text(program.migratedAt == nil ? "Not ready yet" : "Ready · start it from Sandbox or Projects")
                }
            }
            if let draft = programs.draft {
                editor(draft)
            }
        } header: {
            Text("Your own programs")
        } footer: {
            Text("For programs and agents sv does not know, like a script that runs Claude Code against LM Studio. The program, the commands it calls and the files it needs are copied in, and the ports on this Mac it talks to are opened.")
        }
        .confirmationDialog("Remove \(removing?.name ?? "")?", isPresented: Binding(get: { removing != nil }, set: { if !$0 { removing = nil } })) {
            Button("Remove", role: .destructive) {
                if let program = removing { Task { await programs.remove(program) } }
            }
        } message: {
            Text("Its files and ports are removed. Commands it calls stay available.")
        }
    }

    @ViewBuilder
    private func editor(_ draft: CustomProgram) -> some View {
        Text(verbatim: draft.name).font(.headline)
        TextField("Commands it calls", text: Binding(get: { draft.dependencies.joined(separator: " ") }, set: programs.setDependencies),
                  prompt: Text("jq fzf"))
        TextField("Ports on this Mac", text: Binding(get: { draft.hostPorts.map(String.init).joined(separator: " ") }, set: programs.setPorts),
                  prompt: Text("1234"))
        TextField("Files from your home folder", text: Binding(get: { draft.files.joined(separator: "\n") }, set: programs.setFiles),
                  prompt: Text(".config/tool/settings.json"), axis: .vertical)
            .lineLimit(1...6)
        ForEach(draft.files, id: \.self) { file in
            Toggle(isOn: Binding(get: { draft.allowedSecrets.contains(file) }, set: { programs.allowSecret(file, $0) })) {
                Text(verbatim: file)
                Text("Allow even if it looks like a password or key. The sandbox can then read it.")
            }
        }
        Toggle("A project task is its first prompt", isOn: Binding(get: { draft.takesPrompt }, set: { programs.draft?.takesPrompt = $0 }))
        HStack {
            if programs.isBusy { ProgressView().controlSize(.small) }
            Spacer()
            Button("Cancel") { programs.draft = nil }
            Button("Bring into Sandbox") { Task { await programs.migrate() } }
                .buttonStyle(.borderedProminent)
                .disabled(programs.isBusy)
        }
        if let report = programs.report {
            ForEach(report.steps, id: \.self) { step in
                Label {
                    Text(verbatim: "\(step.subject): \(step.detail)")
                } icon: {
                    Image(systemName: step.done ? "checkmark.circle.fill" : "xmark.circle")
                }
                .foregroundStyle(step.done ? Color.green : Color.orange)
                .font(.callout)
                .textSelection(.enabled)
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
                        Button("Stop Sharing…") { confirmUnshare = true }
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
