import SandvaultAppModel
import SandvaultCore
import SwiftUI

/// Start a shell or an agent, and create, rebuild or delete the sandbox. sv runs in the terminal from Settings.
struct SandboxView: View {
    let model: AppModel
    @State private var confirmDelete = false

    var body: some View {
        let sandbox = model.sandbox
        VStack(spacing: 0) {
            MessageArea(message: sandbox.message) { sandbox.message = nil }
            Form {
                Section("Status") {
                    LabeledContent("Sandbox", value: sandbox.summary)
                    LabeledContent("Account", value: sandbox.environment.sandvaultUser)
                    LabeledContent("Shared workspace", value: sandbox.environment.sharedWorkspace)
                    LabeledContent("Terminal", value: model.editor.config.handoff.terminal.displayName)
                }
                if sandbox.installed {
                    StartSection(sandbox: sandbox, repos: model.repos, defaultAgent: model.editor.config.handoff.defaultAgent)
                }
                ManageSection(sandbox: sandbox, confirmDelete: $confirmDelete)
            }
            .formStyle(.grouped)
        }
        .navigationTitle(Screen.sandbox.title)
        .confirmationDialog("Delete the sandbox?", isPresented: $confirmDelete) {
            Button("Delete Sandbox", role: .destructive) { Task { await sandbox.delete() } }
        } message: {
            Text(sandbox.deleteExplanation)
        }
    }
}

struct StartSection: View {
    @Bindable var sandbox: SandboxModel
    let repos: ReposModel
    let defaultAgent: AgentKind

    var body: some View {
        Section("Start") {
            Picker("Start in", selection: $sandbox.startDirectory) {
                Text("Shared workspace").tag(String?.none)
                ForEach(repos.repositories) { repo in
                    Text(repo.name).tag(Optional(repo.sandboxPath))
                }
            }
            HStack {
                Menu("Other Agent") {
                    ForEach(AgentKind.allCases.filter { $0 != .shell && $0 != defaultAgent }, id: \.self) { agent in
                        Button(agent.displayName) { Task { await sandbox.open(agent) } }
                    }
                }
                .fixedSize()
                Spacer()
                Button("Open Shell") { Task { await sandbox.open(.shell) } }
                if defaultAgent != .shell {
                    Button("Start \(defaultAgent.displayName)") { Task { await sandbox.open(defaultAgent) } }
                        .buttonStyle(.borderedProminent)
                }
            }
            .disabled(sandbox.isBusy)
        }
    }
}

struct ManageSection: View {
    @Bindable var sandbox: SandboxModel
    @Binding var confirmDelete: Bool

    var body: some View {
        Section("Manage") {
            if sandbox.installed {
                Text("Rebuild repairs sv's configuration and file permissions, then writes the sandbox rules and the firewall again.")
                    .font(.callout)
                    .foregroundStyle(.secondary)
                HStack {
                    Button("Delete Sandbox…", role: .destructive) { confirmDelete = true }
                    Spacer()
                    Button("Rebuild") { Task { await sandbox.rebuild() } }
                }
                .disabled(sandbox.isBusy)
            } else {
                Picker("Preset", selection: $sandbox.setup) {
                    ForEach(SandboxSetup.allCases) { setup in
                        Text(setup.title).tag(setup)
                    }
                }
                Text(sandbox.setup.explanation)
                    .font(.callout)
                    .foregroundStyle(.secondary)
                HStack {
                    Spacer()
                    Button("Create Sandbox") { Task { await sandbox.create() } }
                        .buttonStyle(.borderedProminent)
                        .disabled(sandbox.isBusy)
                }
            }
            Text("sv runs in a terminal window and asks for your administrator password there.")
                .font(.caption)
                .foregroundStyle(.secondary)
        }
    }
}
