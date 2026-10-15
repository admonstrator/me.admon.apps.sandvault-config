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
            MessageArea(message: model.docker.message) { model.docker.message = nil }
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
                if model.docker.installed {
                    DockerSandboxesSection(docker: model.docker, home: sandbox.environment.hostHome)
                }
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
                ForEach(repos.repositories.filter { $0.record?.dockerSandbox == nil }) { repo in
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

/// Docker Sandboxes VMs (D47), shown only when `sbx` is installed.
struct DockerSandboxesSection: View {
    let docker: DockerSandboxesModel
    let home: String
    @State private var deleting: DockerSandbox?

    var body: some View {
        Section("Linux VMs (Docker Sandboxes)") {
            if docker.state.sshAgentForwarding == true {
                Label("Your SSH agent is forwarded into every VM. Turn it off with: sbx settings set ssh.agentForwardingEnabled false",
                      systemImage: "exclamationmark.triangle.fill")
                    .foregroundStyle(.orange)
                    .textSelection(.enabled)
            }
            if let problem = docker.state.problem {
                Text(problem)
                    .foregroundStyle(.secondary)
            } else if docker.state.sandboxes.isEmpty {
                Text(verbatim: docker.isLoading ? "Loading…" : "No VMs. Hand off a repository to a Linux VM under Repos & Hand-off.")
                    .foregroundStyle(.secondary)
            }
            ForEach(docker.state.sandboxes) { sandbox in
                HStack {
                    VStack(alignment: .leading, spacing: 2) {
                        Text(sandbox.name)
                            .fontWeight(.medium)
                        Text(sandbox.summary(home: home))
                            .font(.caption)
                            .foregroundStyle(.secondary)
                        if sandbox.mountsHome(home) {
                            Label("Sees your whole home folder, SSH keys included", systemImage: "exclamationmark.triangle.fill")
                                .font(.caption)
                                .foregroundStyle(.orange)
                        }
                    }
                    Spacer()
                    Button("Delete…", role: .destructive) { deleting = sandbox }
                    if sandbox.isRunning {
                        Button("Stop") { Task { await docker.stop(sandbox) } }
                    }
                    Button("Open") { Task { await docker.open(sandbox) } }
                }
                .disabled(docker.busy.contains(sandbox.name))
            }
            HStack {
                Spacer()
                Button("Refresh") { Task { await docker.refresh() } }
                    .disabled(docker.isLoading)
            }
        }
        .confirmationDialog("Delete \(deleting?.name ?? "")?", isPresented: isDeleting, presenting: deleting) { sandbox in
            Button("Delete VM", role: .destructive) { Task { await docker.remove(sandbox) } }
        } message: { sandbox in
            Text(docker.deleteExplanation(sandbox))
        }
    }

    private var isDeleting: Binding<Bool> {
        Binding(get: { deleting != nil }, set: { if !$0 { deleting = nil } })
    }
}
