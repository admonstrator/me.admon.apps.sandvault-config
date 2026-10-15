import SandvaultAppModel
import SandvaultCore
import SwiftUI

/// Start a shell or an agent, choose the preset, rebuild or delete the sandbox, and the Docker Sandboxes VMs.
/// sv runs in the terminal from Settings.
struct SandboxView: View {
    let model: AppModel
    @State private var confirmDelete = false
    @State private var pendingPreset: SandboxSetup?

    var body: some View {
        let sandbox = model.sandbox
        VStack(spacing: 0) {
            MessageArea(message: sandbox.message) { sandbox.message = nil }
            MessageArea(message: model.rules.message) { model.rules.message = nil }
            MessageArea(message: model.firewall.message) { model.firewall.message = nil }
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
                PresetSection(
                    sandbox: sandbox, choices: SandboxSetup.choices(for: model.mode), current: currentPreset,
                    busy: sandbox.isBusy || model.rules.isBusy || model.firewall.isBusy
                ) { setup in
                    pendingPreset = setup
                }
                ManageSection(sandbox: sandbox, confirmDelete: $confirmDelete)
                if model.docker.installed {
                    DockerSandboxesSection(docker: model.docker, home: sandbox.environment.hostHome)
                }
            }
            .formStyle(.grouped)
        }
        .navigationTitle(Screen.sandbox.title)
        .navigationSubtitle(sandbox.environment.sandvaultUser)
        .confirmationDialog("Delete the sandbox?", isPresented: $confirmDelete) {
            Button("Delete Sandbox", role: .destructive) { Task { await sandbox.delete() } }
        } message: {
            Text(sandbox.deleteExplanation)
        }
        .confirmationDialog(
            "Switch to \(pendingPreset?.title ?? "")?", isPresented: isSwitching, presenting: pendingPreset
        ) { setup in
            Button("Switch to \(setup.title)") { Task { await apply(setup) } }
        } message: { setup in
            Text("\(setup.explanation) The sandbox rules and the protection level are applied now; new sessions get the new rules.")
        }
    }

    /// The preset whose rules and protection level the configuration has; `nil` for anything else.
    private var currentPreset: SandboxSetup? {
        let rules = model.editor.config.sandbox.preset
        let protection = model.firewall.protection
        return SandboxSetup.allCases.first { $0.rules == rules && $0.protection == protection }
    }

    private var isSwitching: Binding<Bool> {
        Binding(get: { pendingPreset != nil }, set: { if !$0 { pendingPreset = nil } })
    }

    /// An existing sandbox takes the preset's rules (applied through the helper) and its protection level.
    private func apply(_ setup: SandboxSetup) async {
        model.sandbox.setup = setup
        await model.rules.setPreset(setup.rules)
        await model.rules.apply()
        await model.firewall.setProtection(setup.protection)
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

/// The presets of the mode. Without a sandbox, the one Create uses; with one, choosing a preset asks first, then
/// applies its rules and protection level.
struct PresetSection: View {
    @Bindable var sandbox: SandboxModel
    let choices: [SandboxSetup]
    let current: SandboxSetup?
    let busy: Bool
    let switchTo: (SandboxSetup) -> Void

    var body: some View {
        Section {
            ForEach(choices) { setup in
                let selected = sandbox.installed ? current == setup : sandbox.setup == setup
                Button {
                    if sandbox.installed {
                        if current != setup { switchTo(setup) }
                    } else {
                        sandbox.setup = setup
                    }
                } label: {
                    HStack(spacing: 10) {
                        Image(systemName: setup.presetSymbol)
                            .font(.title3)
                            .foregroundStyle(setup.presetColor)
                            .frame(width: 24)
                        VStack(alignment: .leading, spacing: 2) {
                            Text(setup.title)
                                .fontWeight(.medium)
                            Text(setup.explanation)
                                .font(.caption)
                                .foregroundStyle(.secondary)
                                .fixedSize(horizontal: false, vertical: true)
                        }
                        Spacer(minLength: 8)
                        if selected {
                            Image(systemName: "checkmark")
                                .foregroundStyle(Color.accentColor)
                                .fontWeight(.semibold)
                        }
                    }
                    .contentShape(Rectangle())
                }
                .buttonStyle(.plain)
                .disabled(busy)
                .accessibilityAddTraits(selected ? .isSelected : [])
            }
            if sandbox.installed && current == nil {
                Text("Your rules or protection level match no preset. Choosing one replaces them.")
                    .font(.caption)
                    .foregroundStyle(.secondary)
            }
        } header: {
            Text("Preset")
        } footer: {
            Text("A preset sets the sandbox rules and the protection level together.")
        }
    }
}

extension SandboxSetup {
    fileprivate var presetSymbol: String {
        switch self {
        case .everyday: "eye"
        case .careful: "checkmark.shield"
        case .offline: "hand.raised"
        case .unrestricted: "lock.open"
        }
    }

    fileprivate var presetColor: Color {
        switch self {
        case .everyday: .blue
        case .careful: .green
        case .offline: .secondary
        case .unrestricted: .orange
        }
    }
}

struct ManageSection: View {
    @Bindable var sandbox: SandboxModel
    @Binding var confirmDelete: Bool

    var body: some View {
        Section("Manage") {
            if sandbox.installed {
                LabeledContent {
                    Button("Rebuild") { Task { await sandbox.rebuild() } }
                } label: {
                    Text("Rebuild")
                    Text("Repairs sv's configuration and file permissions, then writes the sandbox rules and the firewall again.")
                }
                LabeledContent {
                    Button("Delete…", role: .destructive) { confirmDelete = true }
                } label: {
                    Text("Delete Sandbox")
                    Text("Removes the sandbox user and its home. The shared workspace stays.")
                }
            } else {
                HStack {
                    Text("Creates the sandbox with the preset above.")
                        .foregroundStyle(.secondary)
                    Spacer()
                    Button("Create Sandbox") { Task { await sandbox.create() } }
                        .buttonStyle(.borderedProminent)
                }
            }
            Text("sv runs in a terminal window and asks for your administrator password there.")
                .font(.caption)
                .foregroundStyle(.secondary)
        }
        .disabled(sandbox.isBusy)
    }
}

/// Docker Sandboxes VMs (D47), shown only when `sbx` is installed.
struct DockerSandboxesSection: View {
    let docker: DockerSandboxesModel
    let home: String
    @State private var deleting: DockerSandbox?

    var body: some View {
        Section {
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
                Text(verbatim: docker.isLoading ? "Loading…" : "No VMs yet.")
                    .foregroundStyle(.secondary)
            }
            ForEach(docker.state.sandboxes) { sandbox in
                HStack {
                    Image(systemName: "cpu")
                        .foregroundStyle(.teal)
                        .frame(width: 18)
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
        } header: {
            Text("Linux VMs (Docker Sandboxes)")
        } footer: {
            Text("Hand a project to a Linux VM under Projects.")
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
