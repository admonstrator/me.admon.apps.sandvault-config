import Foundation
import SandvaultAppModel
import SandvaultCore
import SwiftUI

/// Projects: a folder dropped anywhere on the page, chosen or given as a URL is checked and offered for hand-off;
/// below, the repositories already in the sandbox with Fetch Back.
struct HandoffView: View {
    let model: AppModel

    var body: some View {
        HandoffPage(handoff: model.handoff, repos: model.repos, mode: model.mode) {
            if let path = FolderPicker.chooseRepository() {
                Task { await model.handoff.select(path) }
            }
        }
        .dropDestination(for: URL.self) { urls, _ in
            model.handOff(paths: urls.map(\.path))
        }
        .navigationTitle(Screen.handoff.title)
        .task(id: model.mode) {
            // Easy hides the Linux VM target and the sv options, so it hands off with their defaults.
            guard model.mode == .easy else { return }
            model.handoff.includeUncommitted = false
            model.handoff.deployKey = HandoffRequest.DeployKeyMode.none
            if model.handoff.target != .sandvault { await model.handoff.choose(.sandvault) }
        }
    }
}

struct HandoffPage: View {
    @Bindable var handoff: HandoffModel
    let repos: ReposModel
    var mode: InterfaceMode = .expert
    let choose: () -> Void
    @State private var url = ""

    var body: some View {
        VStack(spacing: 0) {
            MessageArea(message: handoff.message) { handoff.message = nil }
            MessageArea(message: repos.message) { repos.message = nil }
            Form {
                if case .notAvailableYet(let note) = handoff.availability {
                    Section {
                        NotAvailableView(title: "Hand-off is not available yet", note: note)
                    }
                }
                if let source = handoff.source {
                    chosen(source)
                    if mode >= .advanced && handoff.offersDocker {
                        runIn
                    }
                    agentSection
                } else {
                    Section {
                        DropZone(url: $url, choose: choose) {
                            Task { await handoff.select(url: url) }
                        }
                    }
                }
                Section {
                    ReposList(repos: repos)
                } header: {
                    Text("In the sandbox")
                } footer: {
                    Text("When the agent is done, Fetch Back brings its commits into your own copy as a branch. Nothing is overwritten.")
                }
            }
            .formStyle(.grouped)
        }
    }

    /// The chosen folder with its checks.
    @ViewBuilder
    private func chosen(_ source: String) -> some View {
        Section("Project") {
            LabeledContent {
                HStack {
                    Button("Change…", action: choose)
                    Button("Clear") {
                        handoff.clear()
                        url = ""
                    }
                }
            } label: {
                Text(verbatim: (source as NSString).lastPathComponent)
                Text(verbatim: source)
            }
            if handoff.isChecking {
                ProgressView("Checking…")
                    .controlSize(.small)
            }
            if let readiness = handoff.readiness {
                ReadinessView(report: readiness)
            }
        }
    }

    /// sv's macOS user or a Docker Sandboxes Linux VM (Advanced and up, only with `sbx` installed).
    private var runIn: some View {
        Section("Run in") {
            Picker("Run in", selection: target) {
                ForEach(HandoffTarget.allCases, id: \.self) { target in
                    Text(target.displayName).tag(target)
                }
            }
            .pickerStyle(.radioGroup)
            .labelsHidden()
            Text(handoff.target.explanation)
                .font(.caption)
                .foregroundStyle(.secondary)
        }
    }

    private var agentSection: some View {
        Section {
            Picker("Agent", selection: $handoff.agent) {
                ForEach(handoff.agents, id: \.self) { agent in
                    Text(agent.displayName).tag(agent)
                }
            }
            TextField("Task for the agent (optional)", text: $handoff.task, prompt: Text("Fix the failing tests"), axis: .vertical)
                .lineLimit(2...8)
            if mode >= .advanced && handoff.target == .sandvault {
                Toggle("Include uncommitted changes", isOn: $handoff.includeUncommitted)
                Picker("Deploy key", selection: $handoff.deployKey) {
                    ForEach(HandoffRequest.DeployKeyMode.allCases, id: \.self) { key in
                        Text(key.displayName).tag(key)
                    }
                }
            }
            HStack {
                Text(handoff.disabledReason ?? "Opens in \(handoff.terminal.displayName)")
                    .foregroundStyle(.secondary)
                Spacer()
                Button("Hand Off") { Task { await handoff.handOff() } }
                    .buttonStyle(.borderedProminent)
                    .disabled(!handoff.canHandOff)
            }
            if mode == .expert, let result = handoff.lastResult {
                Text(result.shellLine)
                    .font(.system(.caption, design: .monospaced))
                    .textSelection(.enabled)
            }
        } header: {
            Text("Agent")
        } footer: {
            Text("The code is copied into the sandbox. Your own folder stays as it is.")
        }
    }

    private var target: Binding<HandoffTarget> {
        Binding(get: { handoff.target }, set: { target in Task { await handoff.choose(target) } })
    }
}

/// The empty state: drop a folder, choose one, or paste a repository URL.
private struct DropZone: View {
    @Binding var url: String
    let choose: () -> Void
    let useURL: () -> Void

    var body: some View {
        VStack(spacing: 10) {
            Image(systemName: "tray.and.arrow.down")
                .font(.system(size: 30, weight: .light))
                .foregroundStyle(.secondary)
            Text("Drop a project folder here")
                .font(.headline)
            Text("The code is copied into the sandbox. Your own folder stays untouched until you fetch the work back.")
                .font(.callout)
                .foregroundStyle(.secondary)
                .multilineTextAlignment(.center)
            Button("Choose Folder…", action: choose)
                .buttonStyle(.borderedProminent)
            HStack {
                TextField("Repository URL", text: $url, prompt: Text("Or paste a repository URL"))
                    .labelsHidden()
                    .onSubmit(useURL)
                Button("Use URL", action: useURL)
                    .disabled(url.trimmingCharacters(in: .whitespaces).isEmpty)
            }
            .frame(maxWidth: 420)
        }
        .frame(maxWidth: .infinity)
        .padding(.vertical, 18)
        .padding(.horizontal, 12)
        .overlay {
            RoundedRectangle(cornerRadius: 12, style: .continuous)
                .strokeBorder(Color.secondary.opacity(0.4), style: StrokeStyle(lineWidth: 1.5, dash: [6, 4]))
        }
    }
}

struct ReadinessView: View {
    let report: ReadinessReport

    var body: some View {
        if report.findings.isEmpty {
            Label("Ready: nothing blocks the hand-off.", systemImage: "checkmark.circle.fill")
                .foregroundStyle(.green)
        }
        ForEach(Array(report.findings.enumerated()), id: \.offset) { item in
            FindingRow(finding: item.element)
        }
    }
}

struct FindingRow: View {
    let finding: ReadinessFinding

    var body: some View {
        HStack(alignment: .top, spacing: 8) {
            Image(systemName: finding.severity.symbolName)
                .foregroundStyle(finding.severity.tint.color)
            VStack(alignment: .leading, spacing: 2) {
                Text(finding.message)
                if let path = finding.path {
                    Text(path)
                        .font(.system(.caption, design: .monospaced))
                        .foregroundStyle(.secondary)
                }
            }
        }
    }
}

struct ReposList: View {
    let repos: ReposModel

    private func fetchHelp(_ repo: RepoStatus) -> String {
        let remote = repo.record?.dockerSandbox.map { "sandbox-" + $0 } ?? "sandvault"
        return "git fetch " + remote + " in the host repository"
    }

    var body: some View {
        if case .notAvailableYet(let note) = repos.availability {
            Text(note)
                .foregroundStyle(.secondary)
        } else if repos.repositories.isEmpty {
            Text(verbatim: repos.isLoading ? "Loading…" : "No projects in the sandbox yet.")
                .foregroundStyle(.secondary)
        }
        ForEach(repos.repositories) { repo in
            HStack {
                Image(systemName: repo.record?.dockerSandbox == nil ? "arrow.triangle.branch" : "cpu")
                    .foregroundStyle(.secondary)
                    .frame(width: 18)
                VStack(alignment: .leading, spacing: 2) {
                    Text(repo.name)
                        .fontWeight(.medium)
                    Text(repo.summary)
                        .font(.caption)
                        .foregroundStyle(.secondary)
                }
                Spacer()
                Button("Fetch Back") { Task { await repos.fetchBack(repo) } }
                    .disabled(repo.record == nil || repos.fetching.contains(repo.id))
                    .help(fetchHelp(repo))
            }
        }
        HStack {
            Spacer()
            Button("Refresh") { Task { await repos.refresh() } }
                .disabled(repos.isLoading)
        }
    }
}
