import Foundation
import SandvaultAppModel
import SandvaultCore
import SwiftUI

/// Repos & Hand-off. A folder dropped anywhere on the page is checked and offered for hand-off.
struct HandoffView: View {
    let model: AppModel

    var body: some View {
        HandoffPage(handoff: model.handoff, repos: model.repos) {
            if let path = FolderPicker.chooseRepository() {
                Task { await model.handoff.select(path) }
            }
        }
        .dropDestination(for: URL.self) { urls, _ in
            model.handOff(paths: urls.map(\.path))
        }
        .navigationTitle(Screen.handoff.title)
    }
}

struct HandoffPage: View {
    @Bindable var handoff: HandoffModel
    let repos: ReposModel
    let choose: () -> Void

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
                Section("Hand off a repository") {
                    HStack {
                        Text(handoff.source ?? "Drop a repository folder here, or choose one.")
                            .foregroundStyle(handoff.source == nil ? Color.secondary : Color.primary)
                            .textSelection(.enabled)
                        Spacer()
                        Button("Choose…", action: choose)
                    }
                    if handoff.isChecking {
                        ProgressView()
                            .controlSize(.small)
                    }
                    if let readiness = handoff.readiness {
                        ReadinessView(report: readiness)
                    }
                    Picker("Agent", selection: $handoff.agent) {
                        ForEach(AgentKind.allCases, id: \.self) { agent in
                            Text(agent.displayName).tag(agent)
                        }
                    }
                    TextField("Task for the agent (optional)", text: $handoff.task, axis: .vertical)
                        .lineLimit(3...8)
                    Toggle("Include uncommitted changes", isOn: $handoff.includeUncommitted)
                    Picker("Deploy key", selection: $handoff.deployKey) {
                        ForEach(HandoffRequest.DeployKeyMode.allCases, id: \.self) { mode in
                            Text(mode.displayName).tag(mode)
                        }
                    }
                    LabeledContent("Terminal", value: handoff.terminal.displayName)
                    HStack {
                        if let reason = handoff.disabledReason {
                            Text(reason)
                                .foregroundStyle(.secondary)
                        }
                        Spacer()
                        Button("Hand Off") { Task { await handoff.handOff() } }
                            .disabled(!handoff.canHandOff)
                    }
                    if let result = handoff.lastResult {
                        Text(result.command.joined(separator: " "))
                            .font(.system(.caption, design: .monospaced))
                            .textSelection(.enabled)
                    }
                }
                Section("Repositories in the sandbox") {
                    ReposList(repos: repos)
                }
            }
            .formStyle(.grouped)
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

    var body: some View {
        if case .notAvailableYet(let note) = repos.availability {
            Text(note)
                .foregroundStyle(.secondary)
        } else if repos.repositories.isEmpty {
            Text(verbatim: repos.isLoading ? "Loading…" : "No repositories in the shared workspace.")
                .foregroundStyle(.secondary)
        }
        ForEach(repos.repositories) { repo in
            HStack {
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
                    .help("git fetch sandvault in the host repository")
            }
        }
        HStack {
            Spacer()
            Button("Refresh") { Task { await repos.refresh() } }
                .disabled(repos.isLoading)
        }
    }
}
