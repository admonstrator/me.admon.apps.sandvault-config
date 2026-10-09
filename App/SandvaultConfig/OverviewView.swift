import SandvaultAppModel
import SandvaultCore
import SwiftUI

struct OverviewView: View {
    let model: AppModel

    var body: some View {
        Form {
            Section("Next step") {
                NextStepView(step: model.overview.nextStep) { screen in model.select(screen) }
            }
            Section("Now") {
                LabeledContent("Firewall", value: model.editor.config.network.mode.displayName)
                LabeledContent("sandvault-netd", value: model.netd.isConnected ? "running" : "not running")
                LabeledContent("Sessions", value: String(model.processes.sessionCount))
                LabeledContent("Sandbox processes", value: String(model.processes.processCount))
                LabeledContent("Listening ports", value: listeningPorts)
                if let errors = model.overview.summary?.errors, !errors.isEmpty {
                    Text(errors.joined(separator: "\n"))
                        .font(.caption)
                        .foregroundStyle(.secondary)
                }
            }
            if !model.overview.sessions.isEmpty {
                Section("Sessions") {
                    ForEach(model.overview.sessions) { session in
                        SessionRow(session: session)
                    }
                }
            }
            ForEach(model.overview.sections) { section in
                Section(section.title) {
                    ForEach(section.checks) { check in
                        CheckRow(check: check)
                    }
                }
            }
        }
        .formStyle(.grouped)
        .navigationTitle(Screen.overview.title)
        .toolbar {
            Button {
                Task { await model.overview.refresh() }
            } label: {
                Label("Refresh", systemImage: "arrow.clockwise")
            }
            .disabled(model.overview.isRefreshing)
        }
    }

    private var listeningPorts: String {
        let ports = model.overview.summary?.listeningPorts ?? []
        return ports.isEmpty ? "none" : ports.map(String.init).joined(separator: ", ")
    }
}

struct NextStepView: View {
    let step: SetupStep
    let open: (Screen) -> Void

    var body: some View {
        VStack(alignment: .leading, spacing: 6) {
            Label(step.title, systemImage: step.isDone ? "checkmark.seal.fill" : "arrow.right.circle.fill")
                .font(.headline)
                .foregroundStyle(step.isDone ? Color.green : Color.accentColor)
            Text(step.detail)
                .foregroundStyle(.secondary)
            if let command = step.suggestedCommand {
                Text(command)
                    .font(.system(.body, design: .monospaced))
                    .textSelection(.enabled)
            }
            if let screen = step.screen {
                Button("Open \(screen.title)") { open(screen) }
            }
        }
        .padding(.vertical, 4)
    }
}

struct SessionRow: View {
    let session: SandboxSession

    var body: some View {
        HStack {
            Text(session.command)
                .fontWeight(.medium)
            Text(Format.shortSession(session.id))
                .font(.system(.body, design: .monospaced))
                .foregroundStyle(.secondary)
            Spacer()
            Text(verbatim: "\(session.processCount) processes · \(Format.duration(session.elapsedSeconds))")
                .foregroundStyle(.secondary)
        }
    }
}
