import SandvaultAppModel
import SandvaultCore
import SwiftUI

struct OverviewView: View {
    let model: AppModel

    private var expert: Bool { model.settings.preferences.expertMode }

    var body: some View {
        VStack(spacing: 0) {
            MessageArea(message: model.firewall.message) { model.firewall.message = nil }
            Form {
                Section("Protection") {
                    ProtectionPicker(firewall: model.firewall, netdRunning: model.netd.isConnected)
                }
                if expert || !model.overview.nextStep.isDone {
                    Section("Next step") {
                        NextStepView(step: model.overview.nextStep) { screen in model.select(screen) }
                    }
                }
                Section("Now") {
                    LabeledContent("Sessions", value: String(model.processes.sessionCount))
                    LabeledContent("Sandbox processes", value: String(model.processes.processCount))
                    if expert {
                        LabeledContent("Firewall", value: model.editor.config.network.mode.displayName)
                        LabeledContent("sandvault-netd", value: model.netd.isConnected ? "running" : "not running")
                        LabeledContent("Listening ports", value: listeningPorts)
                    }
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
                if !expert {
                    RecentActivitySection(activity: model.activity) { model.select(.activity) }
                }
                if expert {
                    ForEach(model.overview.sections) { section in
                        Section(section.title) {
                            ForEach(section.checks) { check in
                                CheckRow(check: check)
                            }
                        }
                    }
                }
            }
            .formStyle(.grouped)
        }
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

/// The four protection levels; choosing one saves and applies it at once.
struct ProtectionPicker: View {
    let firewall: FirewallModel
    let netdRunning: Bool

    var body: some View {
        Picker("Protection", selection: level) {
            ForEach(ProtectionLevel.allCases) { level in
                Text(level.title).tag(Optional(level))
            }
        }
        .pickerStyle(.segmented)
        .labelsHidden()
        .disabled(firewall.isBusy)
        if let current = firewall.protection {
            Text(current.explanation)
                .font(.callout)
                .foregroundStyle(.secondary)
            if firewall.network.mode.needsNetd && !netdRunning {
                Label("sandvault-netd is not running, so the sandbox has no web access. Install it in Settings.", systemImage: "exclamationmark.triangle")
                    .foregroundStyle(.orange)
            }
        } else {
            Text("Custom settings from expert mode: \(firewall.network.mode.displayName). Choosing a level replaces them.")
                .font(.callout)
                .foregroundStyle(.secondary)
        }
    }

    private var level: Binding<ProtectionLevel?> {
        Binding<ProtectionLevel?>(
            get: { firewall.protection },
            set: { level in
                if let level { Task { await firewall.setProtection(level) } }
            }
        )
    }
}

/// The newest few activity lines with a link to the whole list.
struct RecentActivitySection: View {
    let activity: ActivityModel
    let showAll: () -> Void

    var body: some View {
        Section("Recent activity") {
            let items = activity.items
            if items.isEmpty {
                Text("Nothing yet.")
                    .foregroundStyle(.secondary)
            }
            ForEach(items.prefix(5)) { item in
                ActivityRow(item: item, activity: activity)
            }
            if let hint = activity.hint {
                Text(hint)
                    .font(.caption)
                    .foregroundStyle(.secondary)
            }
            Button("Show All Activity", action: showAll)
        }
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
