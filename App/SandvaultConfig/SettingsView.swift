import SandvaultAppModel
import SandvaultCore
import SwiftUI

struct SettingsView: View {
    let settings: SettingsModel
    let netd: NetdLink
    let setExpertMode: @MainActor (Bool) -> Void

    var body: some View {
        VStack(spacing: 0) {
            MessageArea(message: settings.message) { settings.message = nil }
            Form {
                HelperSection(settings: settings)
                NetdSection(settings: settings, netd: netd)
                HandoffDefaultsSection(settings: settings)
                AppSection(settings: settings, setExpertMode: setExpertMode)
            }
            .formStyle(.grouped)
        }
        .navigationTitle(Screen.settings.title)
    }
}

struct HelperSection: View {
    let settings: SettingsModel

    private var installTitle: String {
        settings.helperInstalled ? "Reinstall…" : "Install…"
    }

    private var status: String {
        settings.helperInstalled ? "installed at \(AppPaths.helperPath)" : "not installed"
    }

    var body: some View {
        Section("Privileged helper") {
            LabeledContent("Status", value: status)
            Text("Rules and the firewall take effect through a root helper with an argument-exact sudoers rule. Installing and removing it asks for an administrator password.")
                .font(.callout)
                .foregroundStyle(.secondary)
            HStack {
                Spacer()
                Button("Uninstall…") { Task { await settings.uninstallHelper() } }
                    .disabled(!settings.helperInstalled || settings.isBusy)
                Button(installTitle) { Task { await settings.installHelper() } }
                    .disabled(settings.bundled.helper == nil || settings.isBusy)
            }
        }
    }
}

struct NetdSection: View {
    let settings: SettingsModel
    let netd: NetdLink

    var body: some View {
        Section("sandvault-netd") {
            LabeledContent("LaunchAgent", value: settings.netdAgentSummary)
            LabeledContent("Control socket", value: netd.summary)
            if settings.netdExecutableMismatch {
                Label("The LaunchAgent runs a different sandvault-netd than this app; install it again.", systemImage: "exclamationmark.triangle")
                    .foregroundStyle(.orange)
            }
            HStack {
                Spacer()
                Button("Uninstall") { Task { await settings.uninstallNetd() } }
                    .disabled(settings.netdAgent?.installed != true || settings.isBusy)
                Button("Restart") { Task { await settings.restartNetd() } }
                    .disabled(settings.netdAgent?.installed != true || settings.isBusy)
                Button("Install") { Task { await settings.installNetd() } }
                    .disabled(settings.bundled.netd == nil || !settings.netdSupported || settings.isBusy)
            }
        }
    }
}

struct HandoffDefaultsSection: View {
    let settings: SettingsModel

    var body: some View {
        Section("Hand-off") {
            Picker("Default agent", selection: agent) {
                ForEach(AgentKind.allCases, id: \.self) { agent in
                    Text(agent.displayName).tag(agent)
                }
            }
            Picker("Terminal", selection: terminal) {
                ForEach(TerminalApp.allCases, id: \.self) { terminal in
                    Text(terminal.displayName).tag(terminal)
                }
            }
        }
    }

    private var agent: Binding<AgentKind> {
        Binding<AgentKind>(get: { settings.handoff.defaultAgent }, set: { agent in Task { await settings.setDefaultAgent(agent) } })
    }

    private var terminal: Binding<TerminalApp> {
        Binding<TerminalApp>(get: { settings.handoff.terminal }, set: { terminal in Task { await settings.setTerminal(terminal) } })
    }
}

struct AppSection: View {
    let settings: SettingsModel
    let setExpertMode: @MainActor (Bool) -> Void

    var body: some View {
        Section("App") {
            Toggle("Expert mode", isOn: expertMode)
            Text("Shows processes, sockets, firewall details, sandbox rules, tools and migration in the sidebar.")
                .font(.callout)
                .foregroundStyle(.secondary)
            Picker("Refresh while visible", selection: interval) {
                ForEach([1.0, 2.0, 5.0, 10.0, 30.0], id: \.self) { seconds in
                    Text(verbatim: "every \(Int(seconds)) s").tag(seconds)
                }
            }
            LabeledContent("svctl", value: settings.bundled.svctl ?? "not bundled")
            if let command = settings.svctlLinkCommand {
                Text(command)
                    .font(.system(.caption, design: .monospaced))
                    .textSelection(.enabled)
            }
        }
    }

    private var expertMode: Binding<Bool> {
        Binding<Bool>(get: { settings.preferences.expertMode }, set: { on in setExpertMode(on) })
    }

    private var interval: Binding<Double> {
        Binding<Double>(get: { settings.preferences.refreshInterval }, set: { seconds in settings.setRefreshInterval(seconds) })
    }
}
