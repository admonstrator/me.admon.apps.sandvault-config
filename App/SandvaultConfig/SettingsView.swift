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
                ConnectionRequestsSection(settings: settings)
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

/// What netd looks up for a connection request, the assessment and the safer default (D38-D41).
struct ConnectionRequestsSection: View {
    let settings: SettingsModel

    @State private var countries = ""

    var body: some View {
        Section {
            ForEach(AskDetailSwitch.lookupsBeforeNetwork, id: \.self) { setting in
                DetailToggle(setting: setting, isOn: binding(setting))
            }
            Picker(selection: network) {
                ForEach(NetworkLookupMode.allCases, id: \.self) { mode in
                    Text(mode.displayName).tag(mode)
                }
            } label: {
                DetailLabel("Network and country", note: "Online reveals the address to the registry.", symbol: "server.rack", color: .green)
            }
            if settings.askDetails.network != .off {
                Text(settings.askDetails.network.explanation)
                    .font(.callout)
                    .foregroundStyle(.secondary)
            }
            if settings.askDetails.network == .offline {
                NetworkDatabaseRow(settings: settings)
            }
            ForEach(AskDetailSwitch.lookupsAfterNetwork, id: \.self) { setting in
                DetailToggle(setting: setting, isOn: binding(setting))
            }
        } header: {
            Text("Connection requests")
        } footer: {
            Text("netd collects these details before the request appears; whatever takes longer than \(String(format: "%.1f", settings.askDetails.budgetSeconds)) s is left out.")
        }

        Section {
            ForEach(AskDetailSwitch.judgement, id: \.self) { setting in
                DetailToggle(setting: setting, isOn: binding(setting))
                    .disabled(setting == .saferDefault && !settings.isOn(.assessment))
            }
            LabeledContent {
                TextField("Marked countries", text: $countries, prompt: Text(verbatim: "RU, KP"))
                    .labelsHidden()
                    .multilineTextAlignment(.trailing)
                    .font(.system(.body, design: .monospaced))
                    .frame(maxWidth: 180)
                    .onSubmit { Task { await settings.setMarkedCountries(countries) } }
            } label: {
                DetailLabel("Marked countries", note: "ISO codes, e.g. RU. Adds points, never decides alone.", symbol: "flag", color: .pink)
            }
        }
        .onAppear { countries = settings.markedCountriesText }
        .onChange(of: settings.markedCountriesText) { _, text in countries = text }
    }

    private func binding(_ setting: AskDetailSwitch) -> Binding<Bool> {
        Binding<Bool>(
            get: { settings.isOn(setting) },
            set: { on in Task { await settings.setAskDetail(setting, on) } }
        )
    }

    private var network: Binding<NetworkLookupMode> {
        Binding<NetworkLookupMode>(get: { settings.askDetails.network }, set: { mode in Task { await settings.setNetworkLookup(mode) } })
    }
}

/// Status of the offline table and the button that downloads or updates it.
private struct NetworkDatabaseRow: View {
    let settings: SettingsModel

    var body: some View {
        LabeledContent {
            HStack(spacing: 8) {
                if settings.isUpdatingDatabase {
                    ProgressView()
                        .controlSize(.small)
                }
                Button(settings.networkDatabaseActionTitle) { Task { await settings.updateNetworkDatabase() } }
                    .disabled(settings.isUpdatingDatabase)
            }
        } label: {
            VStack(alignment: .leading, spacing: 1) {
                Text("Network database")
                Text(settings.networkDatabaseSummary)
                    .font(.caption)
                    .foregroundStyle(.secondary)
            }
        }
        .task { await settings.refreshNetworkDatabase() }
    }
}

/// A settings row label: a white symbol on a coloured square, a title and a one-line note.
private struct DetailLabel: View {
    let title: String
    let note: String
    let symbol: String
    let color: Color

    init(_ title: String, note: String, symbol: String, color: Color) {
        self.title = title
        self.note = note
        self.symbol = symbol
        self.color = color
    }

    var body: some View {
        HStack(spacing: 10) {
            Image(systemName: symbol)
                .font(.system(size: 13, weight: .semibold))
                .foregroundStyle(.white)
                .frame(width: 26, height: 26)
                .background(color, in: RoundedRectangle(cornerRadius: 7, style: .continuous))
            VStack(alignment: .leading, spacing: 1) {
                Text(title)
                Text(note)
                    .font(.caption)
                    .foregroundStyle(.secondary)
            }
        }
    }
}

private struct DetailToggle: View {
    let setting: AskDetailSwitch
    let isOn: Binding<Bool>

    private var color: Color {
        switch setting {
        case .name: .blue
        case .reverseDNS: .indigo
        case .port: .gray
        case .program: .orange
        case .history: .purple
        case .assessment: .red
        case .saferDefault: .gray
        }
    }

    var body: some View {
        Toggle(isOn: isOn) {
            DetailLabel(setting.title, note: setting.note, symbol: setting.symbolName, color: color)
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
            Toggle("Show in Dock", isOn: showInDock)
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

    private var showInDock: Binding<Bool> {
        Binding<Bool>(get: { settings.preferences.showInDock }, set: { on in
            settings.setShowInDock(on)
            DockPresence.apply(on)
        })
    }

    private var expertMode: Binding<Bool> {
        Binding<Bool>(get: { settings.preferences.expertMode }, set: { on in setExpertMode(on) })
    }

    private var interval: Binding<Double> {
        Binding<Double>(get: { settings.preferences.refreshInterval }, set: { seconds in settings.setRefreshInterval(seconds) })
    }
}
