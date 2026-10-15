import SandvaultAppModel
import SandvaultCore
import SwiftUI

/// The Settings window (⌘,): one tab per part the current mode has (D53).
struct SettingsView: View {
    let model: AppModel

    var body: some View {
        @Bindable var settings = model.settings
        TabView(selection: $settings.pane) {
            ForEach(SettingsPane.panes(for: model.mode)) { pane in
                SettingsPaneView(model: model, pane: pane)
                    .tabItem { Label(pane.title, systemImage: pane.symbolName) }
                    .tag(pane)
            }
        }
        .frame(minWidth: 600, idealWidth: 660, minHeight: 520, idealHeight: 640)
    }
}

struct SettingsPaneView: View {
    let model: AppModel
    let pane: SettingsPane

    var body: some View {
        let settings = model.settings
        VStack(spacing: 0) {
            MessageArea(message: settings.message) { settings.message = nil }
            if pane == .recording {
                MessageArea(message: model.recording.message) { model.recording.message = nil }
            }
            if pane == .general {
                MessageArea(message: model.sandbox.message) { model.sandbox.message = nil }
            }
            Form {
                switch pane {
                case .general:
                    ModeSection(model: model)
                    if model.mode != .expert {
                        SimpleServiceSection(settings: settings, netd: model.netd)
                    }
                    HandoffDefaultsSection(settings: settings, mode: model.mode)
                    AppSection(settings: settings, mode: model.mode)
                    if model.mode == .easy && model.sandbox.installed {
                        SandboxManageSection(sandbox: model.sandbox)
                    }
                case .websites:
                    DeveloperBasicsSection(settings: settings)
                    Section {
                        LabeledContent("Websites the sandbox used") {
                            Button("Show Websites") { AppRuntime.showMainWindow(.websites) }
                        }
                    } footer: {
                        Text("Every website with what the sandbox did there. Allow or block it in one click.")
                    }
                case .connectionRequests:
                    ConnectionRequestsSection(settings: settings)
                case .recording:
                    RecordingSections(recording: model.recording, mode: model.mode)
                case .service:
                    HelperSection(settings: settings)
                    NetdSection(settings: settings, netd: model.netd)
                    SvctlSection(settings: settings)
                }
            }
            .formStyle(.grouped)
        }
    }
}

/// Easy, Advanced or Expert as three cards, with what each adds.
struct ModeSection: View {
    let model: AppModel

    var body: some View {
        Section {
            ModeCards(selected: model.mode) { mode in model.setMode(mode) }
        } header: {
            Text("Interface")
        } footer: {
            Text("Switching never changes your protection. Hidden pages keep their settings.")
        }
    }
}

/// The three modes side by side; Settings > General and first launch.
struct ModeCards: View {
    let selected: InterfaceMode
    let choose: (InterfaceMode) -> Void

    var body: some View {
        HStack(alignment: .top, spacing: 10) {
            ForEach(InterfaceMode.allCases) { mode in
                ModeCard(mode: mode, selected: mode == selected) { choose(mode) }
            }
        }
        .fixedSize(horizontal: false, vertical: true)
        .padding(.vertical, 4)
    }
}

struct ModeCard: View {
    let mode: InterfaceMode
    let selected: Bool
    let action: () -> Void

    var body: some View {
        let shape = RoundedRectangle(cornerRadius: 10, style: .continuous)
        Button(action: action) {
            VStack(alignment: .leading, spacing: 6) {
                HStack {
                    Image(systemName: mode.symbolName)
                        .font(.system(size: 13, weight: .semibold))
                        .foregroundStyle(.white)
                        .frame(width: 28, height: 28)
                        .background(color, in: RoundedRectangle(cornerRadius: 7, style: .continuous))
                    Spacer(minLength: 0)
                    if selected {
                        Image(systemName: "checkmark.circle.fill")
                            .foregroundStyle(Color.accentColor)
                    }
                }
                Text(mode.title)
                    .font(.headline)
                if mode == .easy {
                    Text("Recommended")
                        .font(.caption2.weight(.semibold))
                        .foregroundStyle(.green)
                }
                Text(mode.explanation)
                    .font(.caption)
                    .foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true)
                Spacer(minLength: 0)
            }
            .padding(10)
            .frame(maxWidth: .infinity, maxHeight: .infinity, alignment: .topLeading)
            .background(selected ? Color.accentColor.opacity(0.12) : Color.primary.opacity(0.04), in: shape)
            .overlay {
                shape.strokeBorder(selected ? Color.accentColor : Color.primary.opacity(0.1), lineWidth: selected ? 2 : 1)
            }
            .contentShape(shape)
        }
        .buttonStyle(.plain)
        .accessibilityAddTraits(selected ? .isSelected : [])
    }

    private var color: Color {
        switch mode {
        case .easy: .green
        case .advanced: .blue
        case .expert: .purple
        }
    }
}

/// Websites allowed without asking (D53); a rule for the same host still decides first.
struct DeveloperBasicsSection: View {
    let settings: SettingsModel

    var body: some View {
        Section {
            Toggle(isOn: enabled) {
                DetailLabel("Allow developer basics", note: "Websites most coding tools need, allowed without asking.", symbol: "checkmark.shield", color: .green)
            }
            ForEach(DeveloperBasicsGroup.catalog) { group in
                Toggle(isOn: binding(group)) {
                    DetailLabel(group.title, note: Self.websites(group), symbol: group.symbolName, color: Self.color(group))
                }
                .disabled(!settings.developerBasics.enabled)
            }
        } header: {
            Text("Developer basics")
        } footer: {
            Text("These websites open without asking, for web traffic only. A rule of yours for the same website always wins. Turn off what you do not use.")
        }
    }

    /// `github.com, githubusercontent.com`: a `*.` pattern also covers the website itself.
    static func websites(_ group: DeveloperBasicsGroup) -> String {
        var seen: Set<String> = []
        return group.patterns
            .map { $0.hasPrefix("*.") ? String($0.dropFirst(2)) : $0 }
            .filter { seen.insert($0).inserted }
            .joined(separator: ", ")
    }

    static func color(_ group: DeveloperBasicsGroup) -> Color {
        switch group.id {
        case "github": .gray
        case "npm": .red
        case "python": .blue
        case "homebrew", "rust": .orange
        case "go": .teal
        case "docker": .indigo
        case "ai": .purple
        default: .gray
        }
    }

    private var enabled: Binding<Bool> {
        Binding<Bool>(get: { settings.developerBasics.enabled }, set: { on in Task { await settings.setDeveloperBasics(on) } })
    }

    private func binding(_ group: DeveloperBasicsGroup) -> Binding<Bool> {
        Binding<Bool>(get: { settings.developerBasics.isOn(group) }, set: { on in Task { await settings.setDeveloperBasics(group, on) } })
    }
}

/// General below Expert: the helper and netd in plain words, each with one button.
struct SimpleServiceSection: View {
    let settings: SettingsModel
    let netd: NetdLink

    var body: some View {
        Section {
            LabeledContent {
                Button(settings.helperInstalled ? "Reinstall…" : "Install…") { Task { await settings.installHelper() } }
                    .disabled(settings.bundled.helper == nil || settings.isBusy)
            } label: {
                DetailLabel(
                    "Helper", note: settings.helperInstalled ? "Installed." : "Not installed. The protection needs it.",
                    symbol: "lock.shield", color: .red
                )
            }
            LabeledContent {
                Button(netd.isConnected ? "Restart" : "Start") { Task { await settings.startNetd() } }
                    .disabled(settings.bundled.netd == nil || !settings.netdSupported || settings.isBusy)
            } label: {
                DetailLabel(
                    "Network monitor", note: netd.isConnected ? "Running." : "Not running. Websites do not work without it.",
                    symbol: "network", color: .blue
                )
            }
        } header: {
            Text("Service")
        } footer: {
            Text("Both run in the background. Installing the helper asks for your administrator password once.")
        }
    }
}

/// Rebuild and Delete for Easy, which has no Sandbox page.
struct SandboxManageSection: View {
    let sandbox: SandboxModel
    @State private var confirmDelete = false

    var body: some View {
        Section("Sandbox") {
            LabeledContent {
                Button("Rebuild") { Task { await sandbox.rebuild() } }
                    .disabled(sandbox.isBusy)
            } label: {
                DetailLabel("Rebuild", note: "Repairs the sandbox if something stopped working.", symbol: "arrow.clockwise", color: .gray)
            }
            LabeledContent {
                Button("Delete…", role: .destructive) { confirmDelete = true }
                    .disabled(sandbox.isBusy)
                    .confirmationDialog("Delete the sandbox?", isPresented: $confirmDelete) {
                        Button("Delete Sandbox", role: .destructive) { Task { await sandbox.delete() } }
                    } message: {
                        Text(sandbox.deleteExplanation)
                    }
            } label: {
                DetailLabel("Delete Sandbox", note: "Removes the sandbox user. The shared workspace stays.", symbol: "trash", color: .red)
            }
        }
    }
}

/// Settings > Service: the command line tool that comes with the app.
struct SvctlSection: View {
    let settings: SettingsModel

    var body: some View {
        Section {
            LabeledContent("svctl", value: settings.bundled.svctl ?? "not bundled")
            if let command = settings.svctlLinkCommand {
                Text(command)
                    .font(.system(.caption, design: .monospaced))
                    .textSelection(.enabled)
            }
        } header: {
            Text("Command line")
        } footer: {
            Text("Everything in this window is also available as svctl.")
        }
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
struct DetailLabel: View {
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
    var mode: InterfaceMode = .expert

    var body: some View {
        Section("Starting") {
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
            if mode >= .advanced {
                LabeledContent("Clone folder") {
                    HStack {
                        Text(settings.handoff.cloneDirectory)
                            .textSelection(.enabled)
                        Button("Choose…") {
                            if let path = FolderPicker.chooseFolder(message: "Choose where repository URLs are cloned before they go to a Linux VM.") {
                                Task { await settings.setCloneDirectory(path) }
                            }
                        }
                    }
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
    var mode: InterfaceMode = .expert

    var body: some View {
        Section("App") {
            Toggle("Show in Dock", isOn: showInDock)
            if mode == .expert {
                Picker("Refresh while visible", selection: interval) {
                    ForEach([1.0, 2.0, 5.0, 10.0, 30.0], id: \.self) { seconds in
                        Text(verbatim: "every \(Int(seconds)) s").tag(seconds)
                    }
                }
            }
        }
    }

    private var showInDock: Binding<Bool> {
        Binding<Bool>(get: { settings.preferences.showInDock }, set: { on in
            settings.setShowInDock(on)
            DockPresence.apply(on)
        })
    }

    private var interval: Binding<Double> {
        Binding<Double>(get: { settings.preferences.refreshInterval }, set: { seconds in settings.setRefreshInterval(seconds) })
    }
}
