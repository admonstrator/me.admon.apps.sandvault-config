import SandvaultAppModel
import SandvaultCore
import SwiftUI
import TipKit

struct MainWindow: View {
    static let id = "main"

    let model: AppModel
    @State private var confirmStop = false

    var body: some View {
        NavigationSplitView {
            Sidebar(model: model)
        } detail: {
            ScreenView(model: model)
        }
        .toolbar {
            ToolbarItem(placement: .primaryAction) {
                EmergencyStopButton(firewall: model.firewall) { confirmStop = true }
            }
        }
        .confirmationDialog("Stop everything in the sandbox?", isPresented: $confirmStop) {
            Button("Stop Everything", role: .destructive) {
                Task { await AppRuntime.emergencyStop() }
            }
        } message: {
            Text("The sandbox loses its network and every program in it ends now. Your files stay as they are.")
        }
        .sheet(isPresented: onboarding) {
            OnboardingView(model: model)
                .interactiveDismissDisabled()
        }
        .background(WindowOpenerRegistration())
        .onAppear { model.setVisible(.window, true) }
        .onDisappear { model.setVisible(.window, false) }
    }

    /// First launch: the sheet stays until `finishOnboarding` marks it done.
    private var onboarding: Binding<Bool> {
        Binding<Bool>(get: { model.needsOnboarding }, set: { _ in })
    }
}

/// Red while the sandbox runs; during a stop it ends the stop with the level from before.
struct EmergencyStopButton: View {
    let firewall: FirewallModel
    let confirm: () -> Void

    var body: some View {
        if firewall.panicActive {
            Button {
                Task { await AppRuntime.endEmergencyStop() }
            } label: {
                Label("End Stop", systemImage: "play.fill")
            }
            .labelStyle(.titleAndIcon)
            .help("Ends the stop with the protection level \(AppRuntime.resumeLevel.title)")
            .disabled(firewall.isBusy)
        } else {
            Button(role: .destructive, action: confirm) {
                Label("Emergency Stop", systemImage: "stop.fill")
            }
            .labelStyle(.titleAndIcon)
            .buttonStyle(.borderedProminent)
            .tint(.red)
            .help("Blocks the network and ends every program in the sandbox")
            .disabled(firewall.isBusy)
        }
    }
}

struct Sidebar: View {
    let model: AppModel

    var body: some View {
        List(selection: selection) {
            ForEach(model.sidebar) { section in
                Section(section.title) {
                    ForEach(section.screens) { screen in
                        NavigationLink(value: screen) {
                            Label(screen.title, systemImage: screen.symbolName)
                        }
                    }
                }
            }
        }
        .navigationSplitViewColumnWidth(min: 190, ideal: 220)
        .safeAreaInset(edge: .bottom) {
            SidebarFooter(model: model)
        }
    }

    private var selection: Binding<Screen?> {
        Binding<Screen?>(
            get: { model.selection },
            set: { screen in
                if let screen { model.select(screen) }
            }
        )
    }
}

/// The status line and the mode pill, one click from Settings > General.
struct SidebarFooter: View {
    let model: AppModel
    private let modeTip = ModeTip()

    var body: some View {
        let status = SidebarStatus(
            mode: model.mode, protection: model.firewall.protection, panicActive: model.firewall.panicActive,
            netdMissing: model.editor.config.network.mode.needsNetd && !model.netd.isConnected, netdSummary: model.netd.summary
        )
        VStack(alignment: .leading, spacing: 8) {
            HStack(alignment: .top, spacing: 6) {
                Circle()
                    .fill(status.tint.color)
                    .frame(width: 7, height: 7)
                    .padding(.top, 4)
                Text(status.text)
                    .font(.caption)
                    .foregroundStyle(.secondary)
                    .lineLimit(3)
                    .fixedSize(horizontal: false, vertical: true)
            }
            HStack {
                modePill
                Spacer()
                Button {
                    model.showSettings()
                } label: {
                    Image(systemName: "gearshape")
                }
                .buttonStyle(.borderless)
                .help("Settings")
            }
        }
        .frame(maxWidth: .infinity, alignment: .leading)
        .padding(10)
    }

    @ViewBuilder
    private var modePill: some View {
        let pill = Button {
            modeTip.invalidate(reason: .actionPerformed)
            model.showSettings(.general)
        } label: {
            Label(model.mode.title, systemImage: model.mode.symbolName)
                .font(.caption.weight(.medium))
                .padding(.horizontal, 9)
                .padding(.vertical, 4)
                .background(Capsule().fill(Color.primary.opacity(0.08)))
                .contentShape(Capsule())
        }
        .buttonStyle(.plain)
        .help("Mode \(model.mode.title). Click to change it in Settings.")
        if model.mode == .expert {
            pill
        } else {
            pill.popoverTip(modeTip)
        }
    }
}

struct ScreenView: View {
    let model: AppModel

    var body: some View {
        switch model.selection {
        case .overview: OverviewView(model: model)
        case .websites: WebsitesView(model: model)
        case .diagnostics: DiagnosticsView(model: model)
        case .lab: LabView(model: model)
        case .sandbox: SandboxView(model: model)
        case .activity: ActivityView(model: model)
        case .processes: ProcessesView(processes: model.processes)
        case .network: NetworkView(network: model.network, netd: model.netd)
        case .firewall: FirewallView(firewall: model.firewall)
        case .rules: RulesView(rules: model.rules)
        case .tools: ToolsView(tools: model.tools, android: model.android)
        case .handoff: HandoffView(model: model)
        case .migration: MigrationView(migration: model.migration, keys: model.keys)
        case .settings: EmptyView()
        }
    }
}
