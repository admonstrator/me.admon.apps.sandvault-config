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
                .safeAreaInset(edge: .top, spacing: 0) {
                    ServiceProblemsBanner(settings: model.settings)
                }
                .sheet(isPresented: updateWelcome) {
                    UpdateWelcomeView(settings: model.settings)
                        .interactiveDismissDisabled()
                }
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
        .onAppear {
            model.setVisible(.window, true)
            // Catch a helper or netd that broke while the window was closed.
            Task { await model.settings.refresh() }
        }
        .onDisappear { model.setVisible(.window, false) }
    }

    /// After an update, not on first launch (that sheet comes first).
    private var updateWelcome: Binding<Bool> {
        Binding<Bool>(get: { !model.needsOnboarding && model.settings.needsUpdateWelcome }, set: { _ in })
    }

    /// First launch: the sheet stays until `finishOnboarding` marks it done.
    private var onboarding: Binding<Bool> {
        Binding<Bool>(get: { model.needsOnboarding }, set: { _ in })
    }
}

/// Parts outside the app that are out of date or stopped, each with its repair (like Docker Desktop's banner).
struct ServiceProblemsBanner: View {
    let settings: SettingsModel

    var body: some View {
        let problems = settings.needsUpdateWelcome ? [] : settings.problems
        if !problems.isEmpty {
            VStack(spacing: 6) {
                ForEach(problems) { problem in
                    HStack(alignment: .firstTextBaseline, spacing: 10) {
                        Image(systemName: "exclamationmark.triangle.fill")
                            .foregroundStyle(.orange)
                        VStack(alignment: .leading, spacing: 2) {
                            Text(problem.title).bold()
                            Text(problem.detail)
                                .font(.callout)
                                .foregroundStyle(.secondary)
                        }
                        Spacer()
                        Button(problem.repairTitle) { Task { await settings.repair(problem) } }
                            .disabled(settings.isBusy)
                    }
                }
                if let message = settings.message {
                    MessageBanner(message: message) { settings.message = nil }
                }
            }
            .padding(12)
            .background(.orange.opacity(0.12), in: RoundedRectangle(cornerRadius: 10))
            .padding(.horizontal, 16)
            .padding(.top, 10)
        }
    }
}

/// After an update: what changes outside the app, done with one button.
struct UpdateWelcomeView: View {
    let settings: SettingsModel
    @State private var working = false

    var body: some View {
        VStack(alignment: .leading, spacing: 14) {
            Label("Sandvault Config was updated", systemImage: "sparkles")
                .font(.title2.bold())
            Text("You now run version \(settings.bundled.version ?? "?").")
                .foregroundStyle(.secondary)
            let steps = settings.updateSteps
            if steps.isEmpty {
                Text("Nothing outside the app needs updating.")
            } else {
                Text("These parts run outside the app and still have the old version:")
                ForEach(steps, id: \.self) { step in
                    Label(step, systemImage: "arrow.triangle.2.circlepath")
                }
            }
            HStack {
                if working { ProgressView().controlSize(.small) }
                Spacer()
                if !steps.isEmpty {
                    Button("Later") { Task { await settings.finishUpdate(apply: false) } }
                        .disabled(working)
                }
                Button(steps.isEmpty ? "Continue" : "Update Now") {
                    working = true
                    Task {
                        await settings.finishUpdate(apply: true)
                        working = false
                    }
                }
                .keyboardShortcut(.defaultAction)
                .disabled(working)
            }
        }
        .padding(24)
        .frame(width: 460)
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
        case .tools: ToolsView(tools: model.tools, android: model.android, programs: model.programs)
        case .handoff: HandoffView(model: model)
        case .migration: MigrationView(migration: model.migration, keys: model.keys)
        case .settings: EmptyView()
        }
    }
}
