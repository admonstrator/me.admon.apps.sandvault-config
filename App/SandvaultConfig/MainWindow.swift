import SandvaultAppModel
import SwiftUI

struct MainWindow: View {
    static let id = "main"

    let model: AppModel

    var body: some View {
        NavigationSplitView {
            Sidebar(model: model)
        } detail: {
            ScreenView(model: model)
        }
        .background(WindowOpenerRegistration())
        .onAppear { model.setVisible(.window, true) }
        .onDisappear { model.setVisible(.window, false) }
    }
}

struct Sidebar: View {
    let model: AppModel

    var body: some View {
        List(selection: selection) {
            ForEach(model.screens) { screen in
                NavigationLink(value: screen) {
                    Label(screen.title, systemImage: screen.symbolName)
                }
            }
        }
        .navigationSplitViewColumnWidth(min: 190, ideal: 220)
        .safeAreaInset(edge: .bottom) {
            Text(model.netd.summary)
                .font(.caption)
                .foregroundStyle(.secondary)
                .lineLimit(3)
                .frame(maxWidth: .infinity, alignment: .leading)
                .padding(10)
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

struct ScreenView: View {
    let model: AppModel

    var body: some View {
        switch model.selection {
        case .overview: OverviewView(model: model)
        case .sandbox: SandboxView(model: model)
        case .activity: ActivityView(activity: model.activity)
        case .processes: ProcessesView(processes: model.processes)
        case .network: NetworkView(network: model.network, netd: model.netd)
        case .firewall: FirewallView(firewall: model.firewall)
        case .rules: RulesView(rules: model.rules)
        case .tools: ToolsView(tools: model.tools)
        case .handoff: HandoffView(model: model)
        case .migration: MigrationView(migration: model.migration, keys: model.keys)
        case .settings: SettingsView(settings: model.settings, netd: model.netd) { on in model.setExpertMode(on) }
        }
    }
}
