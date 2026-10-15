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
        case .websites: WebsitesView(model: model)
        case .diagnostics: DiagnosticsView(model: model)
        case .lab: ContentUnavailableView("Lab", systemImage: Screen.lab.symbolName)
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
