import AppKit
import SandvaultAppModel
import SandvaultCore
import SwiftUI

struct MenuBarLabel: View {
    let model: AppModel

    var body: some View {
        let pending = model.asks.pending.count
        if pending > 0 {
            HStack(spacing: 2) {
                Image(systemName: model.menuBarSymbol)
                Text(verbatim: "\(pending)")
            }
        } else {
            Image(systemName: model.menuBarSymbol)
        }
    }
}

/// The menu bar window: state, counts, quick actions, recently denied hosts. Folders dropped here are handed off.
struct MenuBarView: View {
    let model: AppModel
    @Environment(\.openWindow) private var openWindow
    @State private var armPanic = false

    var body: some View {
        let summary = model.menuBar
        VStack(alignment: .leading, spacing: 10) {
            Label(summary.stateTitle, systemImage: summary.symbolName)
                .font(.headline)
            HStack(spacing: 18) {
                MenuStat(title: "Sessions", value: summary.sessions)
                MenuStat(title: "Processes", value: summary.processes)
                MenuStat(title: "Denied, 1 h", value: summary.deniedLastHour)
            }
            if summary.pendingAsks > 0 {
                Text(verbatim: "\(summary.pendingAsks) connection request(s) waiting for an answer")
                    .foregroundStyle(.orange)
            }
            if !summary.netdRunning {
                Text("sandvault-netd is not running")
                    .font(.caption)
                    .foregroundStyle(.secondary)
            }
            Divider()
            if model.settings.preferences.expertMode {
                Picker("Firewall", selection: mode) {
                    ForEach(FirewallMode.allCases, id: \.self) { mode in
                        Text(mode.displayName).tag(mode)
                    }
                }
                .pickerStyle(.menu)
            } else {
                Picker("Protection", selection: protection) {
                    ForEach(ProtectionLevel.allCases) { level in
                        Text(level.title).tag(Optional(level))
                    }
                }
                .pickerStyle(.menu)
                .disabled(model.firewall.isBusy)
            }
            StartSessionRow(sandbox: model.sandbox, defaultAgent: model.editor.config.handoff.defaultAgent)
            HStack {
                Button("Hand Off a Repository…") { chooseAndHandOff() }
                Spacer()
                Button("Open Window") { open(nil) }
            }
            PanicRow(armed: $armPanic, firewall: model.firewall)
            if !summary.recentDenied.isEmpty {
                Divider()
                Text("Recently denied")
                    .font(.caption)
                    .foregroundStyle(.secondary)
                ForEach(summary.recentDenied) { denied in
                    HStack {
                        Text(denied.host)
                            .lineLimit(1)
                            .truncationMode(.middle)
                        Text(verbatim: "\(denied.count)x")
                            .foregroundStyle(.secondary)
                        Spacer()
                        Button("Allow") { Task { await model.network.allowHost(denied.host) } }
                            .help("Allow rule for exactly this host")
                    }
                }
            }
            if let message = model.sandbox.message ?? model.network.message ?? model.firewall.message {
                Text(message.title)
                    .font(.caption)
                    .foregroundStyle(message.kind.tint.color)
                    .lineLimit(2)
            }
            Divider()
            HStack {
                Text(BundleIdentity.displayName)
                    .font(.caption)
                    .foregroundStyle(.secondary)
                Spacer()
                Button("Quit") { NSApplication.shared.terminate(nil) }
            }
        }
        .padding(14)
        .frame(width: 340)
        .background(WindowOpenerRegistration())
        .onAppear { model.setVisible(.menu, true) }
        .onDisappear { model.setVisible(.menu, false) }
        .dropDestination(for: URL.self) { urls, _ in
            let taken = model.handOff(paths: urls.map(\.path))
            if taken { open(.handoff) }
            return taken
        }
    }

    /// Choosing a mode here saves it and opens the Firewall page with the generated rules to confirm.
    private var mode: Binding<FirewallMode> {
        Binding<FirewallMode>(
            get: { model.editor.config.network.mode },
            set: { mode in
                Task {
                    await model.firewall.setMode(mode)
                    await model.firewall.prepareApply()
                }
                open(.firewall)
            }
        )
    }

    /// Choosing a level here saves and applies it at once, like on the overview.
    private var protection: Binding<ProtectionLevel?> {
        Binding<ProtectionLevel?>(
            get: { model.firewall.protection },
            set: { level in
                if let level { Task { await model.firewall.setProtection(level) } }
            }
        )
    }

    private func chooseAndHandOff() {
        guard let path = FolderPicker.chooseRepository() else { return }
        if model.handOff(paths: [path]) { open(.handoff) }
    }

    private func open(_ screen: Screen?) {
        if let screen { model.select(screen) }
        openWindow(id: MainWindow.id)
        NSApplication.shared.activate()
    }
}

/// Shell and the default agent in one click; sv itself builds a missing sandbox on first use.
struct StartSessionRow: View {
    let sandbox: SandboxModel
    let defaultAgent: AgentKind

    var body: some View {
        HStack {
            Button("Open Shell") { Task { await sandbox.open(.shell) } }
            if defaultAgent != .shell {
                Button("Start \(defaultAgent.displayName)") { Task { await sandbox.open(defaultAgent) } }
            }
            Spacer()
        }
        .disabled(sandbox.isBusy)
    }
}

struct MenuStat: View {
    let title: String
    let value: Int

    var body: some View {
        VStack(alignment: .leading, spacing: 0) {
            Text(verbatim: "\(value)")
                .font(.title2)
                .monospacedDigit()
            Text(title)
                .font(.caption)
                .foregroundStyle(.secondary)
        }
    }
}

/// Two steps, so a stray click never ends every sandbox process.
struct PanicRow: View {
    @Binding var armed: Bool
    let firewall: FirewallModel

    var body: some View {
        if armed {
            HStack {
                Text("Block the network and end all sandbox processes?")
                    .font(.callout)
                Spacer()
                Button("Cancel") { armed = false }
                Button("Panic", role: .destructive) {
                    armed = false
                    Task { await firewall.panic() }
                }
            }
        } else {
            HStack {
                Button("Panic…", role: .destructive) { armed = true }
                    .disabled(firewall.isBusy)
                Spacer()
                Button("Firewall Off") { Task { await firewall.turnOff() } }
                    .disabled(firewall.isBusy || firewall.network.mode == .off)
            }
        }
    }
}
