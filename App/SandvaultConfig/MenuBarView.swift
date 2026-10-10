import AppKit
import SandvaultAppModel
import SandvaultCore
import SwiftUI

/// The vault door, with the number of waiting asks beside it; the state itself shows in the window.
struct MenuBarLabel: View {
    let model: AppModel

    var body: some View {
        let pending = model.asks.pending.count
        HStack(spacing: 2) {
            Image("MenuBarVault")
                .renderingMode(.template)
            if pending > 0 {
                Text(verbatim: "\(pending)")
            }
        }
    }
}

/// The menu bar window in the style of Control Center: level buttons, alerts, counts, start rows, recently blocked
/// hosts and the usual menu rows. Folders dropped here are handed off.
struct MenuBarView: View {
    let model: AppModel
    @Environment(\.openWindow) private var openWindow
    @State private var armStop = false

    private var expert: Bool { model.settings.preferences.expertMode }

    var body: some View {
        let summary = model.menuBar
        VStack(alignment: .leading, spacing: 2) {
            header(summary)
            ProtectionButtons(firewall: model.firewall)
            Text(summary.explanation)
                .font(.caption)
                .foregroundStyle(.secondary)
                .fixedSize(horizontal: false, vertical: true)
                .frame(maxWidth: .infinity, minHeight: 30, alignment: .topLeading)
                .padding(.horizontal, 10)
                .padding(.top, 2)
                .padding(.bottom, 4)
            if expert {
                FirewallModeRow(model: model) { open($0) }
            }
            alerts(summary)
            stats(summary)

            MenuSeparator()
            MenuSectionLabel("Start in the sandbox")
            StartRows(model: model, chooseAndHandOff: chooseAndHandOff)

            if !summary.recentDenied.isEmpty {
                MenuSeparator()
                MenuSectionLabel("Recently blocked")
                ForEach(summary.recentDenied) { denied in
                    BlockedHostRow(denied: denied) { Task { await model.network.allowHost(denied.host) } }
                }
            }

            if let message = model.sandbox.message ?? model.network.message ?? model.firewall.message ?? model.settings.message {
                Text(message.title)
                    .font(.caption)
                    .foregroundStyle(message.kind.tint.color)
                    .lineLimit(2)
                    .padding(.horizontal, 10)
                    .padding(.top, 4)
            }

            MenuSeparator()
            MenuRow("Open \(BundleIdentity.displayName)…", shortcut: "⌘O") { open(nil) }
                .keyboardShortcut("o")
            MenuRow("Settings…", shortcut: "⌘,") { open(.settings) }
                .keyboardShortcut(",")
            EmergencyStop(armed: $armStop, firewall: model.firewall)
            MenuSeparator()
            MenuRow("Quit \(BundleIdentity.displayName)", shortcut: "⌘Q") { NSApplication.shared.terminate(nil) }
                .keyboardShortcut("q")
            footer
        }
        .padding(6)
        .frame(width: 300)
        .background(WindowOpenerRegistration())
        .onAppear { model.setVisible(.menu, true) }
        .onDisappear {
            model.setVisible(.menu, false)
            armStop = false
        }
        .dropDestination(for: URL.self) { urls, _ in
            let taken = model.handOff(paths: urls.map(\.path))
            if taken { open(.handoff) }
            return taken
        }
    }

    private func header(_ summary: MenuBarSummary) -> some View {
        HStack {
            Text("Sandvault")
                .font(.system(size: 13, weight: .bold))
            Spacer()
            HStack(spacing: 6) {
                Circle()
                    .fill(summary.statusTint.color)
                    .frame(width: 7, height: 7)
                Text(summary.statusText)
                    .font(.caption)
                    .foregroundStyle(.secondary)
            }
        }
        .padding(.horizontal, 10)
        .padding(.top, 8)
        .padding(.bottom, 4)
    }

    @ViewBuilder
    private func alerts(_ summary: MenuBarSummary) -> some View {
        if summary.pendingAsks > 0 {
            AlertCard(
                symbol: "bell",
                title: summary.pendingAsks == 1 ? "1 request waiting" : "\(summary.pendingAsks) requests waiting",
                detail: summary.pendingHosts.joined(separator: ", "),
                action: "Review", prominent: true
            ) { AppRuntime.showAskPanels() }
        }
        if summary.netdMissing {
            AlertCard(
                symbol: "exclamationmark.triangle",
                title: "Network monitor stopped",
                detail: "Websites and DNS fail until it runs.",
                action: "Start", prominent: false
            ) { Task { await model.settings.startNetd() } }
            .disabled(model.settings.isBusy)
        }
    }

    private func stats(_ summary: MenuBarSummary) -> some View {
        HStack(spacing: 4) {
            StatTile(title: "Sessions", value: summary.sessions, hot: false)
            StatTile(title: "Processes", value: summary.processes, hot: false)
            StatTile(title: "Blocked, 1 h", value: summary.deniedLastHour, hot: summary.deniedLastHour > 0)
        }
        .padding(.horizontal, 6)
        .padding(.vertical, 2)
    }

    private var footer: some View {
        HStack {
            Text(model.sandbox.environment.sandvaultUser)
            Spacer()
            Text(verbatim: "v\(BundleIdentity.version)")
        }
        .font(.system(size: 11))
        .foregroundStyle(.tertiary)
        .padding(.horizontal, 10)
        .padding(.top, 2)
        .padding(.bottom, 6)
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

// MARK: Protection

/// The four levels as round buttons, like Focus or AirDrop in Control Center. A setting only expert mode makes
/// leaves all four unselected.
struct ProtectionButtons: View {
    let firewall: FirewallModel

    var body: some View {
        let current = firewall.panicActive ? nil : firewall.protection
        HStack(spacing: 4) {
            ForEach(ProtectionLevel.allCases) { level in
                Button {
                    Task { await firewall.setProtection(level) }
                } label: {
                    LevelButtonLabel(level: level, selected: level == current)
                }
                .buttonStyle(.plain)
                .accessibilityAddTraits(level == current ? .isSelected : [])
                .help(level.explanation)
            }
        }
        .padding(.horizontal, 6)
        .padding(.top, 4)
        .disabled(firewall.isBusy)
    }
}

struct LevelButtonLabel: View {
    let level: ProtectionLevel
    let selected: Bool
    @State private var hovering = false

    var body: some View {
        VStack(spacing: 5) {
            Image(systemName: level.menuSymbol)
                .font(.system(size: 16, weight: .medium))
                .foregroundStyle(selected ? Color.white : Color.primary)
                .frame(width: 38, height: 38)
                .background(Circle().fill(fill))
            Text(level.title)
                .font(.system(size: 11, weight: selected ? .semibold : .regular))
                .foregroundStyle(selected ? Color.primary : Color.secondary)
        }
        .frame(maxWidth: .infinity)
        .padding(.vertical, 4)
        .contentShape(Rectangle())
        .onHover { hovering = $0 }
        .animation(.easeOut(duration: 0.15), value: selected)
    }

    private var fill: Color {
        if selected { return level == .blockAll ? Color.red : Color.accentColor }
        return Color.primary.opacity(hovering ? 0.13 : 0.08)
    }
}

extension ProtectionLevel {
    var menuSymbol: String {
        switch self {
        case .off: "shield.slash"
        case .watch: "eye"
        case .ask: "questionmark.circle"
        case .blockAll: "nosign"
        }
    }
}

/// Expert mode keeps the firewall mode choice; choosing one saves it and opens the Firewall page with the
/// generated rules to confirm.
struct FirewallModeRow: View {
    let model: AppModel
    let open: (Screen?) -> Void

    var body: some View {
        HStack {
            Text("Firewall mode")
                .foregroundStyle(.secondary)
            Spacer()
            Picker("Firewall mode", selection: mode) {
                ForEach(FirewallMode.allCases, id: \.self) { mode in
                    Text(mode.displayName).tag(mode)
                }
            }
            .labelsHidden()
            .pickerStyle(.menu)
            .fixedSize()
        }
        .font(.system(size: 12))
        .padding(.horizontal, 10)
        .padding(.bottom, 4)
        .disabled(model.firewall.isBusy)
    }

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
}

// MARK: Alerts and counts

struct AlertCard: View {
    let symbol: String
    let title: String
    let detail: String
    let action: String
    let prominent: Bool
    let perform: () -> Void

    var body: some View {
        HStack(spacing: 10) {
            Image(systemName: symbol)
                .font(.system(size: 15, weight: .medium))
                .foregroundStyle(.orange)
            VStack(alignment: .leading, spacing: 1) {
                Text(title)
                    .fontWeight(.semibold)
                if !detail.isEmpty {
                    Text(detail)
                        .font(.system(size: 11.5))
                        .foregroundStyle(.secondary)
                        .lineLimit(1)
                        .truncationMode(.tail)
                }
            }
            Spacer(minLength: 0)
            PillButton(title: action, kind: prominent ? .accent : .quiet, action: perform)
        }
        .padding(.horizontal, 10)
        .padding(.vertical, 8)
        .background(Color.orange.opacity(0.16), in: RoundedRectangle(cornerRadius: 11, style: .continuous))
        .padding(.horizontal, 4)
        .padding(.vertical, 2)
    }
}

struct StatTile: View {
    let title: String
    let value: Int
    let hot: Bool

    var body: some View {
        VStack(alignment: .leading, spacing: 1) {
            Text(verbatim: "\(value)")
                .font(.system(size: 17, weight: .semibold))
                .monospacedDigit()
                .foregroundStyle(hot ? Color.orange : Color.primary)
            Text(title)
                .font(.system(size: 11))
                .foregroundStyle(.secondary)
                .lineLimit(1)
        }
        .frame(maxWidth: .infinity, alignment: .leading)
        .padding(.horizontal, 9)
        .padding(.vertical, 7)
        .background(Color.primary.opacity(0.055), in: RoundedRectangle(cornerRadius: 10, style: .continuous))
    }
}

// MARK: Start rows

/// Default agent, shell and hand-off; sv itself builds a missing sandbox on first use.
struct StartRows: View {
    let model: AppModel
    let chooseAndHandOff: () -> Void

    var body: some View {
        let sandbox = model.sandbox
        let handoff = model.editor.config.handoff
        let agent = handoff.defaultAgent
        Group {
            if agent != .shell {
                IconRow(symbol: "sparkle", prominent: true, title: "Start \(agent.displayName)", detail: "\(place) · \(handoff.terminal.displayName)") {
                    Task { await sandbox.open(agent) }
                }
            }
            IconRow(symbol: "chevron.right", prominent: false, title: "Open Shell", detail: "sv shell") {
                Task { await sandbox.open(.shell) }
            }
            IconRow(symbol: "folder", prominent: false, title: "Hand Off a Repository…", detail: "Or drop a folder here", action: chooseAndHandOff)
        }
        .disabled(sandbox.isBusy)
    }

    /// Where a session starts: the chosen folder or the shared workspace.
    private var place: String {
        if let directory = model.sandbox.startDirectory { return (directory as NSString).lastPathComponent }
        return "Shared workspace"
    }
}

// MARK: Recently blocked

/// A blocked host; Allow appears on hover, like the actions in a Notification Center row.
struct BlockedHostRow: View {
    let denied: DeniedHost
    let allow: () -> Void
    @State private var hovering = false

    var body: some View {
        HStack(spacing: 8) {
            Text(denied.host)
                .font(.system(size: 12, design: .monospaced))
                .lineLimit(1)
                .truncationMode(.middle)
            Spacer(minLength: 4)
            Text(verbatim: "\(denied.count)×")
                .font(.system(size: 11.5))
                .monospacedDigit()
                .foregroundStyle(.secondary)
            PillButton(title: "Allow", kind: .quiet, compact: true, action: allow)
                .help("Allow rule for exactly this host")
                .opacity(hovering ? 1 : 0)
                .allowsHitTesting(hovering)
        }
        .padding(.horizontal, 10)
        .padding(.vertical, 3)
        .background(
            RoundedRectangle(cornerRadius: 9, style: .continuous)
                .fill(Color.primary.opacity(hovering ? 0.055 : 0))
        )
        .contentShape(Rectangle())
        .onHover { hovering = $0 }
        .animation(.easeOut(duration: 0.12), value: hovering)
    }
}

// MARK: Emergency stop

/// Two steps, so a stray click never ends every sandbox process; the confirmation opens in place.
struct EmergencyStop: View {
    @Binding var armed: Bool
    let firewall: FirewallModel

    var body: some View {
        if armed {
            VStack(alignment: .leading, spacing: 8) {
                Text("Block the network and end every process in the sandbox? Your files stay as they are.")
                    .font(.system(size: 12.5))
                    .fixedSize(horizontal: false, vertical: true)
                HStack(spacing: 6) {
                    Spacer()
                    PillButton(title: "Cancel", kind: .quiet) { armed = false }
                        .keyboardShortcut(.cancelAction)
                    PillButton(title: "Stop Sandbox", kind: .destructive) {
                        armed = false
                        Task { await firewall.panic() }
                    }
                }
            }
            .padding(10)
            .background(Color.primary.opacity(0.055), in: RoundedRectangle(cornerRadius: 11, style: .continuous))
            .padding(.horizontal, 4)
            .padding(.vertical, 2)
        } else {
            MenuRow("Emergency Stop…", destructive: true) { armed = true }
                .disabled(firewall.isBusy)
        }
    }
}

// MARK: Building blocks

/// A plain menu row: title, an optional shortcut hint, highlight on hover.
struct MenuRow: View {
    let title: String
    var shortcut: String?
    var destructive = false
    let action: () -> Void

    init(_ title: String, shortcut: String? = nil, destructive: Bool = false, action: @escaping () -> Void) {
        self.title = title
        self.shortcut = shortcut
        self.destructive = destructive
        self.action = action
    }

    var body: some View {
        Button(action: action) {
            HStack {
                Text(title)
                    .foregroundStyle(destructive ? Color.red : Color.primary)
                Spacer()
                if let shortcut {
                    Text(verbatim: shortcut)
                        .foregroundStyle(.tertiary)
                }
            }
            .padding(.horizontal, 10)
            .padding(.vertical, 4)
        }
        .buttonStyle(HighlightRowStyle())
    }
}

/// A row with a round symbol and a second line, like a network in the Wi-Fi menu.
struct IconRow: View {
    let symbol: String
    let prominent: Bool
    let title: String
    let detail: String
    let action: () -> Void

    var body: some View {
        Button(action: action) {
            HStack(spacing: 10) {
                Image(systemName: symbol)
                    .font(.system(size: 12, weight: .semibold))
                    .foregroundStyle(prominent ? Color.white : Color.primary)
                    .frame(width: 26, height: 26)
                    .background(Circle().fill(prominent ? Color.accentColor : Color.primary.opacity(0.08)))
                VStack(alignment: .leading, spacing: 0) {
                    Text(title)
                    Text(detail)
                        .font(.system(size: 11.5))
                        .foregroundStyle(.secondary)
                        .lineLimit(1)
                        .truncationMode(.tail)
                }
                Spacer(minLength: 0)
            }
            .padding(.horizontal, 8)
            .padding(.vertical, 5)
        }
        .buttonStyle(HighlightRowStyle())
    }
}

/// Full-width row button with the menu highlight on hover and press.
struct HighlightRowStyle: ButtonStyle {
    func makeBody(configuration: Configuration) -> some View {
        HighlightRow(configuration: configuration)
    }

    private struct HighlightRow: View {
        let configuration: ButtonStyleConfiguration
        @Environment(\.isEnabled) private var isEnabled
        @State private var hovering = false

        var body: some View {
            configuration.label
                .frame(maxWidth: .infinity, alignment: .leading)
                .contentShape(Rectangle())
                .background(
                    RoundedRectangle(cornerRadius: 9, style: .continuous)
                        .fill(Color.primary.opacity(highlight))
                )
                .opacity(isEnabled ? 1 : 0.45)
                .onHover { hovering = $0 }
        }

        private var highlight: Double {
            guard isEnabled else { return 0 }
            if configuration.isPressed { return 0.1 }
            return hovering ? 0.055 : 0
        }
    }
}

/// A small capsule button: accent for the main answer, quiet for the rest, red for the emergency stop.
struct PillButton: View {
    enum Kind { case accent, quiet, destructive }

    let title: String
    let kind: Kind
    var compact = false
    let action: () -> Void

    init(title: String, kind: Kind, compact: Bool = false, action: @escaping () -> Void) {
        self.title = title
        self.kind = kind
        self.compact = compact
        self.action = action
    }

    var body: some View {
        Button(action: action) {
            Text(title)
                .font(.system(size: compact ? 11.5 : 12, weight: .semibold))
                .foregroundStyle(kind == .quiet ? Color.primary : Color.white)
                .padding(.horizontal, compact ? 9 : 11)
                .padding(.vertical, compact ? 2 : 4)
                .background(Capsule().fill(fill))
                .contentShape(Capsule())
        }
        .buttonStyle(.plain)
    }

    private var fill: Color {
        switch kind {
        case .accent: Color.accentColor
        case .quiet: Color.primary.opacity(0.08)
        case .destructive: Color.red
        }
    }
}

struct MenuSeparator: View {
    var body: some View {
        Rectangle()
            .fill(Color.primary.opacity(0.09))
            .frame(height: 0.5)
            .padding(.horizontal, 10)
            .padding(.vertical, 4)
    }
}

struct MenuSectionLabel: View {
    let title: LocalizedStringKey

    init(_ title: LocalizedStringKey) {
        self.title = title
    }

    var body: some View {
        Text(title)
            .font(.system(size: 11, weight: .semibold))
            .foregroundStyle(.secondary)
            .padding(.horizontal, 10)
            .padding(.top, 6)
            .padding(.bottom, 2)
    }
}
