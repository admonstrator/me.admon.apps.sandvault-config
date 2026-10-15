import SandvaultAppModel
import SandvaultCore
import SandvaultObserve
import SwiftUI
import TipKit

/// Home (D53): how protected the sandbox is, the protection level, the next setup step, start buttons and the
/// newest websites. Expert also gets the system details and the doctor checks.
struct OverviewView: View {
    let model: AppModel
    private let protectionTip = ProtectionTip()
    private let basicsTip = DeveloperBasicsTip()

    private var expert: Bool { model.mode == .expert }
    /// Tips are for newcomers; Expert never shows them.
    private var showsTips: Bool { model.mode != .expert }

    var body: some View {
        let summary = model.menuBar
        let status = HomeStatus(
            protection: model.firewall.protection, panicActive: summary.panicActive, netdMissing: summary.netdMissing,
            firewallMode: model.editor.config.network.mode, developerBasics: model.settings.developerBasics.enabled
        )
        let step = HomeStep(model.overview.nextStep, mode: model.mode)
        VStack(spacing: 0) {
            MessageArea(message: model.firewall.message) { model.firewall.message = nil }
            MessageArea(message: model.sandbox.message) { model.sandbox.message = nil }
            MessageArea(message: model.settings.message) { model.settings.message = nil }
            Form {
                Section {
                    HomeStatusCard(status: status, summary: summary)
                }

                Section {
                    if showsTips {
                        TipView(protectionTip)
                    }
                    ProtectionPicker(firewall: model.firewall, netdRunning: model.netd.isConnected, mode: model.mode, showsExplanation: false)
                    if expert {
                        Button("Firewall & Proxy…") { model.select(.firewall) }
                            .buttonStyle(.link)
                    }
                    if showsTips && model.settings.developerBasics.enabled && model.firewall.protection == .ask {
                        TipView(basicsTip)
                    }
                } header: {
                    Text("Protection")
                } footer: {
                    Text("How the sandbox may use the internet. You can change it any time.")
                }

                if expert || (!step.isDone && step.action != .endStop) {
                    Section("Next step") {
                        HomeStepView(step: step, busy: busy, perform: perform)
                    }
                }

                if model.sandbox.installed {
                    Section {
                        StartButtons(model: model)
                    } header: {
                        Text("Start")
                    } footer: {
                        Text("Programs started here run as a separate Mac user. They see the shared workspace and the websites you allow, nothing else of yours.")
                    }
                }

                if model.mode >= .advanced && !model.overview.sessions.isEmpty {
                    Section("Running now") {
                        ForEach(model.overview.sessions) { session in
                            SessionRow(session: session)
                        }
                    }
                }

                RecentWebsitesSection(model: model)

                if expert {
                    Section("System") {
                        LabeledContent("Firewall", value: model.editor.config.network.mode.displayName)
                        LabeledContent("sandvault-netd", value: model.netd.isConnected ? "running" : "not running")
                        LabeledContent("Sandbox processes", value: String(model.processes.processCount))
                        LabeledContent("Listening ports", value: listeningPorts)
                        if let errors = model.overview.summary?.errors, !errors.isEmpty {
                            Text(errors.joined(separator: "\n"))
                                .font(.caption)
                                .foregroundStyle(.secondary)
                        }
                    }
                    // The checks stay here in Expert until Diagnostics has its own page.
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
        .navigationSubtitle(summary.statusText)
        .toolbar {
            ToolbarItem(placement: .automatic) {
                Button {
                    Task { await model.overview.refresh() }
                } label: {
                    Label("Refresh", systemImage: "arrow.clockwise")
                }
                .help("Check the setup again")
                .disabled(model.overview.isRefreshing)
            }
        }
    }

    private var busy: Bool {
        model.settings.isBusy || model.firewall.isBusy || model.sandbox.isBusy
    }

    private func perform(_ action: HomeStepAction) {
        switch action {
        case .installHelper:
            Task { await model.settings.installHelper() }
        case .startNetd:
            Task { await model.settings.startNetd() }
        case .createSandbox:
            Task {
                await model.sandbox.create()
                await model.overview.refresh()
            }
        case .endStop:
            Task { await AppRuntime.endEmergencyStop() }
        case .applyFirewall:
            Task {
                await model.firewall.prepareApply()
                await model.firewall.confirmApply()
            }
        case .open(let screen):
            model.select(screen)
        }
    }

    private var listeningPorts: String {
        let ports = model.overview.summary?.listeningPorts ?? []
        return ports.isEmpty ? "none" : ports.map(String.init).joined(separator: ", ")
    }
}

/// The big status card: a symbol, one sentence, the counts, and the way out of a stop or to waiting requests.
struct HomeStatusCard: View {
    let status: HomeStatus
    let summary: MenuBarSummary

    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            HStack(alignment: .top, spacing: 12) {
                Image(systemName: status.symbolName)
                    .font(.system(size: 22, weight: .semibold))
                    .foregroundStyle(.white)
                    .frame(width: 44, height: 44)
                    .background(status.tint.color, in: RoundedRectangle(cornerRadius: 11, style: .continuous))
                VStack(alignment: .leading, spacing: 3) {
                    Text(status.title)
                        .font(.title3.weight(.semibold))
                    Text(status.detail)
                        .foregroundStyle(.secondary)
                        .fixedSize(horizontal: false, vertical: true)
                }
                Spacer(minLength: 0)
                if summary.panicActive {
                    Button("End Stop") { Task { await AppRuntime.endEmergencyStop() } }
                        .buttonStyle(.borderedProminent)
                        .help("Brings back the protection level \(AppRuntime.resumeLevel.title)")
                } else if summary.pendingAsks > 0 {
                    Button("Review…") { AppRuntime.showAskPanels() }
                        .buttonStyle(.borderedProminent)
                        .help("Show the websites waiting for your answer")
                }
            }
            HStack(spacing: 6) {
                StatTile(title: "Sessions", value: summary.sessions, hot: false)
                StatTile(title: "Blocked, last hour", value: summary.deniedLastHour, hot: summary.deniedLastHour > 0)
                StatTile(title: "Waiting for you", value: summary.pendingAsks, hot: summary.pendingAsks > 0)
            }
        }
        .padding(.vertical, 6)
    }
}

/// The next setup step with its button, where the app can do it.
struct HomeStepView: View {
    let step: HomeStep
    let busy: Bool
    let perform: (HomeStepAction) -> Void

    var body: some View {
        HStack(alignment: .top, spacing: 10) {
            Image(systemName: step.isDone ? "checkmark.seal.fill" : "arrow.right.circle.fill")
                .font(.title2)
                .foregroundStyle(step.isDone ? Color.green : Color.accentColor)
            VStack(alignment: .leading, spacing: 4) {
                Text(step.title)
                    .font(.headline)
                Text(step.detail)
                    .foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true)
                if let command = step.command {
                    Text(command)
                        .font(.system(.callout, design: .monospaced))
                        .textSelection(.enabled)
                }
            }
            Spacer(minLength: 8)
            if let action = step.action, let title = step.actionTitle {
                Button(title) { perform(action) }
                    .buttonStyle(.borderedProminent)
                    .disabled(busy)
            }
        }
        .padding(.vertical, 4)
    }
}

/// The default agent and a shell, in the configured terminal.
struct StartButtons: View {
    let model: AppModel

    var body: some View {
        let agent = model.editor.config.handoff.defaultAgent
        HStack(spacing: 10) {
            if agent != .shell {
                Button {
                    Task { await model.sandbox.open(agent) }
                } label: {
                    Label("Start \(agent.displayName)", systemImage: "sparkle")
                }
                .buttonStyle(.borderedProminent)
            }
            Button {
                Task { await model.sandbox.open(.shell) }
            } label: {
                Label("Open Shell", systemImage: "terminal")
            }
            Spacer()
            Text("in \(model.editor.config.handoff.terminal.displayName)")
                .font(.callout)
                .foregroundStyle(.secondary)
        }
        .controlSize(.large)
        .disabled(model.sandbox.isBusy)
        .padding(.vertical, 2)
    }
}

/// The newest websites the sandbox used, with a link to the Websites page.
struct RecentWebsitesSection: View {
    let model: AppModel

    var body: some View {
        let websites = ActivityItem.recentWebsites(model.activity.items)
        Section {
            if websites.isEmpty {
                Text("No websites yet. They appear here as soon as the sandbox opens one.")
                    .foregroundStyle(.secondary)
            }
            ForEach(websites) { item in
                RecentWebsiteRow(item: item)
            }
            Button("Show All Websites") { model.select(.websites) }
        } header: {
            Text("Recent websites")
        } footer: {
            Text(hint)
        }
    }

    private var hint: String {
        switch model.editor.config.network.mode {
        case .off, .open: "While protection is off, only addresses are visible. Choose Watch or Ask to see websites by name."
        case .blocked: "The sandbox has no network, so nothing new appears here."
        case .watch, .proxyOnly: "Newest first. Allow or block a website on the Websites page."
        }
    }
}

struct RecentWebsiteRow: View {
    let item: ActivityItem

    var body: some View {
        HStack(spacing: 10) {
            Image(systemName: "globe")
                .foregroundStyle(item.tint.color)
                .frame(width: 18)
            VStack(alignment: .leading, spacing: 1) {
                Text(item.title)
                    .lineLimit(1)
                    .truncationMode(.middle)
                Text(item.detail)
                    .font(.caption)
                    .foregroundStyle(.secondary)
                    .lineLimit(1)
            }
            Spacer()
            Text(item.status)
                .font(.callout)
                .foregroundStyle(item.tint.color)
        }
    }
}

/// The protection levels the mode offers; choosing one saves and applies it at once.
struct ProtectionPicker: View {
    let firewall: FirewallModel
    let netdRunning: Bool
    var mode: InterfaceMode = .expert
    /// Home shows the current level's sentence in its status card instead.
    var showsExplanation = true

    var body: some View {
        Picker("Protection", selection: level) {
            ForEach(ProtectionLevel.choices(for: mode)) { level in
                Text(level.title).tag(Optional(level))
            }
        }
        .pickerStyle(.segmented)
        .labelsHidden()
        .disabled(firewall.isBusy)
        if showsExplanation {
            if let current = firewall.protection {
                Text(current.explanation)
                    .font(.callout)
                    .foregroundStyle(.secondary)
                if firewall.network.mode.needsNetd && !netdRunning {
                    Label("sandvault-netd is not running, so the sandbox has no web access. Install it in Settings.", systemImage: "exclamationmark.triangle")
                        .foregroundStyle(.orange)
                }
            } else {
                Text("Custom settings from Expert mode: \(firewall.network.mode.displayName). Choosing a level replaces them.")
                    .font(.callout)
                    .foregroundStyle(.secondary)
            }
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
            Text(verbatim: "\(session.processCount) programs · \(Format.duration(session.elapsedSeconds))")
                .foregroundStyle(.secondary)
            ShowProcessButton(title: "Details", reference: ProcessReference(pid: session.rootPID))
        }
    }
}
