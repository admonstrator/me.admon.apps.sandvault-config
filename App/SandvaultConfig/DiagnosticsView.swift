import AppKit
import SandvaultAppModel
import SandvaultCore
import SwiftUI

/// Diagnostics (Expert): the doctor checks, netd and the helper, and the whole report as plain text (D53).
struct DiagnosticsView: View {
    let model: AppModel
    @State private var copied = false

    var body: some View {
        let overview = model.overview
        VStack(spacing: 0) {
            Form {
                Section("Services") {
                    LabeledContent("sandvault-netd", value: netdState)
                    LabeledContent("netd LaunchAgent", value: model.settings.netdAgentSummary)
                    LabeledContent("Helper", value: model.settings.helperInstalled ? "installed" : "not installed")
                    LabeledContent("Firewall", value: model.editor.config.network.mode.displayName)
                }
                if overview.sections.isEmpty {
                    Section {
                        if overview.isRefreshing {
                            ProgressView("Running the checks…")
                                .controlSize(.small)
                        } else {
                            Text("No checks yet. Click Check Again.")
                                .foregroundStyle(.secondary)
                        }
                    }
                }
                ForEach(overview.sections) { section in
                    Section(section.title) {
                        ForEach(section.checks) { check in
                            CheckRow(check: check)
                        }
                    }
                }
                Section {
                    if let link = model.settings.svctlLinkCommand {
                        Text(verbatim: link)
                            .font(.system(.callout, design: .monospaced))
                            .textSelection(.enabled)
                    }
                    Text(verbatim: "svctl doctor --json")
                        .font(.system(.callout, design: .monospaced))
                        .textSelection(.enabled)
                } header: {
                    Text("Command line")
                } footer: {
                    Text("The same checks from Terminal. The first line puts svctl on your PATH.")
                }
            }
            .formStyle(.grouped)
        }
        .navigationTitle(Screen.diagnostics.title)
        .navigationSubtitle(subtitle)
        .toolbar {
            ToolbarItemGroup {
                Button {
                    copyReport()
                } label: {
                    Label(copied ? "Copied" : "Copy Report", systemImage: copied ? "checkmark" : "doc.on.doc")
                }
                .help("Copy every check as plain text, for a bug report")
                Button {
                    Task {
                        await model.overview.refresh()
                        await model.settings.refresh()
                    }
                } label: {
                    Label("Check Again", systemImage: "arrow.clockwise")
                }
                .disabled(overview.isRefreshing)
            }
        }
        .task { await model.settings.refresh() }
    }

    private var netdState: String {
        model.netd.isConnected ? "running" : "not running"
    }

    /// `1 warning`, `All checks passed`.
    private var subtitle: String {
        let checks = model.overview.checks
        if checks.isEmpty { return model.overview.isRefreshing ? "Checking…" : "Not checked yet" }
        let failures = checks.filter { $0.state == .failure }.count
        let warnings = checks.filter { $0.state == .warning }.count
        var parts: [String] = []
        if failures > 0 { parts.append(Format.count(failures, "failure")) }
        if warnings > 0 { parts.append(Format.count(warnings, "warning")) }
        return parts.isEmpty ? "All checks passed" : parts.joined(separator: " · ")
    }

    private func copyReport() {
        NSPasteboard.general.clearContents()
        NSPasteboard.general.setString(report, forType: .string)
        copied = true
        Task {
            try? await Task.sleep(nanoseconds: 2_000_000_000)
            copied = false
        }
    }

    /// Plain text of everything the page shows.
    private var report: String {
        var lines = ["Sandvault Config diagnostics, \(Date().formatted(.iso8601))", ""]
        lines.append("sandvault-netd: \(netdState)")
        lines.append("netd LaunchAgent: \(model.settings.netdAgentSummary)")
        lines.append("Helper: \(model.settings.helperInstalled ? "installed" : "not installed")")
        lines.append("Firewall: \(model.editor.config.network.mode.displayName)")
        for section in model.overview.sections {
            lines.append("")
            lines.append("[\(section.title)]")
            for check in section.checks {
                let state = check.state.rawValue.uppercased().padding(toLength: 8, withPad: " ", startingAt: 0)
                lines.append("\(state) \(check.title): \(check.detail)")
                if let fix = check.fix, check.state >= .warning {
                    lines.append("         Fix: \(fix)")
                }
            }
        }
        return lines.joined(separator: "\n")
    }
}
