import AppKit
import SandvaultAppModel
import SandvaultCore
import SwiftUI

/// Websites: every website the sandbox used, what decides each one, the developer basics and your own rules (D53).
struct WebsitesView: View {
    let model: AppModel
    @Bindable var websites: WebsitesModel

    init(model: AppModel) {
        self.model = model
        _websites = Bindable(model.websites)
    }

    var body: some View {
        let mode = model.mode
        let rows = websites.rows
        VStack(spacing: 0) {
            MessageArea(message: websites.message) { websites.message = nil }
            Form {
                Section {
                    Label(websites.hint, systemImage: "info.circle")
                        .foregroundStyle(.secondary)
                }
                Section {
                    LabeledContent {
                        Button("Change…") { model.showSettings(.websites) }
                    } label: {
                        Text("Developer basics")
                        Text(websites.basicsSummary.map { "Always allowed: \($0)" } ?? "Off. Every website follows your protection level.")
                    }
                }
                Section {
                    if rows.isEmpty {
                        Text(emptyText)
                            .foregroundStyle(.secondary)
                    }
                    ForEach(rows) { row in
                        WebsiteRowView(row: row, mode: mode, websites: websites, showRequests: requestsAction(row, mode: mode))
                    }
                } header: {
                    Text("Websites")
                }
                Section {
                    if websites.rules.isEmpty {
                        Text("No rules yet. Allow or Block a website to add one.")
                            .foregroundStyle(.secondary)
                    }
                    ForEach(websites.rules) { rule in
                        WebsiteRuleRow(rule: rule, mode: mode) {
                            Task { await websites.removeRule(rule) }
                        }
                    }
                } header: {
                    Text("Your rules")
                } footer: {
                    Text("Your rules come first, then developer basics, then your protection level.")
                }
            }
            .formStyle(.grouped)
        }
        .navigationTitle(Screen.websites.title)
        .navigationSubtitle(websites.summary)
        .searchable(text: $websites.search, prompt: "Search websites")
        .toolbar {
            ToolbarItem(placement: .principal) {
                Picker("Show", selection: $websites.filter) {
                    ForEach(WebsiteFilter.allCases) { filter in
                        Label(filter.title, systemImage: filter.symbolName).tag(filter)
                    }
                }
                .pickerStyle(.segmented)
                .labelsHidden()
                .help("Show all websites, only the allowed ones or only the blocked ones")
            }
        }
    }

    /// Activity > Web traffic filtered to the website; from Advanced, where Activity exists.
    private func requestsAction(_ row: WebsiteRow, mode: InterfaceMode) -> (() -> Void)? {
        guard mode >= .advanced, !row.lookupOnly else { return nil }
        let host = row.host
        return {
            model.activity.showRequests(of: host)
            model.select(.activity)
        }
    }

    private var emptyText: String {
        if !websites.search.trimmingCharacters(in: .whitespaces).isEmpty { return "No website matches the search." }
        switch websites.filter {
        case .all: return "No websites yet. Every website the sandbox uses appears here."
        case .allowed: return "No allowed websites."
        case .blocked: return "No blocked websites."
        }
    }
}

/// One website: state, name, program and count, when it was last used, and the one action that changes it.
struct WebsiteRowView: View {
    let row: WebsiteRow
    let mode: InterfaceMode
    let websites: WebsitesModel
    let showRequests: (() -> Void)?

    var body: some View {
        HStack(spacing: 10) {
            Image(systemName: row.state.symbolName)
                .foregroundStyle(row.state.tint.color)
                .frame(width: 18)
            VStack(alignment: .leading, spacing: 2) {
                Text(verbatim: row.host)
                    .fontWeight(.medium)
                    .lineLimit(1)
                    .truncationMode(.middle)
                Text(verbatim: row.detail(mode: mode))
                    .font(.caption)
                    .foregroundStyle(.secondary)
                    .lineLimit(1)
                    .truncationMode(.tail)
            }
            Spacer(minLength: 8)
            VStack(alignment: .trailing, spacing: 3) {
                Text(row.state.title)
                    .font(.caption.weight(.medium))
                    .foregroundStyle(row.state.tint.color)
                    .padding(.horizontal, 7)
                    .padding(.vertical, 2)
                    .background(row.state.tint.color.opacity(0.14), in: Capsule())
                Text(row.lastSeen, format: .relative(presentation: .named))
                    .font(.caption2)
                    .foregroundStyle(.secondary)
            }
            primaryAction
                .controlSize(.small)
        }
        .padding(.vertical, 2)
        .help(row.note(mode: mode))
        .contextMenu {
            if row.canAllow {
                Button("Allow") { Task { await websites.allow(row) } }
            }
            if row.canBlock {
                Button("Block") { Task { await websites.block(row) } }
            }
            if let showRequests {
                Divider()
                Button("Show Requests", action: showRequests)
            }
            Divider()
            Button("Copy Name") {
                NSPasteboard.general.clearContents()
                NSPasteboard.general.setString(row.host, forType: .string)
            }
        }
    }

    @ViewBuilder
    private var primaryAction: some View {
        if row.state == .waiting {
            Button("Review…") { AppRuntime.showAskPanels() }
                .buttonStyle(.borderedProminent)
                .help("Open the request window to answer")
        } else if row.isBlocked && row.canAllow {
            Button("Allow") { Task { await websites.allow(row) } }
                .help("Let the sandbox use this website")
        } else if !row.isBlocked && row.state != .allowedByBasics && row.canBlock {
            Button("Block") { Task { await websites.block(row) } }
                .help("Stop the sandbox from using this website")
        }
    }
}

/// One rule of yours: pattern, what it covers, its action and a remove button.
struct WebsiteRuleRow: View {
    let rule: DomainRule
    let mode: InterfaceMode
    let remove: () -> Void

    var body: some View {
        LabeledContent {
            HStack(spacing: 10) {
                Text(rule.websiteActionTitle)
                    .foregroundStyle(rule.websiteActionTint.color)
                Button(action: remove) {
                    Image(systemName: "minus.circle")
                }
                .buttonStyle(.borderless)
                .help("Remove this rule")
                .accessibilityLabel(Text("Remove \(rule.websiteTitle(mode: mode))"))
            }
        } label: {
            Text(verbatim: rule.websiteTitle(mode: mode))
                .font(.system(.body, design: .monospaced))
            Text(rule.websiteScope)
        }
    }
}
