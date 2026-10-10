import SandvaultAppModel
import SandvaultCore
import SandvaultEnforce
import SwiftUI

struct RulesView: View {
    let rules: RulesModel

    var body: some View {
        VStack(spacing: 0) {
            MessageArea(message: rules.message) { rules.message = nil }
            Form {
                RuleSettingsSection(rules: rules)
                RuleListSection(rules: rules)
                AddRuleSection(rules: rules)
                ProfileSection(rules: rules)
                LearnSection(rules: rules)
            }
            .formStyle(.grouped)
        }
        .navigationTitle(Screen.rules.title)
    }
}

struct RuleSettingsSection: View {
    let rules: RulesModel

    var body: some View {
        Section("Preset") {
            Picker("Preset", selection: preset) {
                ForEach(SandboxPreset.allCases, id: \.self) { preset in
                    Text(preset.displayName).tag(preset)
                }
            }
            .pickerStyle(.segmented)
            Text("Hardened denies osascript, open, launchctl, screencapture and similar tools plus the clipboard and LaunchServices. Verify with your agents before relying on it.")
                .font(.callout)
                .foregroundStyle(.secondary)
            Toggle("Re-apply automatically when sv --rebuild removed the block", isOn: autoReapply)
        }
    }

    private var preset: Binding<SandboxPreset> {
        Binding<SandboxPreset>(get: { rules.settings.preset }, set: { preset in Task { await rules.setPreset(preset) } })
    }

    private var autoReapply: Binding<Bool> {
        Binding<Bool>(get: { rules.settings.autoReapply }, set: { on in Task { await rules.setAutoReapply(on) } })
    }
}

struct RuleListSection: View {
    let rules: RulesModel

    var body: some View {
        Section("Rules (last match wins; these come after sv's profile)") {
            if rules.rules.isEmpty {
                Text("No rules. sv's profile applies unchanged.")
                    .foregroundStyle(.secondary)
            }
            ForEach(rules.rules) { rule in
                HStack {
                    Text(rule.effect.displayName)
                        .foregroundStyle(rule.effect == .deny ? Color.red : Color.green)
                        .frame(width: 50, alignment: .leading)
                    Text(rule.summary)
                        .font(.system(.body, design: .monospaced))
                        .textSelection(.enabled)
                    if let note = rule.note {
                        Text(note).foregroundStyle(.secondary)
                    }
                    Spacer()
                    Button {
                        Task { await rules.removeRule(rule.id) }
                    } label: {
                        Image(systemName: "minus.circle")
                    }
                    .buttonStyle(.borderless)
                    .help("Remove")
                }
            }
        }
    }
}

struct AddRuleSection: View {
    enum Kind: String, CaseIterable {
        case file = "File"
        case mach = "Mach service"
        case exec = "Executable"
    }

    let rules: RulesModel
    @State private var kind = Kind.file
    @State private var target = ""
    @State private var access = FileAccess.read
    @State private var match = PathMatch.subpath
    @State private var effect = RuleEffect.allow
    @State private var note = ""

    var body: some View {
        Section("Add a rule") {
            Picker("Kind", selection: $kind) {
                ForEach(Kind.allCases, id: \.self) { kind in
                    Text(kind.rawValue).tag(kind)
                }
            }
            .pickerStyle(.segmented)
            TextField(placeholder, text: $target)
            if kind == .file {
                Picker("Access", selection: $access) {
                    ForEach(FileAccess.allCases, id: \.self) { access in
                        Text(access.displayName).tag(access)
                    }
                }
                Picker("Match", selection: $match) {
                    ForEach(PathMatch.allCases, id: \.self) { match in
                        Text(match.displayName).tag(match)
                    }
                }
            }
            Picker("Effect", selection: $effect) {
                ForEach(RuleEffect.allCases, id: \.self) { effect in
                    Text(effect.displayName).tag(effect)
                }
            }
            .pickerStyle(.segmented)
            TextField("Note", text: $note)
            HStack {
                Spacer()
                Button("Add Rule") { add() }
                    .disabled(target.isEmpty)
            }
        }
    }

    private var placeholder: String {
        kind == .mach ? "Service name, e.g. com.apple.pasteboard.1" : "Absolute path (real path: /private/tmp, not /tmp)"
    }

    private func add() {
        Task {
            let added: Bool
            switch kind {
            case .file: added = await rules.addFileRule(path: target, match: match, access: access, effect: effect, note: note)
            case .mach: added = await rules.addMachRule(name: target, effect: effect, note: note)
            case .exec: added = await rules.addExecRule(path: target, effect: effect, note: note)
            }
            if added {
                target = ""
                note = ""
            }
        }
    }
}

struct ProfileSection: View {
    let rules: RulesModel
    @State private var confirmApply = false
    @State private var confirmReset = false

    var body: some View {
        Section("sv's profile") {
            if let plan = rules.plan {
                LabeledContent("Managed block") {
                    Text(plan.drift.displayName)
                        .foregroundStyle(plan.drift.tint.color)
                }
                if plan.svPartChanged {
                    Label("sv rewrote its part of the profile since the last apply.", systemImage: "exclamationmark.triangle")
                        .foregroundStyle(.orange)
                }
                if plan.hasChanges {
                    CodeView(text: plan.unifiedDiff)
                        .frame(minHeight: 160, maxHeight: 320)
                }
            } else if let error = rules.planError {
                MessageBanner(message: error) {}
            }
            HStack {
                Button("Refresh") { rules.refreshPlan() }
                Spacer()
                Button("Reset…") { confirmReset = true }
                    .disabled(rules.isBusy)
                Button("Apply Rules…") { confirmApply = true }
                    .disabled(rules.isBusy)
            }
            .confirmationDialog("Write the managed block into sv's profile?", isPresented: $confirmApply) {
                Button("Apply") { Task { await rules.apply() } }
            } message: {
                Text("The helper validates the profile with sandbox-exec first. New sv sessions use it.")
            }
            .confirmationDialog("Remove the managed block from sv's profile?", isPresented: $confirmReset) {
                Button("Reset", role: .destructive) { Task { await rules.reset() } }
            }
        }
        .onAppear { rules.refreshPlan() }
    }
}

/// Learn mode in plain words (D46): one card per suggestion, at most two allow choices and Keep Blocked.
struct LearnSection: View {
    @Bindable var rules: RulesModel

    var body: some View {
        Section("Learn mode") {
            HStack {
                Button(learnTitle) { toggle() }
                if rules.isLearning {
                    TimelineView(.periodic(from: .now, by: 30)) { context in
                        Label(rules.watchingText(now: context.date) ?? "Watching", systemImage: "record.circle")
                            .foregroundStyle(.red)
                    }
                }
                Toggle("Include unattributed", isOn: $rules.includeUnattributed)
                Spacer()
                if !rules.observed.isEmpty {
                    Button("Clear") { rules.clearObserved() }
                }
            }
            Text("Everything the sandbox was not allowed to do while you watched. Allow what you need, keep the rest blocked. Nothing changes until you choose.")
                .font(.callout)
                .foregroundStyle(.secondary)
            if let error = rules.learnError {
                MessageBanner(message: error) {}
            }
            ForEach(rules.learnCards) { card in
                LearnCardView(card: card, decision: rules.decisions[card.id], rules: rules)
            }
        }
    }

    private var learnTitle: String {
        rules.isLearning ? "Stop Learning" : "Start Learning"
    }

    private func toggle() {
        if rules.isLearning {
            rules.stopLearning()
        } else {
            rules.startLearning()
        }
    }
}

struct LearnCardView: View {
    let card: LearnCard
    let decision: LearnDecision?
    let rules: RulesModel

    private var symbol: String {
        switch card.kind {
        case .folder: "folder"
        case .file: "doc"
        case .sensitive: "key"
        case .program: "play.fill"
        case .service: "gearshape.2"
        }
    }

    private var tint: Color {
        switch card.kind {
        case .folder: .orange
        case .file: .blue
        case .sensitive: .red
        case .program: .purple
        case .service: .gray
        }
    }

    var body: some View {
        HStack(alignment: .top, spacing: 12) {
            Image(systemName: symbol)
                .font(.system(size: 15, weight: .semibold))
                .foregroundStyle(tint)
                .frame(width: 34, height: 34)
                .background(tint.opacity(0.14), in: RoundedRectangle(cornerRadius: 8))
            VStack(alignment: .leading, spacing: 6) {
                sentence
                    .fontWeight(.medium)
                Text(card.reason)
                    .font(.callout)
                    .foregroundStyle(card.warning ? Color.red : Color.secondary)
                if let decision {
                    HStack {
                        Text(Self.stateText(decision))
                            .foregroundStyle(.secondary)
                        Button("Undo") { Task { await rules.undo(card) } }
                            .buttonStyle(.borderless)
                    }
                } else {
                    HStack {
                        ForEach(Array(card.choices.enumerated()), id: \.element.id) { index, choice in
                            ChoiceButton(title: choice.title, prominent: index == 0 && !card.warning) {
                                Task { await rules.allow(card, choice) }
                            }
                        }
                        ChoiceButton(title: "Keep Blocked", prominent: card.warning) { rules.keepBlocked(card) }
                    }
                }
                DisclosureGroup("Details") {
                    VStack(alignment: .leading, spacing: 2) {
                        Text(card.suggestion.summary)
                        ForEach(card.details, id: \.self) { line in
                            Text(line)
                        }
                    }
                    .font(.system(.caption, design: .monospaced))
                    .foregroundStyle(.secondary)
                    .textSelection(.enabled)
                    .frame(maxWidth: .infinity, alignment: .leading)
                }
                .font(.caption)
            }
        }
        .padding(.vertical, 4)
        .opacity(decision == nil ? 1 : 0.7)
    }

    @ViewBuilder private var sentence: some View {
        if let place = card.place {
            Text("\(card.lead) \(Text(place).font(.system(.body, design: .monospaced)))")
        } else {
            Text(card.lead)
        }
    }

    static func stateText(_ decision: LearnDecision) -> String {
        switch decision {
        case .allowed(_, let ruleID): ruleID == nil ? "Allowed · the rule already existed" : "Allowed · rule added"
        case .keptBlocked: "Stays blocked"
        }
    }
}

private struct ChoiceButton: View {
    let title: String
    let prominent: Bool
    let action: () -> Void

    var body: some View {
        if prominent {
            Button(title, action: action)
                .buttonStyle(.borderedProminent)
        } else {
            Button(title, action: action)
                .buttonStyle(.bordered)
        }
    }
}
