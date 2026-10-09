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

struct LearnSection: View {
    @Bindable var rules: RulesModel

    var body: some View {
        Section("Learn mode") {
            HStack {
                Button(learnTitle) { toggle() }
                Toggle("Include unattributed", isOn: $rules.includeUnattributed)
                Spacer()
                Text(verbatim: "\(rules.observed.count) violations")
                    .foregroundStyle(.secondary)
                if !rules.observed.isEmpty {
                    Button("Clear") { rules.clearObserved() }
                }
            }
            Text("Follows sandbox denials in the unified log (needs an administrator account) and proposes the smallest allow rules.")
                .font(.callout)
                .foregroundStyle(.secondary)
            if let error = rules.learnError {
                MessageBanner(message: error) {}
            }
            ForEach(rules.suggestions) { suggestion in
                SuggestionRow(suggestion: suggestion) {
                    Task { await rules.accept(suggestion) }
                } dismiss: {
                    rules.dismiss(suggestion)
                }
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

struct SuggestionRow: View {
    let suggestion: RuleSuggestion
    let accept: () -> Void
    let dismiss: () -> Void

    var body: some View {
        HStack(alignment: .top) {
            VStack(alignment: .leading, spacing: 2) {
                Text(suggestion.summary)
                    .font(.system(.body, design: .monospaced))
                    .textSelection(.enabled)
                Text(verbatim: "\(suggestion.occurrences) times by \(suggestion.processes.joined(separator: ", "))")
                    .font(.caption)
                    .foregroundStyle(.secondary)
                ForEach(suggestion.examples, id: \.self) { example in
                    Text(example)
                        .font(.system(.caption, design: .monospaced))
                        .foregroundStyle(.secondary)
                }
                if let note = suggestion.note {
                    Text(note)
                        .font(.caption)
                        .foregroundStyle(.orange)
                }
            }
            Spacer()
            Button("Accept", action: accept)
            Button("Dismiss", action: dismiss)
        }
    }
}
