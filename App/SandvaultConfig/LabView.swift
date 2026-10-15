import SandvaultAppModel
import SandvaultCore
import SandvaultEnforce
import SwiftUI

/// Lab (D52): try software in the sandbox, see what it changed, rewind to a checkpoint.
struct LabView: View {
    let model: AppModel

    var body: some View {
        LabPage(lab: model.lab)
    }
}

struct LabPage: View {
    @Bindable var lab: LabModel
    @State private var rewindTarget: LabCheckpoint?
    @State private var confirmEnd = false

    var body: some View {
        VStack(spacing: 0) {
            MessageArea(message: lab.message) { lab.message = nil }
            Form {
                if case .notAvailableYet(let note) = lab.availability {
                    Section { NotAvailableView(title: "Lab is not available here", note: note) }
                } else if lab.isRunning {
                    sessionSection
                    findingsSection
                    serversSection
                    checkpointsSection
                    if let comparison = lab.comparison { changesSection(comparison) }
                } else {
                    introSection
                    settingsSection
                }
            }
            .formStyle(.grouped)
        }
        .navigationTitle("Lab")
        .task { await lab.refresh() }
        .sheet(item: Binding(get: { lab.diff }, set: { if $0 == nil { lab.closeDiff() } })) { diff in
            LabDiffSheet(diff: diff) { lab.closeDiff() }
        }
        .confirmationDialog(
            "Rewind to \(rewindTarget.map { LabModel.time($0.takenAt) } ?? "")?",
            isPresented: Binding(get: { rewindTarget != nil }, set: { if !$0 { rewindTarget = nil } }),
            presenting: rewindTarget
        ) { checkpoint in
            Button("Rewind") { Task { await lab.rewind(to: checkpoint.id) } }
        } message: { checkpoint in
            Text("Programs in the sandbox end. Its files go back to how they were at \(LabModel.time(checkpoint.takenAt)) (\(checkpoint.label)). Nothing is lost: the current state becomes a checkpoint first.")
        }
        .confirmationDialog("End the Lab session?", isPresented: $confirmEnd) {
            Button("Keep Changes") { Task { await lab.finish(keep: true) } }
            Button("Discard All Changes", role: .destructive) { Task { await lab.finish(keep: false) } }
        } message: {
            Text("Keep the changes and the sandbox goes on from here, or discard everything and it returns to the start. The checkpoints are deleted either way.")
        }
    }

    // MARK: Not running

    private var introSection: some View {
        Section {
            Label {
                VStack(alignment: .leading, spacing: 4) {
                    Text("Try software, then rewind").font(.title3.weight(.semibold))
                    Text("In a Lab session the sandbox saves checkpoints while you work. Jump back to any of them to undo what a program changed, or look at one to see where it put its keys.")
                        .foregroundStyle(.secondary)
                }
            } icon: {
                Image(systemName: "flask").font(.title).foregroundStyle(.purple)
            }
            .padding(.vertical, 4)
        }
    }

    private var settingsSection: some View {
        Section {
            Toggle("Checkpoint when a program starts", isOn: Binding(
                get: { lab.settings.checkpointOnProgramStart },
                set: { on in Task { await lab.setCheckpointOnProgramStart(on) } }
            ))
            Picker("Automatic checkpoint", selection: Binding(
                get: { lab.settings.intervalSeconds },
                set: { seconds in Task { await lab.setInterval(seconds) } }
            )) {
                ForEach(LabModel.intervalChoices, id: \.self) { seconds in
                    Text(seconds < 60 ? "Every \(seconds) seconds" : seconds == 60 ? "Every minute" : "Every \(seconds / 60) minutes").tag(seconds)
                }
            }
            Toggle(isOn: Binding(get: { lab.settings.includeWorkspace }, set: { on in Task { await lab.setIncludeWorkspace(on) } })) {
                Text("Include the shared workspace")
                Text("Otherwise only the sandbox user's home rewinds.")
            }
            Picker("Space for checkpoints", selection: Binding(
                get: { lab.settings.maxStoreBytes },
                set: { bytes in Task { await lab.setMaxStoreBytes(bytes) } }
            )) {
                ForEach(LabModel.spaceChoices, id: \.self) { bytes in Text("Up to \(Format.bytes(bytes))").tag(bytes) }
            }
            HStack {
                busyIndicator
                Spacer()
                Button {
                    Task { await lab.start() }
                } label: {
                    Label("Start Lab Session", systemImage: "flask")
                }
                .buttonStyle(.borderedProminent)
                .disabled(lab.isBusy)
            }
        } header: {
            Text("New session")
        } footer: {
            Text("A checkpoint is a copy-on-write clone: only what changes afterwards uses room on the disk. Older automatic checkpoints are removed when the space is used up. Also any time with Mark Now. \(lab.storageLine)")
        }
    }

    // MARK: Running

    private var sessionSection: some View {
        Section {
            Label {
                VStack(alignment: .leading, spacing: 2) {
                    Text("Lab session · Mac sandbox").fontWeight(.semibold)
                    Text(lab.statusLine).font(.callout).foregroundStyle(.secondary)
                    Text(lab.storageLine).font(.caption).foregroundStyle(.secondary)
                    if let failure = lab.autoFailure {
                        Text("Automatic checkpoint failed: \(failure)").font(.caption).foregroundStyle(.orange)
                    }
                }
            } icon: {
                Image(systemName: "flask.fill").foregroundStyle(.purple)
            }
            HStack {
                TextField("Name (optional)", text: $lab.markLabel)
                    .onSubmit { Task { await lab.mark() } }
                    .frame(maxWidth: 220)
                Button {
                    Task { await lab.mark() }
                } label: {
                    Label("Mark Now", systemImage: "bookmark")
                }
                busyIndicator
                Spacer()
                Button("End Session...") { confirmEnd = true }
            }
            .disabled(lab.isBusy)
        }
    }

    private var findingsSection: some View {
        Section("Found in this session") {
            if lab.findings.isEmpty {
                Text("No keys, credentials, login items or shell changes so far.").foregroundStyle(.secondary)
            }
            ForEach(lab.findings) { finding in
                Label {
                    VStack(alignment: .leading, spacing: 1) {
                        Text("\(finding.kind.title): \(finding.path.display)").textSelection(.enabled)
                        Text(finding.detail).font(.caption).foregroundStyle(.secondary)
                    }
                } icon: {
                    Image(systemName: finding.kind.symbolName).foregroundStyle(Self.tint(finding.kind))
                }
            }
        }
    }

    private var serversSection: some View {
        Section("Servers contacted") {
            if lab.servers.isEmpty {
                Text("None recorded. Servers appear here when the sandbox's traffic goes through netd.").foregroundStyle(.secondary)
            }
            ForEach(lab.servers.prefix(30)) { server in
                LabeledContent {
                    Text(server.blocked > 0 ? "\(server.connections)x · \(server.blocked) blocked" : "\(server.connections)x")
                        .foregroundStyle(server.blocked > 0 ? Color.red : Color.secondary)
                } label: {
                    Text(server.host).textSelection(.enabled)
                    if !server.programs.isEmpty { Text(server.programs.joined(separator: ", ")) }
                }
            }
            if lab.servers.count > 30 {
                Text("and \(lab.servers.count - 30) more").foregroundStyle(.secondary)
            }
        }
    }

    private var checkpointsSection: some View {
        Section("Checkpoints") {
            ForEach(lab.checkpoints) { checkpoint in
                checkpointRow(checkpoint)
            }
        }
    }

    private func checkpointRow(_ checkpoint: LabCheckpoint) -> some View {
        HStack(alignment: .top, spacing: 10) {
            Image(systemName: Self.symbol(checkpoint.reason))
                .foregroundStyle(.purple)
                .frame(width: 18)
            VStack(alignment: .leading, spacing: 2) {
                HStack(spacing: 6) {
                    Text("\(LabModel.time(checkpoint.takenAt)) · \(checkpoint.label)").fontWeight(.medium)
                    if lab.isHead(checkpoint) {
                        Text("Current").font(.caption2.weight(.semibold)).padding(.horizontal, 6).padding(.vertical, 1)
                            .background(Color.purple.opacity(0.15), in: Capsule())
                    }
                }
                Text(lab.summary(checkpoint)).font(.caption).foregroundStyle(checkpoint.findings > 0 ? Color.orange : Color.secondary)
                let servers = lab.servers(for: checkpoint)
                if !servers.isEmpty {
                    Text("Contacted " + servers.prefix(4).map(\.host).joined(separator: ", ") + (servers.count > 4 ? " and \(servers.count - 4) more" : ""))
                        .font(.caption).foregroundStyle(.secondary)
                }
            }
            Spacer()
            if checkpoint.reason != .start {
                Button("Changes") { Task { await lab.show(checkpoint.id) } }
            }
            Button("Compare with Now") { Task { await lab.compareWithNow(checkpoint.id) } }
            Button("Rewind to Here...") { rewindTarget = checkpoint }
                .disabled(lab.isBusy)
        }
        .padding(.vertical, 2)
        .listRowBackground(lab.selected == checkpoint.id ? Color.purple.opacity(0.08) : nil)
    }

    private func changesSection(_ comparison: LabComparison) -> some View {
        Section {
            if comparison.changes.isEmpty {
                Text("No file changes.").foregroundStyle(.secondary)
            }
            ForEach(comparison.changes) { change in
                Button {
                    Task { await lab.showDiff(change) }
                } label: {
                    HStack(spacing: 8) {
                        Image(systemName: Self.symbol(change.kind)).foregroundStyle(Self.tint(change.kind)).frame(width: 16)
                        Text(change.path.display).font(.system(.callout, design: .monospaced)).lineLimit(1).truncationMode(.middle)
                        if change.secret != nil {
                            Text("Secret").font(.caption2.weight(.semibold)).foregroundStyle(.red).padding(.horizontal, 6)
                                .background(Color.red.opacity(0.12), in: Capsule())
                        }
                        Spacer()
                        if let size = (change.new ?? change.old).map(\.size), size > 0 {
                            Text(Format.bytes(size)).font(.caption).foregroundStyle(.secondary)
                        }
                    }
                    .contentShape(Rectangle())
                }
                .buttonStyle(.plain)
                .disabled((change.new ?? change.old)?.kind != .file)
            }
        } header: {
            Text(comparisonTitle(comparison))
        } footer: {
            Text("\(comparison.created) new, \(comparison.changed) changed, \(comparison.deleted) deleted"
                + (comparison.truncated ? ". The list shows the first \(comparison.changes.count)." : ". Click a file to see what changed in it."))
        }
    }

    private func comparisonTitle(_ comparison: LabComparison) -> String {
        guard let session = lab.session else { return "Changes" }
        let from = session.checkpoint(comparison.from).map { LabModel.time($0.takenAt) } ?? "#\(comparison.from)"
        guard let to = comparison.to else { return "From \(from) to now" }
        if to == comparison.from { return "Checkpoint \(from)" }
        let end = session.checkpoint(to).map { "\(LabModel.time($0.takenAt)) · \($0.label)" } ?? "#\(to)"
        return "Changes in \(end), since \(from)"
    }

    @ViewBuilder
    private var busyIndicator: some View {
        if let activity = lab.activity {
            ProgressView().controlSize(.small)
            Text(activity).foregroundStyle(.secondary)
        }
    }

    // MARK: Symbols

    static func symbol(_ reason: LabCheckpoint.Reason) -> String {
        switch reason {
        case .start: "flag"
        case .interval: "clock"
        case .program: "play.circle"
        case .manual: "bookmark"
        case .beforeRewind: "arrow.uturn.backward.circle"
        }
    }

    static func symbol(_ kind: LabChange.Kind) -> String {
        switch kind {
        case .created: "plus.circle"
        case .changed: "pencil.circle"
        case .deleted: "minus.circle"
        }
    }

    static func tint(_ kind: LabChange.Kind) -> Color {
        switch kind {
        case .created: .green
        case .changed: .orange
        case .deleted: .red
        }
    }

    static func tint(_ kind: LabFinding.Kind) -> Color {
        switch kind {
        case .key, .credential, .keychain, .sshAccess: .red
        case .loginItem: .orange
        case .shellStartup: .secondary
        }
    }
}

/// A text file before and after, line by line.
struct LabDiffSheet: View {
    let diff: LabFileDiff
    let close: () -> Void

    var body: some View {
        VStack(alignment: .leading, spacing: 10) {
            HStack {
                Text(diff.change.path.display).font(.headline).textSelection(.enabled)
                Spacer()
                Button("Done", action: close).keyboardShortcut(.defaultAction)
            }
            if let secret = diff.change.secret {
                Label("This file \(secret).", systemImage: "key").foregroundStyle(.red).font(.callout)
            }
            if let lines = diff.lines {
                ScrollView([.vertical, .horizontal]) {
                    VStack(alignment: .leading, spacing: 0) {
                        ForEach(Array(lines.enumerated()), id: \.offset) { _, line in
                            Text(Self.prefix(line.kind) + line.text)
                                .font(.system(.caption, design: .monospaced))
                                .foregroundStyle(line.kind == .added ? Color.green : line.kind == .removed ? Color.red : Color.primary)
                                .frame(maxWidth: .infinity, alignment: .leading)
                                .background(line.kind == .context ? Color.clear : (line.kind == .added ? Color.green : Color.red).opacity(0.08))
                        }
                    }
                    .textSelection(.enabled)
                    .padding(8)
                }
                .background(Color.secondary.opacity(0.08))
            } else {
                Text(diff.note ?? "").foregroundStyle(.secondary)
            }
        }
        .padding(16)
        .frame(minWidth: 560, minHeight: 380)
    }

    static func prefix(_ kind: DiffLine.Kind) -> String {
        switch kind {
        case .context: "  "
        case .added: "+ "
        case .removed: "- "
        }
    }
}
