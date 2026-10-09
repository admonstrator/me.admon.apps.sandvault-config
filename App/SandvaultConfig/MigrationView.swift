import SandvaultAppModel
import SandvaultCore
import SwiftUI

struct MigrationView: View {
    let migration: MigrationModel
    let keys: KeysModel

    var body: some View {
        VStack(spacing: 0) {
            MessageArea(message: migration.message) { migration.message = nil }
            MessageArea(message: keys.message) { keys.message = nil }
            Form {
                MigrationSection(migration: migration)
                if let plan = migration.plan {
                    MigrationPlanSection(plan: plan)
                }
                if let copied = migration.copied, !copied.isEmpty {
                    Section("Copied") {
                        ForEach(Array(copied.enumerated()), id: \.offset) { item in
                            Text(item.element.summary)
                                .font(.callout)
                        }
                    }
                }
                KeysSection(keys: keys)
            }
            .formStyle(.grouped)
        }
        .navigationTitle(Screen.migration.title)
    }
}

struct MigrationSection: View {
    let migration: MigrationModel

    var body: some View {
        Section("Copy host configuration into the sandbox") {
            if case .notAvailableYet(let note) = migration.availability {
                NotAvailableView(title: "Migration is not available yet", note: note)
            }
            Text("Files go to the shared workspace's user folder, which sv copies into the sandbox home on every session. Credentials, history and token-like content are never copied.")
                .font(.callout)
                .foregroundStyle(.secondary)
            ForEach(MigrationItem.allCases, id: \.self) { item in
                Toggle(item.displayName, isOn: selected(item))
            }
            HStack {
                Spacer()
                Button("Preview") { Task { await migration.preview() } }
                    .disabled(migration.selected.isEmpty || migration.isBusy)
                Button("Copy") { Task { await migration.apply() } }
                    .disabled(migration.copyable.isEmpty || migration.isBusy)
            }
        }
    }

    private func selected(_ item: MigrationItem) -> Binding<Bool> {
        Binding<Bool>(get: { migration.selected.contains(item) }, set: { _ in migration.toggle(item) })
    }
}

struct MigrationPlanSection: View {
    let plan: MigrationPlan

    var body: some View {
        Section("Plan") {
            if plan.entries.isEmpty {
                Text("Nothing to copy.")
                    .foregroundStyle(.secondary)
            }
            ForEach(Array(plan.entries.enumerated()), id: \.offset) { item in
                MigrationEntryRow(entry: item.element)
            }
        }
    }
}

struct MigrationEntryRow: View {
    let entry: MigrationEntry

    var body: some View {
        HStack(alignment: .top, spacing: 8) {
            Image(systemName: entry.blockedReason == nil ? "doc.on.doc" : "nosign")
                .foregroundStyle(entry.blockedReason == nil ? Color.secondary : Color.red)
            VStack(alignment: .leading, spacing: 2) {
                Text(entry.summary)
                    .font(.callout)
                    .textSelection(.enabled)
                if let reason = entry.blockedReason {
                    Text(verbatim: "Not copied: \(reason)")
                        .font(.caption)
                        .foregroundStyle(.red)
                }
            }
        }
    }
}

struct KeysSection: View {
    let keys: KeysModel
    @State private var name = ""
    @State private var publicKey = ""

    var body: some View {
        Section("SSH keys for sv (authorized_keys.d)") {
            if case .notAvailableYet(let note) = keys.availability {
                Text(note)
                    .foregroundStyle(.secondary)
            }
            ForEach(keys.keys) { key in
                HStack {
                    VStack(alignment: .leading, spacing: 2) {
                        Text(key.name)
                            .fontWeight(.medium)
                        Text(verbatim: "\(key.type) \(key.fingerprint)\(key.comment.map { " " + $0 } ?? "")")
                            .font(.system(.caption, design: .monospaced))
                            .foregroundStyle(.secondary)
                    }
                    Spacer()
                    Button {
                        Task { await keys.remove(key) }
                    } label: {
                        Image(systemName: "minus.circle")
                    }
                    .buttonStyle(.borderless)
                    .help("Remove")
                }
            }
            TextField("Name", text: $name)
            TextField("Public key (ssh-ed25519 AAAA...)", text: $publicKey, axis: .vertical)
                .lineLimit(2...4)
            HStack {
                Text("Private keys are refused.")
                    .font(.callout)
                    .foregroundStyle(.secondary)
                Spacer()
                Button("Add Key") { add() }
                    .disabled(name.isEmpty || publicKey.isEmpty)
            }
        }
    }

    private func add() {
        Task {
            if await keys.add(name: name, publicKey: publicKey) {
                name = ""
                publicKey = ""
            }
        }
    }
}
