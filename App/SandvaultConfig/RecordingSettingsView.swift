import SandvaultAppModel
import SandvaultCore
import SwiftUI

/// Settings > Recording: web traffic, files and programs, storage.
struct RecordingSections: View {
    let recording: RecordingModel

    var body: some View {
        Section {
            Toggle(isOn: bind(recording.web.requests) { await recording.setRecordRequests($0) }) {
                DetailLabel("Record requests", note: "Address, status, size and headers of every request. Passwords and tokens in headers are hidden.",
                            symbol: "list.bullet.rectangle", color: .blue)
            }
            Toggle(isOn: bind(recording.web.contents) { await recording.setKeepContents($0) }) {
                DetailLabel("Keep contents", note: "Also store what was sent and received, up to \(Format.bytes(Int64(recording.web.maxContentBytes))) per request.",
                            symbol: "doc.text", color: .indigo)
            }
            .disabled(!recording.web.requests)
            Toggle(isOn: bind(recording.inspectionEnabled) { await recording.setInspection($0) }) {
                DetailLabel("Look inside HTTPS", note: "Needed for addresses and contents of encrypted sites. Programs that check their certificate refuse to connect.",
                            symbol: "lock.open", color: .orange)
            }
            .disabled(recording.isBusy)
        } header: {
            Text("Web traffic")
        } footer: {
            Text("Look inside HTTPS applies to hosts whose rule has Inspect; Web traffic offers it per host.")
        }

        Section("Files & programs") {
            Toggle(isOn: bind(recording.activity.enabled) { await recording.setRecordActivity($0) }) {
                DetailLabel("Record what the sandbox does",
                            note: "Files read, changed, created and deleted, and every program started. macOS asks once for Full Disk Access for Sandvault Config.",
                            symbol: "record.circle", color: .red)
            }
            if let problem = recording.recorderProblem {
                Label(problem, systemImage: "exclamationmark.triangle")
                    .font(.callout)
                    .foregroundStyle(.orange)
            }
            Toggle(isOn: bind(recording.activity.openAndClose) { await recording.setOpenAndClose($0) }) {
                DetailLabel("Include opening and closing", note: "Every single open and close, not just the result. Much longer lists.",
                            symbol: "arrow.left.arrow.right", color: .gray)
            }
            Toggle(isOn: bind(recording.activity.hideSystemFiles) { await recording.setHideSystemFiles($0) }) {
                DetailLabel("Hide system files", note: "Leaves out reads under /System, /usr and /Library that every program does.",
                            symbol: "eye.slash", color: .gray)
            }
        }

        Section("Storage") {
            Picker(selection: retention) {
                ForEach(retentionChoices, id: \.self) { days in
                    Text(RecordingModel.retentionTitle(days)).tag(days)
                }
            } label: {
                DetailLabel("Keep recordings for", note: "Older entries are removed. Everything stays on this Mac.", symbol: "calendar", color: .green)
            }
            LabeledContent {
                if recording.confirmingClear {
                    HStack {
                        Text("Delete all recordings?")
                            .foregroundStyle(.secondary)
                        Button("Cancel") { recording.confirmingClear = false }
                        Button("Delete", role: .destructive) { Task { await recording.clear() } }
                    }
                } else {
                    Button("Clear…") { recording.confirmingClear = true }
                        .disabled(recording.isClearing)
                }
            } label: {
                DetailLabel("Space used", note: recording.spaceText, symbol: "internaldrive", color: .gray)
            }
        }
        .task { await recording.refreshStorage() }
    }

    /// The fixed choices, plus a value set elsewhere (svctl, an edited file).
    private var retentionChoices: [Int] {
        let choices = RecordingModel.retentionChoices
        return choices.contains(recording.retentionDays) ? choices : (choices + [recording.retentionDays]).sorted()
    }

    private var retention: Binding<Int> {
        Binding<Int>(get: { recording.retentionDays }, set: { days in Task { await recording.setRetention(days) } })
    }

    private func bind(_ value: Bool, _ set: @escaping @MainActor @Sendable (Bool) async -> Void) -> Binding<Bool> {
        Binding<Bool>(get: { value }, set: { on in Task { await set(on) } })
    }
}
