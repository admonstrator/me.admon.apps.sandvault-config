import AppKit
import SandvaultAppModel
import SandvaultCore
import SandvaultObserve
import SwiftUI

/// What one sandbox process and the programs it started did (D51): call chain, signature, warnings, five tiles that
/// filter one timeline of web requests, connections and DNS, files and started programs. Opens in its own window
/// (`ShowProcessButton`); the view keeps its own history, so Open on a started program and Back stay in the window.
struct ProcessDetailView: View {
    static let windowID = "process-detail"

    let model: AppModel
    @State private var history: [ProcessReference]
    @State private var filter: ProcessDetailFilter = .all
    @State private var includeChildren = true
    @State private var grouped = true
    @State private var search = ""

    init(model: AppModel, pid: Int32, at: Date? = nil) {
        self.init(model: model, reference: ProcessReference(pid: pid, at: at))
    }

    init(model: AppModel, reference: ProcessReference) {
        self.model = model
        _history = State(initialValue: [reference])
    }

    private var current: ProcessReference { history.last ?? ProcessReference(pid: 0) }
    private var expert: Bool { model.mode == .expert }

    var body: some View {
        let detail = model.processDetail.detail(for: current, includeChildren: includeChildren, grouped: grouped)
        Group {
            if let detail {
                content(detail)
            } else {
                ContentUnavailableView(
                    "Nothing known about pid \(String(current.pid))", systemImage: "questionmark.app",
                    description: Text("The process is not running and nothing it did was recorded.")
                )
            }
        }
        .frame(minWidth: 560, minHeight: 420)
        .navigationTitle(detail.map { "\($0.title) · pid \(String($0.process.pid))" } ?? "Process")
        .toolbar {
            if history.count > 1 {
                ToolbarItem(placement: .navigation) {
                    Button {
                        history.removeLast()
                        filter = .all
                    } label: {
                        Label("Back", systemImage: "chevron.left")
                    }
                    .help("Back to the process shown before")
                }
            }
        }
        .searchable(text: $search, prompt: "Filter")
        .task(id: current) {
            while !Task.isCancelled {
                await model.processDetail.refresh()
                try? await Task.sleep(for: .seconds(3))
            }
        }
    }

    private func open(_ reference: ProcessReference) {
        guard reference != current else { return }
        history.append(reference)
        filter = .all
    }

    private func content(_ detail: ProcessDetail) -> some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 16) {
                ProcessHeader(detail: detail, now: model.processDetail.now)
                ProcessChain(detail: detail, expert: expert, open: open)
                if let title = detail.warningTitle {
                    WarningStrip(title: title, warnings: detail.warnings)
                }
                TileRow(tiles: detail.tiles, selection: $filter)
                HStack {
                    Text(filter.heading)
                        .font(.headline)
                    Spacer()
                    if detail.descendantCount > 0 {
                        Toggle("Include programs it started", isOn: $includeChildren)
                            .toggleStyle(.switch)
                            .controlSize(.small)
                    }
                    Toggle("Group alike", isOn: $grouped)
                        .toggleStyle(.switch)
                        .controlSize(.small)
                        .help("One row for requests to one address, files in one folder, starts of one program")
                }
                timeline(detail)
                ForEach(model.processDetail.hints(for: detail), id: \.self) { hint in
                    NoteBox(symbol: "info.circle", text: hint)
                }
            }
            .padding(20)
            .frame(maxWidth: 980, alignment: .leading)
            .frame(maxWidth: .infinity)
        }
    }

    @ViewBuilder private func timeline(_ detail: ProcessDetail) -> some View {
        let rows = detail.rows(filter, matching: search)
        if rows.isEmpty {
            Text(search.isEmpty ? "Nothing of this kind." : "Nothing matches the filter.")
                .foregroundStyle(.secondary)
                .padding(.vertical, 8)
        } else {
            LazyVStack(alignment: .leading, spacing: 0) {
                ForEach(rows) { row in
                    TimelineRow(row: row, own: row.processID == detail.process.id, expert: expert, open: open)
                    Divider()
                }
            }
            .padding(.horizontal, 12)
            .background(Color.secondary.opacity(0.05), in: RoundedRectangle(cornerRadius: 10))
        }
    }
}

/// Opens a process's details in their own window; disabled without a process.
struct ShowProcessButton: View {
    let title: String
    let reference: ProcessReference?
    @Environment(\.openWindow) private var openWindow

    var body: some View {
        Button(title) {
            if let reference { openWindow(id: ProcessDetailView.windowID, value: reference) }
        }
        .disabled(reference == nil)
        .help(reference == nil ? "netd did not find the program of this request" : "Web, connections, files and programs of this process")
    }
}

/// The detail windows: one per process the user opens.
struct ProcessDetailScene: Scene {
    let model: AppModel

    var body: some Scene {
        WindowGroup("Process", id: ProcessDetailView.windowID, for: ProcessReference.self) { $reference in
            if let reference {
                ProcessDetailView(model: model, reference: reference)
            }
        }
        .defaultSize(width: 820, height: 680)
    }
}

private struct ProcessHeader: View {
    let detail: ProcessDetail
    let now: Date

    var body: some View {
        HStack(alignment: .top, spacing: 14) {
            ProgramBadge(name: detail.process.name)
                .scaleEffect(1.5)
                .frame(width: 40, height: 40)
            VStack(alignment: .leading, spacing: 4) {
                Text(detail.title)
                    .font(.title2.weight(.semibold))
                if let command = detail.process.command {
                    Text(command)
                        .font(.system(.callout, design: .monospaced))
                        .foregroundStyle(.secondary)
                        .lineLimit(3)
                        .textSelection(.enabled)
                }
                HStack(spacing: 14) {
                    if let startedBy = detail.startedBy {
                        Text(startedBy)
                    }
                    Label(detail.signatureText, systemImage: "checkmark.seal")
                        .foregroundStyle(detail.signatureTint.color)
                        .help(detail.process.signingID.map { "Signing identifier \($0)" } ?? "Recorded with Files & programs")
                    Text(detail.state(now: now))
                    if let session = detail.process.sessionID {
                        Text(verbatim: "Session \(Format.shortSession(session))")
                    }
                }
                .font(.callout)
                .foregroundStyle(.secondary)
            }
            Spacer(minLength: 0)
            if let cwd = detail.process.cwd {
                Button("Show Folder") {
                    NSWorkspace.shared.activateFileViewerSelecting([URL(fileURLWithPath: cwd)])
                }
                .help(cwd)
            }
        }
        .padding(14)
        .background(Color.secondary.opacity(0.06), in: RoundedRectangle(cornerRadius: 12))
    }
}

/// `claude > node > sh`, then the programs it started; each opens its own details.
private struct ProcessChain: View {
    let detail: ProcessDetail
    let expert: Bool
    let open: @MainActor (ProcessReference) -> Void

    var body: some View {
        ScrollView(.horizontal, showsIndicators: false) {
            HStack(spacing: 4) {
                ForEach(Array(detail.chain.enumerated()), id: \.element.id) { index, process in
                    if index > 0 {
                        Image(systemName: "chevron.right")
                            .imageScale(.small)
                            .foregroundStyle(.secondary)
                    }
                    chip(process, current: process.id == detail.process.id)
                }
                if !detail.children.isEmpty {
                    Text(verbatim: "started \(detail.children.count == 1 ? "1 program" : "\(detail.children.count) programs"):")
                        .foregroundStyle(.secondary)
                        .padding(.leading, 8)
                    ForEach(detail.children.suffix(12)) { child in
                        chip(child, current: false)
                    }
                    if detail.children.count > 12 {
                        Text(verbatim: "and \(detail.children.count - 12) more")
                            .foregroundStyle(.secondary)
                    }
                }
            }
            .font(.callout)
        }
    }

    private func chip(_ process: TracedProcess, current: Bool) -> some View {
        Button {
            open(process.reference)
        } label: {
            Text(verbatim: expert ? "\(process.name) \(process.pid)" : process.name)
                .fontWeight(current ? .semibold : .regular)
                .padding(.horizontal, 8)
                .padding(.vertical, 2)
                .background((current ? Color.accentColor : Color.secondary).opacity(current ? 0.18 : 0.1), in: RoundedRectangle(cornerRadius: 5))
        }
        .buttonStyle(.plain)
        .disabled(current)
        .help(process.command ?? process.name)
    }
}

private struct WarningStrip: View {
    let title: String
    let warnings: [ProcessDetailRow]

    var body: some View {
        HStack(alignment: .top, spacing: 12) {
            Image(systemName: "key.fill")
                .foregroundStyle(.white)
                .frame(width: 30, height: 30)
                .background(Color.red, in: RoundedRectangle(cornerRadius: 8))
            VStack(alignment: .leading, spacing: 2) {
                Text(title)
                    .fontWeight(.semibold)
                ForEach(warnings.prefix(5)) { row in
                    Text(verbatim: "\(row.title) · \(row.detail)")
                        .font(.caption)
                        .foregroundStyle(.secondary)
                        .lineLimit(1)
                        .truncationMode(.middle)
                }
                if warnings.count > 5 {
                    Text(verbatim: "and \(warnings.count - 5) more")
                        .font(.caption)
                        .foregroundStyle(.secondary)
                }
            }
            Spacer(minLength: 0)
        }
        .padding(12)
        .background(Color.red.opacity(0.1), in: RoundedRectangle(cornerRadius: 12))
    }
}

private struct TileRow: View {
    let tiles: [ProcessDetailTile]
    @Binding var selection: ProcessDetailFilter

    var body: some View {
        HStack(spacing: 8) {
            ForEach(tiles) { tile in
                Button {
                    selection = tile.filter
                } label: {
                    VStack(alignment: .leading, spacing: 2) {
                        Text(Format.grouped(tile.count))
                            .font(.title3.weight(.semibold))
                            .monospacedDigit()
                        Label(tile.filter.title, systemImage: tile.filter.symbolName)
                            .font(.caption)
                            .foregroundStyle(.secondary)
                            .lineLimit(1)
                    }
                    .frame(maxWidth: .infinity, alignment: .leading)
                    .padding(10)
                    .background(Color.secondary.opacity(0.06), in: RoundedRectangle(cornerRadius: 10))
                    .overlay {
                        RoundedRectangle(cornerRadius: 10)
                            .strokeBorder(selection == tile.filter ? Color.accentColor : Color.clear, lineWidth: 1.5)
                    }
                    .contentShape(RoundedRectangle(cornerRadius: 10))
                }
                .buttonStyle(.plain)
            }
        }
    }
}

private struct TimelineRow: View {
    let row: ProcessDetailRow
    /// Done by the shown process itself, not by a program it started.
    let own: Bool
    let expert: Bool
    let open: @MainActor (ProcessReference) -> Void

    var body: some View {
        HStack(alignment: .top, spacing: 10) {
            Text(Format.time(row.time))
                .font(.caption)
                .foregroundStyle(.secondary)
                .monospacedDigit()
                .frame(width: 58, alignment: .leading)
                .padding(.top, 4)
            Image(systemName: row.symbolName)
                .font(.system(size: 11, weight: .semibold))
                .foregroundStyle(row.tint.color)
                .frame(width: 24, height: 24)
                .background(row.tint.color.opacity(0.14), in: RoundedRectangle(cornerRadius: 6))
            VStack(alignment: .leading, spacing: 2) {
                Text(row.title)
                    .fontWeight(.medium)
                    .lineLimit(2)
                    .truncationMode(.middle)
                if !row.detail.isEmpty {
                    Text(row.detail)
                        .font(.system(.caption, design: .monospaced))
                        .foregroundStyle(.secondary)
                        .lineLimit(2)
                        .truncationMode(.middle)
                        .textSelection(.enabled)
                }
                if let sensitive = row.sensitive {
                    Text(sensitive.explanation)
                        .font(.caption)
                        .foregroundStyle(.red)
                }
            }
            Spacer(minLength: 8)
            HStack(spacing: 6) {
                if let status = row.status {
                    StatusPill(text: status, tint: row.sensitive == nil ? row.statusTint : .red)
                }
                if let child = row.opens {
                    Button("Open") { open(child) }
                        .buttonStyle(.link)
                }
                if !own {
                    Button {
                        open(ProcessReference(pid: row.pid, at: row.time))
                    } label: {
                        Text(verbatim: expert ? "\(row.processName) \(row.pid)" : row.processName)
                            .font(.caption.monospaced())
                            .padding(.horizontal, 6)
                            .padding(.vertical, 1)
                            .foregroundStyle(.purple)
                            .background(Color.purple.opacity(0.12), in: RoundedRectangle(cornerRadius: 5))
                    }
                    .buttonStyle(.plain)
                    .help("Open this process")
                }
            }
        }
        .padding(.vertical, 7)
    }
}
