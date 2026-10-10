import AppKit
import SandvaultAppModel
import SandvaultCore
import SwiftUI

/// Activity > Files & programs (D44, D45): the recorder's state, five tiles, and per program either the summary
/// (Changes) or every event (Everything).
struct FileActivityView: View {
    @Bindable var files: FileActivityModel
    let installHelper: @MainActor () async -> Void

    var body: some View {
        VStack(spacing: 0) {
            MessageArea(message: files.message) { files.message = nil }
            ScrollView {
                LazyVStack(alignment: .leading, spacing: 14) {
                    RecorderBanner(files: files, installHelper: installHelper)
                    if files.events.isEmpty {
                        if files.isRecording {
                            ContentUnavailableView("Nothing recorded yet", systemImage: "doc.text.magnifyingglass",
                                                   description: Text("Files and programs the sandbox touches appear here."))
                        }
                    } else {
                        let report = files.report
                        TilesRow(tiles: report.tiles)
                        Picker("Show", selection: $files.mode) {
                            ForEach(FileActivityModel.Mode.allCases) { mode in
                                Text(mode.title).tag(mode)
                            }
                        }
                        .pickerStyle(.segmented)
                        .labelsHidden()
                        .frame(maxWidth: 260)
                        switch files.mode {
                        case .changes:
                            ForEach(report.groups) { group in
                                ChangesGroup(group: group)
                            }
                        case .everything:
                            ForEach(files.everything) { group in
                                EverythingGroup(group: group)
                            }
                        }
                    }
                }
                .padding(16)
                .frame(maxWidth: .infinity, alignment: .leading)
            }
        }
    }
}

/// Off, recording since, or what is missing, with the one button that helps.
private struct RecorderBanner: View {
    let files: FileActivityModel
    let installHelper: @MainActor () async -> Void

    private var tint: Color {
        switch files.state {
        case .off: .secondary
        case .recording: .red
        case .needsFullDiskAccess, .needsHelper, .failed: .orange
        }
    }

    private var symbol: String {
        switch files.state {
        case .off: "record.circle"
        case .recording: "record.circle.fill"
        case .needsFullDiskAccess: "lock.shield"
        case .needsHelper: "wrench.and.screwdriver"
        case .failed: "exclamationmark.triangle"
        }
    }

    var body: some View {
        HStack(alignment: .top, spacing: 12) {
            Image(systemName: symbol)
                .font(.title2)
                .foregroundStyle(tint)
                .frame(width: 30)
            VStack(alignment: .leading, spacing: 3) {
                Text(files.bannerTitle)
                    .fontWeight(.semibold)
                Text(files.bannerText)
                    .font(.callout)
                    .foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true)
            }
            Spacer(minLength: 8)
            buttons
        }
        .padding(12)
        .background(tint.opacity(0.08), in: RoundedRectangle(cornerRadius: 10))
    }

    @ViewBuilder private var buttons: some View {
        switch files.state {
        case .off:
            Button("Start Recording") { Task { await files.start() } }
                .buttonStyle(.borderedProminent)
        case .recording:
            Button("Stop") { Task { await files.stop() } }
        case .needsFullDiskAccess:
            VStack(alignment: .trailing) {
                Button("Open System Settings…") { Self.openFullDiskAccess() }
                    .buttonStyle(.borderedProminent)
                Button("Try Again") { Task { await files.start() } }
                Button("Turn Off") { Task { await files.stop() } }
                    .buttonStyle(.borderless)
            }
        case .needsHelper:
            VStack(alignment: .trailing) {
                Button("Install Helper…") { Task { await installHelper() } }
                    .buttonStyle(.borderedProminent)
                Button("Turn Off") { Task { await files.stop() } }
                    .buttonStyle(.borderless)
            }
        case .failed:
            VStack(alignment: .trailing) {
                Button("Try Again") { Task { await files.start() } }
                    .buttonStyle(.borderedProminent)
                Button("Turn Off") { Task { await files.stop() } }
                    .buttonStyle(.borderless)
            }
        }
    }

    /// System Settings > Privacy & Security > Full Disk Access.
    static func openFullDiskAccess() {
        if let url = URL(string: "x-apple.systempreferences:com.apple.preference.security?Privacy_AllFiles") {
            NSWorkspace.shared.open(url)
        }
    }
}

private struct TilesRow: View {
    let tiles: ActivityTiles

    var body: some View {
        HStack(spacing: 8) {
            Tile(value: tiles.read, label: "files read", symbol: ActivityAction.read.symbolName)
            Tile(value: tiles.changed, label: "changed", symbol: ActivityAction.change.symbolName)
            Tile(value: tiles.created, label: "created", symbol: ActivityAction.create.symbolName)
            Tile(value: tiles.deleted, label: "deleted", symbol: ActivityAction.delete.symbolName)
            Tile(value: tiles.programs, label: "programs", symbol: ActivityAction.run.symbolName)
        }
    }

    private struct Tile: View {
        let value: Int
        let label: String
        let symbol: String

        var body: some View {
            VStack(alignment: .leading, spacing: 2) {
                Text(verbatim: Format.grouped(value))
                    .font(.title2.weight(.semibold))
                    .monospacedDigit()
                Label(label, systemImage: symbol)
                    .font(.caption)
                    .foregroundStyle(.secondary)
            }
            .frame(maxWidth: .infinity, alignment: .leading)
            .padding(10)
            .background(Color.secondary.opacity(0.08), in: RoundedRectangle(cornerRadius: 8))
        }
    }
}

extension ActivityAction {
    var tint: Color {
        switch self {
        case .read: .blue
        case .change: .orange
        case .create: .green
        case .delete: .red
        case .move: .teal
        case .run: .purple
        }
    }
}

private struct ActionBadge: View {
    let action: ActivityAction?

    var body: some View {
        let tint = action?.tint ?? .secondary
        Image(systemName: action?.symbolName ?? "doc")
            .font(.system(size: 11, weight: .semibold))
            .foregroundStyle(tint)
            .frame(width: 24, height: 24)
            .background(tint.opacity(0.14), in: RoundedRectangle(cornerRadius: 6))
    }
}

private struct GroupHeader: View {
    let process: String
    let subtitle: String
    let folder: String?

    var body: some View {
        HStack(spacing: 10) {
            ProgramBadge(name: process)
            VStack(alignment: .leading, spacing: 1) {
                Text(process)
                    .fontWeight(.semibold)
                Text(subtitle)
                    .font(.caption)
                    .foregroundStyle(.secondary)
            }
            Spacer()
            if let folder {
                Button("Show in Finder") {
                    NSWorkspace.shared.activateFileViewerSelecting([URL(fileURLWithPath: folder)])
                }
                .buttonStyle(.borderless)
            }
        }
    }
}

/// One program in Changes: one sentence per kind and folder, sensitive places first.
private struct ChangesGroup: View {
    let group: ProcessActivity

    private var subtitle: String {
        let span = group.firstSeen == group.lastSeen ? Format.time(group.firstSeen) : "\(Format.time(group.firstSeen)) – \(Format.time(group.lastSeen))"
        return "\(span) · \(Format.count(group.eventCount, "event"))"
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 8) {
            GroupHeader(process: group.process, subtitle: subtitle, folder: group.folder)
            ForEach(group.lines) { line in
                ChangeLine(line: line)
            }
        }
        .padding(12)
        .background(Color.secondary.opacity(0.05), in: RoundedRectangle(cornerRadius: 10))
    }
}

private struct ChangeLine: View {
    let line: ActivityLine

    private var placeSuffix: String {
        line.place.map { " in " + $0 } ?? ""
    }

    var body: some View {
        HStack(alignment: .top, spacing: 10) {
            ActionBadge(action: line.action)
            VStack(alignment: .leading, spacing: 2) {
                HStack(spacing: 6) {
                    Text("\(line.verb) \(Text(line.object).fontWeight(.semibold))\(placeSuffix)")
                    if line.sensitive != nil {
                        Text("sensitive")
                            .font(.caption2.weight(.semibold))
                            .foregroundStyle(.red)
                            .padding(.horizontal, 5)
                            .padding(.vertical, 1)
                            .background(Color.red.opacity(0.12), in: Capsule())
                    }
                }
                if let sensitive = line.sensitive {
                    Text(sensitive.explanation)
                        .font(.caption)
                        .foregroundStyle(.red)
                }
                if line.folded {
                    DisclosureGroup {
                        VStack(alignment: .leading, spacing: 1) {
                            ForEach(line.fileNames, id: \.self) { name in
                                Text(name)
                            }
                            if line.count > line.files.count {
                                Text(verbatim: "and \(Format.grouped(line.count - line.files.count)) more")
                                    .foregroundStyle(.secondary)
                            }
                        }
                        .font(.system(.caption, design: .monospaced))
                        .textSelection(.enabled)
                    } label: {
                        PathText(text: line.detail)
                    }
                } else {
                    PathText(text: line.detail)
                }
            }
            Spacer(minLength: 8)
            Text(Format.time(line.lastSeen))
                .font(.caption)
                .foregroundStyle(.secondary)
                .monospacedDigit()
        }
    }
}

private struct PathText: View {
    let text: String

    var body: some View {
        Text(text)
            .font(.system(.caption, design: .monospaced))
            .foregroundStyle(.secondary)
            .lineLimit(2)
            .truncationMode(.middle)
            .textSelection(.enabled)
    }
}

/// One program in Everything: its raw events, newest first, in plain words.
private struct EverythingGroup: View {
    let group: ProcessEvents

    var body: some View {
        VStack(alignment: .leading, spacing: 6) {
            GroupHeader(process: group.process, subtitle: Format.count(group.lines.count + group.more, "event"), folder: nil)
            ForEach(group.lines) { line in
                HStack(alignment: .firstTextBaseline, spacing: 10) {
                    ActionBadge(action: line.action)
                    Text(line.text)
                        .foregroundStyle(line.sensitive ? Color.red : Color.primary)
                    PathText(text: line.path)
                    Spacer(minLength: 8)
                    Text(Format.time(line.time))
                        .font(.caption)
                        .foregroundStyle(.secondary)
                        .monospacedDigit()
                }
            }
            if group.more > 0 {
                Text(verbatim: "… \(Format.grouped(group.more)) more")
                    .font(.caption)
                    .foregroundStyle(.secondary)
            }
        }
        .padding(12)
        .background(Color.secondary.opacity(0.05), in: RoundedRectangle(cornerRadius: 10))
    }
}
