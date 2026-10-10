import AppKit
import SandvaultAppModel
import SandvaultCore
import SwiftUI

/// Activity > Web traffic (D42): one row per request, the selected one opened on the right.
struct WebTrafficView: View {
    @Bindable var activity: ActivityModel
    let openRecordingSettings: () -> Void

    var body: some View {
        VStack(spacing: 0) {
            MessageArea(message: activity.message) { activity.message = nil }
            if !activity.inspectionEnabled {
                InspectionHint(openRecordingSettings: openRecordingSettings)
                    .padding(.horizontal, 16)
                    .padding(.top, 10)
            }
            VStack(alignment: .leading, spacing: 4) {
                Text(activity.webSummary)
                    .font(.headline)
                if let hint = activity.webHint {
                    Label(hint, systemImage: "info.circle")
                        .font(.callout)
                        .foregroundStyle(.secondary)
                }
            }
            .frame(maxWidth: .infinity, alignment: .leading)
            .padding(.horizontal, 16)
            .padding(.vertical, 8)
            HSplitView {
                list
                    .frame(minWidth: 360, idealWidth: 460)
                Group {
                    if let row = activity.selectedRequest {
                        WebRequestDetail(row: row, activity: activity)
                    } else {
                        ContentUnavailableView("No request selected", systemImage: "globe", description: Text("Choose a request to see its headers and contents."))
                    }
                }
                .frame(minWidth: 320, maxWidth: .infinity, maxHeight: .infinity)
            }
        }
        .searchable(text: $activity.webFilter, prompt: "Filter host or path")
    }

    @ViewBuilder private var list: some View {
        let rows = activity.webRows
        if rows.isEmpty {
            ContentUnavailableView("No web traffic", systemImage: "globe",
                                   description: Text(verbatim: activity.webFilter.isEmpty ? "Requests of the sandbox appear here." : "Nothing matches the filter."))
        } else {
            List(rows, selection: $activity.selectedRequestID) { row in
                WebRequestRowView(row: row)
                    .tag(row.id)
            }
        }
    }
}

/// For encrypted sites only the name and the size are visible; the button opens Settings > Recording.
private struct InspectionHint: View {
    let openRecordingSettings: () -> Void

    var body: some View {
        HStack(spacing: 10) {
            Image(systemName: "lock")
                .foregroundStyle(.secondary)
            Text("For encrypted sites only the name and the size are visible. To see addresses and contents, turn on **Look inside HTTPS**.")
                .font(.callout)
            Spacer(minLength: 8)
            Button("Turn On…", action: openRecordingSettings)
        }
        .padding(10)
        .background(Color.blue.opacity(0.08), in: RoundedRectangle(cornerRadius: 8))
    }
}

struct WebRequestRowView: View {
    let row: WebRequestRow

    var body: some View {
        HStack(spacing: 10) {
            ProgramBadge(name: row.process)
            VStack(alignment: .leading, spacing: 2) {
                HStack(spacing: 6) {
                    if let method = row.method {
                        Text(method)
                            .font(.system(.caption, design: .monospaced))
                            .fontWeight(.semibold)
                            .foregroundStyle(.secondary)
                    }
                    Text("\(Text(row.host).fontWeight(.semibold))\(row.path ?? "")")
                        .lineLimit(1)
                        .truncationMode(.middle)
                }
                HStack(spacing: 4) {
                    if row.isTLS {
                        Image(systemName: "lock.fill")
                            .imageScale(.small)
                    }
                    Text(row.subtitle)
                }
                .font(.caption)
                .foregroundStyle(.secondary)
            }
            Spacer(minLength: 8)
            VStack(alignment: .trailing, spacing: 2) {
                StatusPill(text: row.statusText, tint: row.statusTint, locked: row.visibility == .encrypted)
                Text(verbatim: "\(row.sizeText) · \(Format.time(row.time))")
                    .font(.caption)
                    .foregroundStyle(.secondary)
                    .monospacedDigit()
            }
        }
        .padding(.vertical, 2)
    }
}

struct StatusPill: View {
    let text: String
    let tint: Tint
    var locked = false

    var body: some View {
        HStack(spacing: 3) {
            if locked {
                Image(systemName: "lock.fill")
                    .imageScale(.small)
            }
            Text(text)
        }
        .font(.caption.weight(.semibold))
        .padding(.horizontal, 7)
        .padding(.vertical, 2)
        .foregroundStyle(tint.color)
        .background(tint.color.opacity(0.14), in: Capsule())
    }
}

/// The first letter of a program in a circle; the colour follows the name, so a program keeps it.
struct ProgramBadge: View {
    let name: String

    private static let palette: [Color] = [.orange, .green, .blue, .purple, .pink, .teal, .indigo, .brown]

    private var color: Color {
        let sum = name.unicodeScalars.reduce(0) { $0 + Int($1.value) }
        return Self.palette[sum % Self.palette.count]
    }

    var body: some View {
        Text(String(name.prefix(1)).uppercased())
            .font(.system(size: 12, weight: .bold))
            .foregroundStyle(.white)
            .frame(width: 26, height: 26)
            .background(color, in: Circle())
            .accessibilityLabel(name)
    }
}

/// The selected request: result, size, duration, program, headers, contents and the actions.
struct WebRequestDetail: View {
    let row: WebRequestRow
    let activity: ActivityModel

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 14) {
                VStack(alignment: .leading, spacing: 4) {
                    Text(verbatim: "\(Format.time(row.time)) · \(row.method ?? (row.isTLS ? "TLS" : "HTTP"))")
                        .font(.caption)
                        .foregroundStyle(.secondary)
                    Text("\(Text(row.host).fontWeight(.semibold))\(row.path ?? "")")
                        .font(.system(.body, design: .monospaced))
                        .textSelection(.enabled)
                }
                HStack(spacing: 8) {
                    FactTile(title: "Result", value: row.resultText)
                    FactTile(title: "Size", value: row.sizeDetail)
                    FactTile(title: "Took", value: row.durationText)
                    FactTile(title: "Program", value: row.process)
                }
                content
                actions
            }
            .padding(16)
            .frame(maxWidth: .infinity, alignment: .leading)
        }
    }

    @ViewBuilder private var content: some View {
        if row.visibility == .encrypted {
            NoteBox(symbol: "lock", text: activity.encryptedNote(row))
            if activity.canInspect(row.host) {
                Button("Look Inside \(row.host)") { Task { await activity.inspect(row.host) } }
            }
        } else if let summary = row.summary {
            HeaderTable(title: "Request", headers: summary.requestHeaders)
            if let meta = summary.requestContent {
                StoredContentView(meta: meta, activity: activity)
            }
            if let note = activity.blockedNote(row) {
                NoteBox(symbol: "shield", text: note)
            } else {
                HeaderTable(title: "Response", headers: summary.responseHeaders)
                if let meta = summary.responseContent {
                    StoredContentView(meta: meta, activity: activity)
                }
            }
        } else if let note = activity.blockedNote(row) {
            NoteBox(symbol: "shield", text: note)
        } else {
            NoteBox(symbol: "info.circle", text: "netd recorded the connection, not its requests.")
        }
    }

    private var actions: some View {
        HStack {
            if let curl = activity.curl(row) {
                Button("Copy as curl") {
                    NSPasteboard.general.clearContents()
                    NSPasteboard.general.setString(curl, forType: .string)
                }
            }
            if row.blocked {
                Button("Allow \(row.host)") { Task { await activity.allow(row.host) } }
                    .help("Allow this domain and its subdomains")
            } else {
                Button("Block \(row.host)") { Task { await activity.block(row.host) } }
                    .help("Refuse exactly this host name")
            }
            Button("Show All from \(row.host)") { activity.showAll(from: row.host) }
                .buttonStyle(.borderless)
        }
    }
}

private struct FactTile: View {
    let title: String
    let value: String

    var body: some View {
        VStack(alignment: .leading, spacing: 2) {
            Text(title)
                .font(.caption)
                .foregroundStyle(.secondary)
            Text(value)
                .fontWeight(.semibold)
                .lineLimit(2)
                .textSelection(.enabled)
        }
        .frame(maxWidth: .infinity, alignment: .leading)
        .padding(8)
        .background(Color.secondary.opacity(0.08), in: RoundedRectangle(cornerRadius: 8))
    }
}

/// Header names and values as recorded; redacted values stay as they came.
private struct HeaderTable: View {
    let title: String
    let headers: [[String]]

    var body: some View {
        VStack(alignment: .leading, spacing: 6) {
            Text(title)
                .font(.subheadline.weight(.semibold))
            if headers.isEmpty {
                Text("No headers recorded.")
                    .font(.caption)
                    .foregroundStyle(.secondary)
            } else {
                Grid(alignment: .leadingFirstTextBaseline, horizontalSpacing: 12, verticalSpacing: 3) {
                    ForEach(Array(headers.enumerated()), id: \.offset) { _, pair in
                        GridRow {
                            Text(pair.first ?? "")
                                .foregroundStyle(.secondary)
                            Text(pair.count > 1 ? pair[1] : "")
                                .foregroundStyle(pair.count > 1 && pair[1] == "<redacted>" ? Color.orange : Color.primary)
                                .textSelection(.enabled)
                        }
                    }
                }
                .font(.system(.caption, design: .monospaced))
            }
        }
    }
}

/// A kept body, fetched from netd when it is first shown (D43).
private struct StoredContentView: View {
    let meta: StoredContent
    let activity: ActivityModel

    private static let shownCharacters = 100_000

    var body: some View {
        VStack(alignment: .leading, spacing: 4) {
            switch activity.content(meta) {
            case nil, .loading?:
                ProgressView()
                    .controlSize(.small)
            case .text(let stored, let text)?:
                ScrollView {
                    Text(verbatim: String(text.prefix(Self.shownCharacters)))
                        .font(.system(.caption, design: .monospaced))
                        .textSelection(.enabled)
                        .frame(maxWidth: .infinity, alignment: .leading)
                        .padding(8)
                }
                .frame(maxHeight: 260)
                .background(Color.secondary.opacity(0.08), in: RoundedRectangle(cornerRadius: 6))
                if let note = ContentLoad.truncationNote(stored) {
                    Text(note)
                        .font(.caption)
                        .foregroundStyle(.secondary)
                }
            case .binary(let stored)?:
                NoteBox(symbol: "doc", text: ContentLoad.binaryNote(stored))
            case .failed(let reason)?:
                NoteBox(symbol: "exclamationmark.triangle", text: "Contents not available: \(reason)")
            }
        }
        .task(id: meta.id) { await activity.loadContent(meta) }
    }
}

struct NoteBox: View {
    let symbol: String
    let text: String

    var body: some View {
        HStack(alignment: .top, spacing: 8) {
            Image(systemName: symbol)
                .foregroundStyle(.secondary)
            Text(text)
                .font(.callout)
                .foregroundStyle(.secondary)
                .fixedSize(horizontal: false, vertical: true)
            Spacer(minLength: 0)
        }
        .padding(10)
        .background(Color.secondary.opacity(0.08), in: RoundedRectangle(cornerRadius: 8))
    }
}
