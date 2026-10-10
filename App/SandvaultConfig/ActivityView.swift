import SandvaultAppModel
import SwiftUI

/// Activity: Hosts, Web traffic and Files & programs, switched in the toolbar.
struct ActivityView: View {
    let model: AppModel
    @Bindable var activity: ActivityModel

    init(model: AppModel) {
        self.model = model
        _activity = Bindable(model.activity)
    }

    var body: some View {
        Group {
            switch activity.page {
            case .hosts: HostsView(activity: activity)
            case .web: WebTrafficView(activity: activity) { model.showRecordingSettings() }
            case .files: FileActivityView(files: model.files) { await model.installHelperForRecording() }
            }
        }
        .navigationTitle(Screen.activity.title)
        .toolbar {
            ToolbarItem(placement: .principal) {
                Picker("View", selection: $activity.page) {
                    ForEach(ActivityPage.allCases) { page in
                        Text(page.title).tag(page)
                    }
                }
                .pickerStyle(.segmented)
                .labelsHidden()
            }
        }
    }
}

/// What the sandbox talks to: host names from netd, direct connections, pings.
struct HostsView: View {
    @Bindable var activity: ActivityModel

    var body: some View {
        VStack(spacing: 0) {
            MessageArea(message: activity.message) { activity.message = nil }
            VStack(alignment: .leading, spacing: 4) {
                Text(activity.summary)
                    .font(.headline)
                if let hint = activity.hint {
                    Label(hint, systemImage: "info.circle")
                        .font(.callout)
                        .foregroundStyle(.secondary)
                }
            }
            .frame(maxWidth: .infinity, alignment: .leading)
            .padding(.horizontal, 16)
            .padding(.vertical, 8)
            let items = activity.items
            if items.isEmpty {
                ContentUnavailableView("No activity", systemImage: "dot.radiowaves.left.and.right",
                                       description: Text("Hosts, connections and pings of the sandbox appear here."))
            } else {
                List(items) { item in
                    ActivityRow(item: item, activity: activity)
                }
            }
        }
        .searchable(text: $activity.filter, prompt: "Filter")
    }
}

struct ActivityRow: View {
    let item: ActivityItem
    let activity: ActivityModel

    var body: some View {
        HStack(spacing: 10) {
            Image(systemName: symbolName)
                .foregroundStyle(item.tint.color)
                .frame(width: 18)
            VStack(alignment: .leading, spacing: 2) {
                Text(item.title)
                    .fontWeight(.medium)
                    .lineLimit(1)
                    .truncationMode(.middle)
                Text(item.detail)
                    .font(.caption)
                    .foregroundStyle(.secondary)
                    .lineLimit(3)
            }
            Spacer()
            Text(item.status)
                .foregroundStyle(item.tint.color)
            if let host = item.host {
                if item.blocked {
                    Button("Allow") { Task { await activity.allow(host) } }
                        .help("Allow this domain and its subdomains")
                } else {
                    Button("Block") { Task { await activity.block(host) } }
                        .help("Refuse exactly this host name")
                }
            }
        }
        .padding(.vertical, 2)
    }

    private var symbolName: String {
        switch item.kind {
        case .host: "globe"
        case .direct: "arrow.up.right.circle"
        case .icmp: "dot.radiowaves.right"
        }
    }
}
