import SandvaultAppModel
import SandvaultObserve
import SwiftUI

struct ProcessesView: View {
    @Bindable var processes: ProcessesModel
    @State private var selection: Int32?
    @State private var confirmEndAll = false
    @Environment(\.openWindow) private var openWindow

    var body: some View {
        VStack(spacing: 0) {
            MessageArea(message: processes.message) { processes.message = nil }
            if let error = processes.refreshError {
                MessageBanner(message: error) {}
                    .padding(.horizontal, 16)
                    .padding(.top, 10)
            }
            switch processes.grouping {
            case .tree:
                ProcessTable(rows: processes.rows, selection: $selection, showDetails: showDetails)
            case .sessions:
                SessionList(groups: processes.sessionGroups, selection: $selection) { id in
                    Task { await processes.terminateSession(id) }
                }
            }
        }
        .navigationTitle(Screen.processes.title)
        .toolbar {
            Picker("View", selection: $processes.grouping) {
                ForEach(ProcessesModel.Grouping.allCases, id: \.self) { grouping in
                    Text(grouping.displayName).tag(grouping)
                }
            }
            .pickerStyle(.segmented)
            Button("Details") {
                if let pid = selection { showDetails(pid) }
            }
            .disabled(selection == nil)
            .help("Web, connections, files and programs of this process (double-click a row)")
            Button("Terminate") {
                if let pid = selection { Task { await processes.terminate(pid) } }
            }
            .disabled(selection == nil || processes.isBusy)
            .help("SIGTERM, sent as the sandbox user")
            Button("Kill") {
                if let pid = selection { Task { await processes.terminate(pid, force: true) } }
            }
            .disabled(selection == nil || processes.isBusy)
            .help("SIGKILL, sent as the sandbox user")
            Button("Throttle") {
                if let pid = selection { Task { await processes.throttle(pid, nice: 10, background: true) } }
            }
            .disabled(selection == nil || processes.isBusy)
            .help("renice +10 and the background QoS band")
            Button("End All", role: .destructive) { confirmEndAll = true }
                .disabled(processes.isBusy || processes.processCount == 0)
        }
        .confirmationDialog("End every process of the sandbox user?", isPresented: $confirmEndAll) {
            Button("End All", role: .destructive) {
                Task { await processes.terminateAll() }
            }
        } message: {
            Text("Uses sv's own rules: launchctl bootout, then pkill -9 for survivors.")
        }
    }

    /// Process details (D51) in their own window.
    private func showDetails(_ pid: Int32) {
        openWindow(id: ProcessDetailView.windowID, value: ProcessReference(pid: pid))
    }
}

struct ProcessTable: View {
    let rows: [ProcessRow]
    @Binding var selection: Int32?
    var showDetails: @MainActor (Int32) -> Void = { _ in }

    var body: some View {
        Table(rows, selection: $selection) {
            TableColumn("Process") { row in
                Text(row.label)
                    .help(row.command)
            }
            TableColumn("PID") { row in
                Text(String(row.pid)).monospacedDigit()
            }
            .width(64)
            TableColumn("CPU %") { row in
                Text(Format.percent(row.cpuPercent)).monospacedDigit()
            }
            .width(56)
            TableColumn("Memory") { row in
                Text(Format.kibibytes(row.rssKiB)).monospacedDigit()
            }
            .width(80)
            TableColumn("Time") { row in
                Text(Format.duration(row.elapsedSeconds)).monospacedDigit()
            }
            .width(72)
            TableColumn("Session") { row in
                Text(Format.shortSession(row.sessionID))
                    .font(.system(.body, design: .monospaced))
            }
            .width(84)
            TableColumn("Command") { row in
                Text(row.command)
                    .foregroundStyle(.secondary)
                    .help(row.command)
            }
        }
        .contextMenu(forSelectionType: Int32.self) { pids in
            if let pid = pids.first { Button("Show What It Did") { showDetails(pid) } }
        } primaryAction: { pids in
            if let pid = pids.first { showDetails(pid) }
        }
    }
}

struct SessionList: View {
    let groups: [SessionGroup]
    @Binding var selection: Int32?
    let endSession: (String) -> Void

    var body: some View {
        List(selection: $selection) {
            ForEach(groups) { group in
                Section {
                    ForEach(group.rows) { row in
                        HStack {
                            Text(row.label)
                            Spacer()
                            Text(verbatim: "pid \(row.pid) · \(Format.percent(row.cpuPercent)) % · \(Format.kibibytes(row.rssKiB))")
                                .foregroundStyle(.secondary)
                                .monospacedDigit()
                        }
                        .help(row.command)
                    }
                } header: {
                    HStack {
                        Text(group.title)
                        Spacer()
                        if let session = group.session {
                            Button("End Session") { endSession(session.id) }
                                .buttonStyle(.borderless)
                        }
                    }
                }
            }
        }
    }
}
