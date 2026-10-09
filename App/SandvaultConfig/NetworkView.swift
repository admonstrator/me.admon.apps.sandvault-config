import SandvaultAppModel
import SandvaultCore
import SwiftUI

struct NetworkView: View {
    enum Tab: String, CaseIterable {
        case hosts = "Hosts (netd)"
        case sockets = "Sockets"
    }

    @Bindable var network: NetworkModel
    let netd: NetdLink
    @State private var tab = Tab.hosts
    @State private var selection: String?

    var body: some View {
        VStack(spacing: 0) {
            MessageArea(message: network.message) { network.message = nil }
            Text(netd.summary)
                .font(.caption)
                .foregroundStyle(.secondary)
                .frame(maxWidth: .infinity, alignment: .leading)
                .padding(.horizontal, 16)
                .padding(.vertical, 6)
            switch tab {
            case .hosts:
                HostTable(network: network, selection: $selection)
            case .sockets:
                SocketsPane(network: network)
            }
        }
        .navigationTitle(Screen.network.title)
        .searchable(text: $network.hostFilter, prompt: "Filter hosts")
        .toolbar {
            Picker("Show", selection: $tab) {
                ForEach(Tab.allCases, id: \.self) { tab in
                    Text(tab.rawValue).tag(tab)
                }
            }
            .pickerStyle(.segmented)
            Toggle("Denied only", isOn: $network.deniedOnly)
            Button("Allow Host") {
                if let host = selection { Task { await network.allowHost(host) } }
            }
            .disabled(selection == nil || tab != .hosts)
            .help("Allow rule for exactly this host name")
            Button("Allow Domain") {
                if let host = selection { Task { await network.allowDomain(host) } }
            }
            .disabled(selection == nil || tab != .hosts)
            .help("Allow rule for *.<registrable domain>")
            Button("Deny") {
                if let host = selection { Task { await network.deny(host) } }
            }
            .disabled(selection == nil || tab != .hosts)
        }
    }
}

struct HostTable: View {
    let network: NetworkModel
    @Binding var selection: String?

    var body: some View {
        Table(network.hostGroups, selection: $selection) {
            TableColumn("Host") { group in
                Text(group.host)
            }
            TableColumn("Last decision") { group in
                Text(group.lastDecision.displayName)
                    .foregroundStyle(group.lastDecision.tint.color)
            }
            .width(140)
            TableColumn("Allowed") { group in
                Text(String(group.allowed)).monospacedDigit()
            }
            .width(60)
            TableColumn("Denied") { group in
                Text(String(group.denied)).monospacedDigit()
            }
            .width(60)
            TableColumn("Ports") { group in
                Text(group.ports.map(String.init).joined(separator: ", "))
            }
            .width(80)
            TableColumn("Processes") { group in
                Text(group.processes.joined(separator: ", "))
            }
            TableColumn("Traffic") { group in
                Text(verbatim: "\(Format.bytes(group.bytesIn)) in · \(Format.bytes(group.bytesOut)) out")
                    .monospacedDigit()
            }
            .width(150)
            TableColumn("Seen") { group in
                Text(Format.time(group.lastSeen)).monospacedDigit()
            }
            .width(70)
            TableColumn("Rule") { group in
                Text(ruleText(group.host))
                    .foregroundStyle(.secondary)
            }
        }
    }

    private func ruleText(_ host: String) -> String {
        guard let rule = network.rule(for: host) else { return "default" }
        return "\(rule.action.displayName) \(rule.pattern)"
    }
}

struct SocketsPane: View {
    let network: NetworkModel

    var body: some View {
        VStack(spacing: 0) {
            if let error = network.socketsError {
                MessageBanner(message: error) {}
                    .padding(.horizontal, 16)
                    .padding(.vertical, 6)
            }
            Table(network.socketRows) {
                TableColumn("Process") { row in
                    Text(row.process)
                }
                TableColumn("PID") { row in
                    Text(String(row.pid)).monospacedDigit()
                }
                .width(64)
                TableColumn("Proto") { row in
                    Text(row.proto.displayName)
                }
                .width(50)
                TableColumn("Local") { row in
                    Text(row.local).font(.system(.body, design: .monospaced))
                }
                TableColumn("Remote") { row in
                    Text(row.remote).font(.system(.body, design: .monospaced))
                }
                TableColumn("State") { row in
                    Text(row.state)
                }
                .width(110)
            }
            if !network.traffic.isEmpty {
                Divider()
                TrafficList(traffic: network.traffic)
                    .frame(height: 150)
            }
        }
    }
}

struct TrafficList: View {
    let traffic: [ProcessTraffic]

    var body: some View {
        List {
            Section("Traffic since the process started (nettop)") {
                ForEach(traffic, id: \.pid) { item in
                    HStack {
                        Text(verbatim: "\(item.process) (\(item.pid))")
                        Spacer()
                        Text(verbatim: "\(Format.bytes(item.bytesIn)) in · \(Format.bytes(item.bytesOut)) out")
                            .foregroundStyle(.secondary)
                            .monospacedDigit()
                    }
                }
            }
        }
    }
}
