import SandvaultAppModel
import SandvaultCore
import SwiftUI

struct ToolsView: View {
    @Bindable var tools: ToolsModel

    var body: some View {
        VStack(spacing: 0) {
            MessageArea(message: tools.message) { tools.message = nil }
            Form {
                if case .notAvailableYet(let note) = tools.availability {
                    Section {
                        NotAvailableView(title: "Tool checks are not available yet", note: note)
                    }
                }
                Section("Check a command") {
                    HStack {
                        TextField("Command name, e.g. jq", text: $tools.query)
                            .onSubmit { Task { await tools.check() } }
                        Button("Check") { Task { await tools.check() } }
                            .disabled(tools.query.isEmpty || tools.isBusy)
                    }
                    if let status = tools.status {
                        ToolStatusView(status: status) { method in
                            Task { await tools.grant(method) }
                        }
                    }
                }
                Section("Granted") {
                    if tools.grants.isEmpty {
                        Text("Nothing granted yet.")
                            .foregroundStyle(.secondary)
                    }
                    ForEach(tools.grants) { grant in
                        LabeledContent(grant.name, value: "\(grant.method.displayName) · \(grant.source)")
                    }
                }
            }
            .formStyle(.grouped)
        }
        .navigationTitle(Screen.tools.title)
    }
}

struct ToolStatusView: View {
    let status: ToolStatus
    let grant: (ToolGrantMethod) -> Void

    var body: some View {
        VStack(alignment: .leading, spacing: 6) {
            Label(status.name, systemImage: status.reachableInSandbox ? "checkmark.circle.fill" : "xmark.circle")
                .foregroundStyle(status.reachableInSandbox ? Color.green : Color.orange)
                .font(.headline)
            Text(status.summary)
                .font(.callout)
                .textSelection(.enabled)
            if let kind = status.kind {
                Text(kind)
                    .font(.callout)
                    .foregroundStyle(.secondary)
            }
            Text(status.reason)
                .font(.callout)
                .foregroundStyle(.secondary)
            if !status.reachableInSandbox {
                HStack {
                    ForEach(status.options.filter { $0 != .available }, id: \.self) { method in
                        Button(method.displayName) { grant(method) }
                    }
                }
            }
        }
    }
}
