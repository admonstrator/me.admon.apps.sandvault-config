import SandvaultAppModel
import SandvaultCore
import SwiftUI

struct FirewallView: View {
    let firewall: FirewallModel

    var body: some View {
        VStack(spacing: 0) {
            MessageArea(message: firewall.message) { firewall.message = nil }
            Form {
                FirewallModeSection(firewall: firewall)
                FirewallGuardsSection(firewall: firewall)
                PortExceptionsSection(firewall: firewall)
                DomainRulesSection(firewall: firewall)
                DnsOverridesSection(firewall: firewall)
                InspectionSection(firewall: firewall)
            }
            .formStyle(.grouped)
        }
        .navigationTitle(Screen.firewall.title)
        .sheet(item: pendingApply) { plan in
            ApplySheet(firewall: firewall, plan: plan)
        }
    }

    private var pendingApply: Binding<FirewallApplyPlan?> {
        Binding<FirewallApplyPlan?>(
            get: { firewall.pendingApply },
            set: { plan in
                if plan == nil { firewall.cancelApply() }
            }
        )
    }
}

struct FirewallModeSection: View {
    let firewall: FirewallModel
    @State private var confirmPanic = false

    var body: some View {
        Section("Mode") {
            Picker("Mode", selection: mode) {
                ForEach(FirewallMode.allCases, id: \.self) { mode in
                    Text(mode.displayName).tag(mode)
                }
            }
            Text(firewall.network.mode.explanation)
                .font(.callout)
                .foregroundStyle(.secondary)
            LabeledContent("Loaded", value: firewall.loadedSummary)
            if firewall.needsApply {
                Label("The configuration differs from what pf has loaded.", systemImage: "exclamationmark.triangle")
                    .foregroundStyle(.orange)
            }
            HStack {
                Button("Apply…") { Task { await firewall.prepareApply() } }
                    .disabled(firewall.isBusy)
                Button("Turn Off") { Task { await firewall.turnOff() } }
                    .disabled(firewall.isBusy)
                Spacer()
                Button("Panic…", role: .destructive) { confirmPanic = true }
                    .disabled(firewall.isBusy)
            }
            .confirmationDialog("Block the sandbox's network and end all its processes?", isPresented: $confirmPanic) {
                Button("Panic", role: .destructive) {
                    Task { await firewall.panic() }
                }
            } message: {
                Text("To end it later, choose a mode and apply, or turn the firewall off.")
            }
        }
    }

    private var mode: Binding<FirewallMode> {
        Binding<FirewallMode>(
            get: { firewall.network.mode },
            set: { mode in Task { await firewall.setMode(mode) } }
        )
    }
}

struct FirewallGuardsSection: View {
    let firewall: FirewallModel

    var body: some View {
        Section("Guards") {
            Toggle("Block LAN destinations (RFC 1918, link-local, CGNAT)", isOn: blockLAN)
            Picker("Localhost", selection: localhost) {
                ForEach(LocalhostPolicy.allCases, id: \.self) { policy in
                    Text(policy.displayName).tag(policy)
                }
            }
            Toggle("Refuse proxy targets that resolve to private addresses", isOn: blockPrivate)
        }
    }

    private var blockLAN: Binding<Bool> {
        Binding<Bool>(get: { firewall.network.blockLAN }, set: { on in Task { await firewall.setBlockLAN(on) } })
    }

    private var localhost: Binding<LocalhostPolicy> {
        Binding<LocalhostPolicy>(get: { firewall.network.localhost }, set: { policy in Task { await firewall.setLocalhost(policy) } })
    }

    private var blockPrivate: Binding<Bool> {
        Binding<Bool>(
            get: { firewall.network.blockPrivateDestinations },
            set: { on in Task { await firewall.setBlockPrivateDestinations(on) } }
        )
    }
}

struct PortExceptionsSection: View {
    let firewall: FirewallModel
    @State private var proto = TransportProtocol.tcp
    @State private var destination = ""
    @State private var port = ""
    @State private var note = ""

    var body: some View {
        Section("Port exceptions (direct traffic past the guards)") {
            ForEach(firewall.network.portExceptions) { exception in
                HStack {
                    Text(verbatim: "\(exception.proto.displayName) \(exception.destination) \(exception.port.map { "port \($0)" } ?? "every port")")
                        .font(.system(.body, design: .monospaced))
                    if let note = exception.note {
                        Text(note).foregroundStyle(.secondary)
                    }
                    Spacer()
                    Button {
                        Task { await firewall.removeException(exception.id) }
                    } label: {
                        Image(systemName: "minus.circle")
                    }
                    .buttonStyle(.borderless)
                    .help("Remove")
                }
            }
            HStack {
                Picker("Protocol", selection: $proto) {
                    ForEach(TransportProtocol.allCases, id: \.self) { value in
                        Text(value.displayName).tag(value)
                    }
                }
                .labelsHidden()
                .frame(width: 80)
                TextField("Address, CIDR or any", text: $destination)
                TextField("Port", text: $port)
                    .frame(width: 70)
                TextField("Note", text: $note)
                Button("Add") { add() }
                    .disabled(destination.isEmpty)
            }
        }
    }

    private func add() {
        Task {
            if await firewall.addException(proto: proto, destination: destination, port: port, note: note) {
                destination = ""
                port = ""
                note = ""
            }
        }
    }
}

struct DomainRulesSection: View {
    let firewall: FirewallModel
    @State private var pattern = ""
    @State private var action = DomainAction.allow
    @State private var inspect = false

    var body: some View {
        Section("Domains (sandvault-netd)") {
            Picker("Hosts without a rule", selection: defaultAction) {
                ForEach(DomainAction.allCases, id: \.self) { action in
                    Text(action.displayName).tag(action)
                }
            }
            Picker("Unanswered asks", selection: askFallback) {
                Text(DomainAction.deny.displayName).tag(DomainAction.deny)
                Text(DomainAction.allow.displayName).tag(DomainAction.allow)
            }
            Stepper(value: askTimeout, in: 5...300, step: 5) {
                Text(verbatim: "Ask timeout: \(firewall.network.askTimeoutSeconds) s")
            }
            ForEach(firewall.network.domainRules) { rule in
                DomainRuleRow(firewall: firewall, rule: rule)
            }
            HStack {
                TextField("example.com, *.example.com or *", text: $pattern)
                Picker("Action", selection: $action) {
                    ForEach(DomainAction.allCases, id: \.self) { action in
                        Text(action.displayName).tag(action)
                    }
                }
                .labelsHidden()
                .frame(width: 90)
                Toggle("Inspect", isOn: $inspect)
                Button("Add") { add() }
                    .disabled(pattern.isEmpty)
            }
        }
    }

    private func add() {
        Task {
            if await firewall.upsertDomainRule(pattern: pattern, action: action, inspect: inspect) {
                pattern = ""
                inspect = false
            }
        }
    }

    private var defaultAction: Binding<DomainAction> {
        Binding<DomainAction>(get: { firewall.network.defaultAction }, set: { action in Task { await firewall.setDefaultAction(action) } })
    }

    private var askFallback: Binding<DomainAction> {
        Binding<DomainAction>(get: { firewall.network.askFallback }, set: { action in Task { await firewall.setAskFallback(action) } })
    }

    private var askTimeout: Binding<Int> {
        Binding<Int>(get: { firewall.network.askTimeoutSeconds }, set: { seconds in Task { await firewall.setAskTimeout(seconds) } })
    }
}

struct DomainRuleRow: View {
    let firewall: FirewallModel
    let rule: DomainRule

    var body: some View {
        HStack {
            Text(rule.pattern)
                .font(.system(.body, design: .monospaced))
            if let note = rule.note {
                Text(note).foregroundStyle(.secondary)
            }
            Spacer()
            Picker("Action", selection: action) {
                ForEach(DomainAction.allCases, id: \.self) { action in
                    Text(action.displayName).tag(action)
                }
            }
            .labelsHidden()
            .frame(width: 90)
            Toggle("Inspect", isOn: inspect)
            Button {
                Task { await firewall.removeDomainRule(rule.id) }
            } label: {
                Image(systemName: "minus.circle")
            }
            .buttonStyle(.borderless)
            .help("Remove")
        }
    }

    private var action: Binding<DomainAction> {
        Binding<DomainAction>(
            get: { rule.action },
            set: { action in Task { await firewall.upsertDomainRule(pattern: rule.pattern, action: action) } }
        )
    }

    private var inspect: Binding<Bool> {
        Binding<Bool>(get: { rule.inspect }, set: { on in Task { await firewall.setInspect(rule, on) } })
    }
}

struct DnsOverridesSection: View {
    let firewall: FirewallModel
    @State private var pattern = ""
    @State private var address = ""

    var body: some View {
        Section("DNS overrides") {
            ForEach(firewall.network.dnsOverrides) { entry in
                HStack {
                    Text(verbatim: "\(entry.pattern) -> \(entry.address)")
                        .font(.system(.body, design: .monospaced))
                    Spacer()
                    Button {
                        Task { await firewall.removeDnsOverride(entry.id) }
                    } label: {
                        Image(systemName: "minus.circle")
                    }
                    .buttonStyle(.borderless)
                    .help("Remove")
                }
            }
            HStack {
                TextField("Host or *.domain", text: $pattern)
                TextField("IPv4 or IPv6 address", text: $address)
                Button("Add") { add() }
                    .disabled(pattern.isEmpty || address.isEmpty)
            }
        }
    }

    private func add() {
        Task {
            if await firewall.upsertDnsOverride(pattern: pattern, address: address) {
                pattern = ""
                address = ""
            }
        }
    }
}

struct InspectionSection: View {
    let firewall: FirewallModel

    var body: some View {
        Section("TLS inspection") {
            Toggle("Decrypt and log HTTP for hosts whose rule has Inspect", isOn: enabled)
                .disabled(firewall.isBusy)
            LabeledContent("CA", value: firewall.caSummary)
            Text("Works for tools that read the CA bundle from the sandbox's environment; others keep their connection uninspected.")
                .font(.callout)
                .foregroundStyle(.secondary)
        }
    }

    private var enabled: Binding<Bool> {
        Binding<Bool>(get: { firewall.network.inspection.enabled }, set: { on in Task { await firewall.setInspection(on) } })
    }
}

/// The generated anchor, shown before anything is loaded.
struct ApplySheet: View {
    let firewall: FirewallModel
    let plan: FirewallApplyPlan

    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            Text(verbatim: "Apply firewall: \(plan.mode.displayName)")
                .font(.title3)
                .fontWeight(.semibold)
            Text(plan.summary)
                .foregroundStyle(.secondary)
            ForEach(plan.notes, id: \.self) { note in
                Label(note, systemImage: "exclamationmark.triangle")
                    .foregroundStyle(.orange)
            }
            CodeView(text: plan.previewText)
            HStack {
                Text("Applying also ends a panic.")
                    .font(.callout)
                    .foregroundStyle(.secondary)
                Spacer()
                Button("Cancel", role: .cancel) { firewall.cancelApply() }
                    .keyboardShortcut(.cancelAction)
                Button("Apply") { Task { await firewall.confirmApply() } }
                    .keyboardShortcut(.defaultAction)
            }
        }
        .padding(20)
        .frame(minWidth: 640, minHeight: 460)
    }
}
