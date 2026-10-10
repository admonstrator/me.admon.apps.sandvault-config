import AppKit
import Observation
import SandvaultAppModel
import SandvaultCore
import SwiftUI

/// One small always-on-top panel per pending ask. Panels open when netd raises an ask and close when it is
/// answered or resolved (timeout, other client); in the background a notification with the same answers is posted.
@MainActor
final class AskPanelController {
    private let asks: AsksModel
    private let notifier: AskNotifier
    private var panels: [UUID: NSPanel] = [:]

    init(asks: AsksModel, notifier: AskNotifier) {
        self.asks = asks
        self.notifier = notifier
        track()
    }

    /// Re-registers after every change: `withObservationTracking` reports one change at a time.
    private func track() {
        let pending = withObservationTracking {
            asks.pending
        } onChange: { [self] in
            Task { @MainActor in self.track() }
        }
        sync(pending)
    }

    /// Every open panel to the front, oldest ask on top.
    func showAll() {
        NSApplication.shared.activate()
        for ask in asks.pending.reversed() {
            panels[ask.id]?.makeKeyAndOrderFront(nil)
        }
    }

    private func sync(_ pending: [AskRequest]) {
        let ids = Set(pending.map(\.id))
        for (id, panel) in panels where !ids.contains(id) {
            panel.close()
            panels[id] = nil
            notifier.withdraw(id)
        }
        for ask in pending where panels[ask.id] == nil {
            let panel = makePanel(for: ask)
            panels[ask.id] = panel
            panel.orderFrontRegardless()
            if !NSApplication.shared.isActive {
                notifier.post(ask, detail: asks.detail(for: ask))
            }
        }
    }

    private func makePanel(for ask: AskRequest) -> NSPanel {
        let panel = NSPanel(
            contentRect: NSRect(x: 0, y: 0, width: 440, height: 220),
            styleMask: [.titled, .closable, .utilityWindow, .nonactivatingPanel],
            backing: .buffered,
            defer: false
        )
        panel.title = "Connection request"
        panel.level = .floating
        panel.isFloatingPanel = true
        panel.hidesOnDeactivate = false
        panel.isReleasedWhenClosed = false
        panel.collectionBehavior = [.canJoinAllSpaces, .fullScreenAuxiliary]
        let hosting = NSHostingView(rootView: AskPanelView(asks: asks, ask: ask))
        panel.contentView = hosting
        panel.setContentSize(hosting.fittingSize)
        if let screen = NSScreen.main?.visibleFrame {
            let offset = CGFloat(panels.count % 8) * 26
            panel.setFrameOrigin(NSPoint(
                x: screen.maxX - panel.frame.width - 16 - offset,
                y: screen.maxY - panel.frame.height - 16 - offset
            ))
        } else {
            panel.center()
        }
        return panel
    }
}

struct AskPanelView: View {
    let asks: AsksModel
    let ask: AskRequest

    var body: some View {
        VStack(alignment: .leading, spacing: 10) {
            Text(ask.host)
                .font(.headline)
                .textSelection(.enabled)
            Text(asks.detail(for: ask))
                .foregroundStyle(.secondary)
            TimelineView(.periodic(from: .now, by: 1)) { context in
                VStack(alignment: .leading, spacing: 4) {
                    ProgressView(value: asks.fractionRemaining(ask, at: context.date))
                    Text(verbatim: "\(Format.countdown(asks.remainingSeconds(ask, at: context.date))) left, then \(asks.fallback.displayName.lowercased())")
                        .font(.caption)
                        .foregroundStyle(.secondary)
                }
            }
            Picker("Remember", selection: scope) {
                Text(asks.rulePattern(for: ask, scope: .host)).tag(AskScope.host)
                Text(asks.rulePattern(for: ask, scope: .domain)).tag(AskScope.domain)
            }
            .pickerStyle(.segmented)
            HStack {
                Button("Deny Always") { answer(.denyAlways) }
                Button("Deny Once") { answer(.denyOnce) }
                Spacer()
                Button("Allow Once") { answer(.allowOnce) }
                Button("Allow Always") { answer(.allowAlways) }
            }
            .disabled(asks.answering.contains(ask.id))
            if let message = asks.message, message.kind != .success {
                Text(message.title)
                    .font(.caption)
                    .foregroundStyle(message.kind.tint.color)
            }
        }
        .padding(16)
        .frame(width: 440)
    }

    private var scope: Binding<AskScope> {
        Binding<AskScope>(get: { asks.scope(for: ask) }, set: { scope in asks.setScope(scope, for: ask) })
    }

    private func answer(_ decision: AskDecision) {
        Task { await asks.answer(ask, decision) }
    }
}
