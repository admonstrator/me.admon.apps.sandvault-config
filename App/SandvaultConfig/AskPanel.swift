import AppKit
import Observation
import SandvaultAppModel
import SandvaultCore
import SwiftUI

/// One small always-on-top panel per pending ask. Panels open when netd raises an ask and close when it is
/// answered or resolved (timeout, other client); in the background a notification with the same answers is posted.
/// Panels come to the front without taking the keyboard, so Return typed into a terminal never answers an ask;
/// after a click into the panel, Return triggers its default button.
@MainActor
final class AskPanelController {
    static let width: CGFloat = 380

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
                notifier.post(ask, title: asks.notificationTitle(for: ask), body: asks.notificationBody(for: ask))
            }
        }
    }

    private func makePanel(for ask: AskRequest) -> NSPanel {
        let panel = AskWindow(
            contentRect: NSRect(x: 0, y: 0, width: Self.width, height: 260),
            styleMask: [.borderless, .nonactivatingPanel],
            backing: .buffered,
            defer: false
        )
        panel.title = "Connection request"
        panel.level = .floating
        panel.isFloatingPanel = true
        panel.hidesOnDeactivate = false
        panel.isReleasedWhenClosed = false
        panel.isMovableByWindowBackground = true
        panel.isOpaque = false
        panel.backgroundColor = .clear
        panel.hasShadow = true
        panel.collectionBehavior = [.canJoinAllSpaces, .fullScreenAuxiliary]
        let hosting = NSHostingView(rootView: AskPanelView(asks: asks, ask: ask))
        panel.contentView = hosting
        panel.setContentSize(hosting.fittingSize)
        panel.invalidateShadow()
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

/// A borderless panel still becomes key when clicked, so the default button and Escape work.
private final class AskWindow: NSPanel {
    override var canBecomeKey: Bool { true }
}

/// The request panel of the approved mockup (D41): header, verdict, detail tiles, then one row of equal height.
struct AskPanelView: View {
    let asks: AsksModel
    let ask: AskRequest

    @State private var selectedTile: AskDetailKind?

    var body: some View {
        let panel = asks.presentation(for: ask, at: Date())
        VStack(alignment: .leading, spacing: 14) {
            AskHeader(asks: asks, ask: ask, panel: panel)
            if let verdict = panel.verdict {
                AskVerdictStrip(verdict: verdict)
            }
            if !panel.tiles.isEmpty {
                AskTileGrid(tiles: panel.tiles, selected: $selectedTile)
                Text(panel.tiles.first { $0.kind == selectedTile }?.explanation ?? "")
                    .font(.caption)
                    .foregroundStyle(.secondary)
                    .lineLimit(2, reservesSpace: true)
                    .padding(.horizontal, 2)
                    .padding(.top, -6)
            }
            AskAnswerRow(asks: asks, ask: ask, panel: panel)
            if let message = asks.message, message.kind != .success {
                Text(message.title)
                    .font(.caption)
                    .foregroundStyle(message.kind.tint.color)
            }
        }
        .padding(16)
        .frame(width: AskPanelController.width)
        .glassEffect(.regular, in: .rect(cornerRadius: 22))
    }
}

private struct AskHeader: View {
    let asks: AsksModel
    let ask: AskRequest
    let panel: AskPresentation

    var body: some View {
        HStack(alignment: .center, spacing: 12) {
            ProgramIcon(path: panel.iconPath, seal: panel.seal)
            VStack(alignment: .leading, spacing: 1) {
                Text(panel.process)
                    .font(.system(size: 14, weight: .semibold))
                    .lineLimit(1)
                Text(verbatim: panel.destination)
                    .font(.system(size: 12.5, design: .monospaced))
                    .textSelection(.enabled)
                    .lineLimit(2)
                if let subtitle = panel.subtitle {
                    Text(verbatim: subtitle)
                        .font(.system(size: 11.5, design: .monospaced))
                        .foregroundStyle(.secondary)
                        .lineLimit(1)
                        .truncationMode(.middle)
                }
            }
            Spacer(minLength: 0)
            TimelineView(.periodic(from: .now, by: 1)) { context in
                CountdownRing(
                    fraction: asks.fractionRemaining(ask, at: context.date),
                    label: asks.ringLabel(ask, at: context.date)
                )
                .help(asks.ringHelp(ask, at: context.date))
            }
        }
    }
}

/// The executable's icon (the app bundle's when it has one) with the signature seal, or a generic symbol.
private struct ProgramIcon: View {
    let path: String?
    let seal: AskSeal?

    var body: some View {
        Group {
            if let path {
                Image(nsImage: NSWorkspace.shared.icon(forFile: path))
                    .resizable()
                    .interpolation(.high)
            } else {
                Image(systemName: "terminal")
                    .font(.system(size: 22, weight: .medium))
                    .foregroundStyle(.secondary)
                    .frame(maxWidth: .infinity, maxHeight: .infinity)
                    .background(Color.primary.opacity(0.07), in: RoundedRectangle(cornerRadius: 11, style: .continuous))
            }
        }
        .frame(width: 44, height: 44)
        .overlay(alignment: .bottomTrailing) {
            if let seal {
                Image(systemName: seal.symbolName)
                    .font(.system(size: 15, weight: .semibold))
                    .foregroundStyle(seal.tint.color)
                    .background(Circle().fill(.background).padding(-1.5))
                    .offset(x: 4, y: 4)
                    .help(seal.help)
            }
        }
    }
}

private struct CountdownRing: View {
    let fraction: Double
    let label: String

    var body: some View {
        ZStack {
            Circle()
                .stroke(Color.primary.opacity(0.1), lineWidth: 3)
            Circle()
                .trim(from: 0, to: fraction)
                .stroke(Color.accentColor, style: StrokeStyle(lineWidth: 3, lineCap: .round))
                .rotationEffect(.degrees(-90))
                .animation(.linear(duration: 1), value: fraction)
            Text(verbatim: label)
                .font(.system(size: 10.5, weight: .semibold).monospacedDigit())
        }
        .frame(width: 30, height: 30)
    }
}

private struct AskVerdictStrip: View {
    let verdict: AskVerdict

    var body: some View {
        HStack(spacing: 8) {
            Image(systemName: verdict.symbolName)
                .font(.system(size: 16, weight: .semibold))
                .foregroundStyle(verdict.tint.color)
            Text(verdict.title)
                .fontWeight(.semibold)
            Spacer(minLength: 8)
            if let hint = verdict.hint {
                Text(hint)
                    .font(.system(size: 11.5))
                    .foregroundStyle(.secondary)
                    .lineLimit(1)
            }
        }
        .padding(.horizontal, 12)
        .padding(.vertical, 8)
        .background(verdict.tint.color.opacity(0.15), in: RoundedRectangle(cornerRadius: 12, style: .continuous))
        .help(verdict.help)
    }
}

private struct AskTileGrid: View {
    let tiles: [AskTile]
    @Binding var selected: AskDetailKind?

    private let columns = Array(repeating: GridItem(.flexible(), spacing: 6), count: 3)

    var body: some View {
        LazyVGrid(columns: columns, spacing: 6) {
            ForEach(tiles) { tile in
                Button {
                    selected = selected == tile.kind ? nil : tile.kind
                } label: {
                    AskTileView(tile: tile, isSelected: selected == tile.kind)
                }
                .buttonStyle(.plain)
                .help(tile.explanation)
                .accessibilityLabel(Text(verbatim: "\(tile.title), \(tile.subtitle)"))
                .accessibilityHint(Text(tile.explanation))
            }
        }
    }
}

private struct AskTileView: View {
    let tile: AskTile
    let isSelected: Bool

    private var symbolColor: Color {
        switch tile.tone {
        case .plus: .green
        case .minus: .red
        case .neutral: .secondary
        }
    }

    private var fill: Color {
        tile.tone == .minus ? Color.red.opacity(0.14) : Color.primary.opacity(0.05)
    }

    var body: some View {
        HStack(spacing: 7) {
            Image(systemName: tile.symbolName)
                .font(.system(size: 15, weight: .medium))
                .foregroundStyle(symbolColor)
                .frame(width: 20)
            VStack(alignment: .leading, spacing: 2) {
                Text(verbatim: tile.title)
                    .font(.system(size: 12.5, weight: .semibold))
                    .lineLimit(1)
                Text(verbatim: tile.subtitle)
                    .font(.system(size: 11))
                    .foregroundStyle(.secondary)
                    .lineLimit(1)
            }
            Spacer(minLength: 0)
        }
        .padding(.horizontal, 9)
        .padding(.vertical, 8)
        .frame(maxWidth: .infinity, minHeight: 50, alignment: .leading)
        .background(fill, in: RoundedRectangle(cornerRadius: 12, style: .continuous))
        .overlay {
            RoundedRectangle(cornerRadius: 12, style: .continuous)
                .strokeBorder(isSelected ? Color.accentColor : Color.clear, lineWidth: 1.5)
        }
        .contentShape(RoundedRectangle(cornerRadius: 12, style: .continuous))
    }
}

/// How long the answer counts, then Deny and Allow of equal size. With the safer default and a suspicious
/// request, Deny is red and the default button; otherwise Allow is.
private struct AskAnswerRow: View {
    let asks: AsksModel
    let ask: AskRequest
    let panel: AskPresentation

    var body: some View {
        HStack(spacing: 8) {
            Menu {
                ForEach(Array(panel.options.enumerated()), id: \.element.id) { index, option in
                    if index == 1 { Divider() }
                    Toggle(isOn: chosen(option)) {
                        Text(option.label)
                        Text(verbatim: option.target)
                            .font(.system(.caption, design: .monospaced))
                    }
                }
            } label: {
                Text(asks.rememberTitle(for: ask))
                    .lineLimit(1)
                    .frame(maxWidth: .infinity, alignment: .leading)
            }
            .menuStyle(.button)
            .buttonStyle(.glass)
            .help(asks.rememberHelp(for: ask))

            answerButton("Deny", allow: false, prominent: panel.prefersDeny, tint: .red)
            answerButton("Allow", allow: true, prominent: !panel.prefersDeny, tint: .accentColor)
        }
        .controlSize(.large)
        .disabled(asks.answering.contains(ask.id))
    }

    private func chosen(_ option: AskRememberOption) -> Binding<Bool> {
        Binding<Bool>(
            get: { asks.rememberedScope(for: ask) == option.scope },
            set: { on in if on { asks.setRememberedScope(option.scope, for: ask) } }
        )
    }

    @ViewBuilder
    private func answerButton(_ title: String, allow: Bool, prominent: Bool, tint: Color) -> some View {
        let button = Button {
            Task { await asks.answer(ask, allow: allow) }
        } label: {
            Text(title)
                .frame(maxWidth: .infinity)
        }
        .frame(width: 96)
        if prominent {
            button
                .buttonStyle(.glassProminent)
                .tint(tint)
                .keyboardShortcut(.defaultAction)
        } else {
            button
                .buttonStyle(.glass)
        }
    }
}
