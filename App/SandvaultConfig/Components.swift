import SandvaultAppModel
import SandvaultCore
import SwiftUI

extension Tint {
    @MainActor var color: Color {
        switch self {
        case .green: Color.green
        case .orange: Color.orange
        case .red: Color.red
        case .gray: Color.secondary
        case .blue: Color.blue
        }
    }
}

/// A result or error with an optional command to run.
struct MessageBanner: View {
    let message: UserMessage
    let dismiss: () -> Void

    var body: some View {
        HStack(alignment: .top, spacing: 8) {
            Image(systemName: message.kind.symbolName)
                .foregroundStyle(message.kind.tint.color)
            VStack(alignment: .leading, spacing: 2) {
                Text(message.title)
                    .fontWeight(.medium)
                if let detail = message.detail {
                    Text(detail)
                        .font(.callout)
                        .foregroundStyle(.secondary)
                        .textSelection(.enabled)
                }
                if let command = message.suggestedCommand {
                    Text(command)
                        .font(.system(.callout, design: .monospaced))
                        .textSelection(.enabled)
                }
            }
            Spacer(minLength: 0)
            Button(action: dismiss) {
                Image(systemName: "xmark")
            }
            .buttonStyle(.borderless)
            .help("Dismiss")
        }
        .padding(10)
        .background(Color.secondary.opacity(0.1), in: RoundedRectangle(cornerRadius: 8))
    }
}

/// A banner above a page when there is a message.
struct MessageArea: View {
    let message: UserMessage?
    let dismiss: () -> Void

    var body: some View {
        if let message {
            MessageBanner(message: message, dismiss: dismiss)
                .padding(.horizontal, 16)
                .padding(.top, 10)
        }
    }
}

struct CheckRow: View {
    let check: Check

    var body: some View {
        HStack(alignment: .top, spacing: 8) {
            Image(systemName: check.state.symbolName)
                .foregroundStyle(check.state.tint.color)
            VStack(alignment: .leading, spacing: 2) {
                Text(check.title)
                Text(check.detail)
                    .font(.caption)
                    .foregroundStyle(.secondary)
                    .textSelection(.enabled)
                if let fix = check.fix, check.state >= .warning {
                    Text(fix)
                        .font(.system(.caption, design: .monospaced))
                        .textSelection(.enabled)
                }
            }
        }
    }
}

/// Shown instead of a feature whose service is not in this build yet.
struct NotAvailableView: View {
    let title: String
    let note: String

    var body: some View {
        ContentUnavailableView(title, systemImage: "hammer", description: Text(note))
    }
}

/// Monospaced, selectable text in a scroll view (pf rules, profile diffs).
struct CodeView: View {
    let text: String

    var body: some View {
        ScrollView([.vertical, .horizontal]) {
            Text(text)
                .font(.system(.caption, design: .monospaced))
                .textSelection(.enabled)
                .frame(maxWidth: .infinity, alignment: .leading)
                .padding(8)
        }
        .background(Color.secondary.opacity(0.08))
    }
}
