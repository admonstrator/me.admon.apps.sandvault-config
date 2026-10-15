import SandvaultAppModel
import SandvaultCore
import SwiftUI

/// First launch (D53), as a sheet on the main window: step 1 the mode, step 2 a sandbox preset (or Skip), then
/// `finishOnboarding` creates the sandbox with it, or gives an existing one the preset's protection level.
struct OnboardingView: View {
    let model: AppModel

    @State private var step = 0
    @State private var mode = InterfaceMode.easy
    @State private var setup = SandboxSetup.careful
    @State private var finishing = false

    var body: some View {
        VStack(alignment: .leading, spacing: 16) {
            StepDots(count: 2, current: step)
            if step == 0 {
                chooseMode
            } else {
                choosePreset
            }
        }
        .padding(24)
        .frame(width: 620)
        .disabled(finishing)
    }

    // MARK: Step 1

    private var chooseMode: some View {
        VStack(alignment: .leading, spacing: 16) {
            SheetIcon(symbol: "shippingbox.fill", color: .indigo)
            VStack(alignment: .leading, spacing: 6) {
                Text("Welcome to Sandvault")
                    .font(.title2.weight(.semibold))
                Text("Agents and tools run as a separate Mac user. They see your projects only when you hand them over, and the internet only where you allow it. How much do you want to see?")
                    .foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true)
            }
            ModeCards(selected: mode) { mode = $0 }
            Text("You can change this any time in Settings.")
                .font(.caption)
                .foregroundStyle(.secondary)
            HStack {
                Spacer()
                Button("Continue") {
                    if !SandboxSetup.choices(for: mode).contains(setup) { setup = .careful }
                    step = 1
                }
                .buttonStyle(.borderedProminent)
                .keyboardShortcut(.defaultAction)
            }
        }
    }

    // MARK: Step 2

    private var choosePreset: some View {
        let installed = model.sandbox.installed
        return VStack(alignment: .leading, spacing: 16) {
            VStack(alignment: .leading, spacing: 6) {
                Text(installed ? "Choose your protection" : "Create your sandbox")
                    .font(.title2.weight(.semibold))
                Text(installed
                    ? "Your sandbox already exists. Pick how careful it should be; its rules stay as they are."
                    : "Pick how careful it should be. You can change it later on Home.")
                    .foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true)
            }
            VStack(spacing: 8) {
                ForEach(SandboxSetup.choices(for: mode)) { choice in
                    PresetRow(setup: choice, selected: choice == setup) { setup = choice }
                }
            }
            if !installed {
                Label("macOS asks for your password once to create the sandbox user.", systemImage: "lock")
                    .font(.caption)
                    .foregroundStyle(.secondary)
            }
            HStack {
                Button("Back") { step = 0 }
                Spacer()
                if finishing {
                    ProgressView()
                        .controlSize(.small)
                }
                Button("Skip") { finish(nil) }
                    .help("Start without creating a sandbox. Home shows the next step.")
                Button(installed ? "Apply" : "Create Sandbox") { finish(setup) }
                    .buttonStyle(.borderedProminent)
                    .keyboardShortcut(.defaultAction)
            }
        }
    }

    private func finish(_ setup: SandboxSetup?) {
        finishing = true
        let mode = self.mode
        Task {
            await model.finishOnboarding(mode: mode, setup: setup)
            await model.overview.refresh()
            finishing = false
        }
    }
}

/// One preset as a selectable row: symbol, title, the model's sentence.
private struct PresetRow: View {
    let setup: SandboxSetup
    let selected: Bool
    let action: () -> Void

    var body: some View {
        let shape = RoundedRectangle(cornerRadius: 10, style: .continuous)
        Button(action: action) {
            HStack(alignment: .top, spacing: 12) {
                Image(systemName: symbol)
                    .font(.system(size: 13, weight: .semibold))
                    .foregroundStyle(.white)
                    .frame(width: 28, height: 28)
                    .background(color, in: RoundedRectangle(cornerRadius: 7, style: .continuous))
                VStack(alignment: .leading, spacing: 2) {
                    HStack(spacing: 6) {
                        Text(setup.title)
                            .font(.headline)
                        if setup == .careful {
                            Text("Recommended")
                                .font(.caption2.weight(.semibold))
                                .foregroundStyle(.green)
                        }
                    }
                    Text(setup.explanation)
                        .font(.callout)
                        .foregroundStyle(.secondary)
                        .fixedSize(horizontal: false, vertical: true)
                }
                Spacer(minLength: 0)
                Image(systemName: selected ? "checkmark.circle.fill" : "circle")
                    .foregroundStyle(selected ? Color.accentColor : Color.secondary)
            }
            .padding(10)
            .frame(maxWidth: .infinity, alignment: .leading)
            .background(selected ? Color.accentColor.opacity(0.12) : Color.primary.opacity(0.04), in: shape)
            .overlay {
                shape.strokeBorder(selected ? Color.accentColor : Color.primary.opacity(0.1), lineWidth: selected ? 2 : 1)
            }
            .contentShape(shape)
        }
        .buttonStyle(.plain)
        .accessibilityAddTraits(selected ? .isSelected : [])
    }

    private var symbol: String {
        switch setup {
        case .everyday: "eye"
        case .careful: "checkmark.shield"
        case .offline: "network.slash"
        case .unrestricted: "shield.slash"
        }
    }

    private var color: Color {
        switch setup {
        case .everyday: .blue
        case .careful: .green
        case .offline: .gray
        case .unrestricted: .orange
        }
    }
}

/// Where the sheet is: one dot per step.
private struct StepDots: View {
    let count: Int
    let current: Int

    var body: some View {
        HStack(spacing: 6) {
            ForEach(0..<count, id: \.self) { index in
                Capsule()
                    .fill(index <= current ? Color.accentColor : Color.primary.opacity(0.15))
                    .frame(width: 18, height: 4)
            }
        }
        .accessibilityElement(children: .ignore)
        .accessibilityLabel("Step \(current + 1) of \(count)")
    }
}

/// A large white symbol on a coloured square, at the top of a sheet.
private struct SheetIcon: View {
    let symbol: String
    let color: Color

    var body: some View {
        Image(systemName: symbol)
            .font(.system(size: 24, weight: .semibold))
            .foregroundStyle(.white)
            .frame(width: 52, height: 52)
            .background(color, in: RoundedRectangle(cornerRadius: 13, style: .continuous))
    }
}
