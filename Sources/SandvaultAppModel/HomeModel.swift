import Foundation
import SandvaultCore

/// The card at the top of Home (D53): how protected the sandbox is, in plain words.
public struct HomeStatus: Sendable, Equatable {
    public var title: String
    public var detail: String
    public var symbolName: String
    public var tint: Tint

    /// In priority order: an emergency stop, netd missing where it carries the web, then the protection level.
    /// `developerBasics` says whether the developer basics apply (the Ask sentence mentions them only then).
    public init(protection: ProtectionLevel?, panicActive: Bool, netdMissing: Bool, firewallMode: FirewallMode, developerBasics: Bool) {
        if panicActive {
            (title, detail, symbolName, tint) = (
                "Everything in the sandbox is stopped", "No network and no programs. Your files are untouched.", "stop.circle.fill", .red
            )
            return
        }
        if netdMissing {
            (title, detail, symbolName, tint) = (
                "Websites do not work right now", "The network monitor is not running, so the sandbox cannot open any website.",
                "exclamationmark.triangle.fill", .orange
            )
            return
        }
        switch protection {
        case .ask?:
            let basics = developerBasics ? " Developer basics like GitHub and npm are allowed." : ""
            (title, detail, symbolName, tint) = (
                "Your sandbox is protected", "A new website waits for your answer.\(basics)", "checkmark.shield.fill", .green
            )
        case .watch?:
            (title, detail, symbolName, tint) = (
                "Your sandbox is being watched", "Everything is allowed, and every website the sandbox uses is listed.", "eye.fill", .blue
            )
        case .blockAll?:
            (title, detail, symbolName, tint) = (
                "Your sandbox is offline", "The sandbox has no network. Running programs keep running.", "network.slash", .gray
            )
        case .off?:
            (title, detail, symbolName, tint) = (
                "Your sandbox is not protected", "The sandbox reaches the internet directly. Websites are not listed by name.", "shield.slash", .orange
            )
        case nil:
            (title, detail, symbolName, tint) = (
                "Custom protection", "Firewall mode \(firewallMode.displayName). Choosing a level replaces it.", "shield.lefthalf.filled", .blue
            )
        }
    }
}

/// What Home's next-step button does.
public enum HomeStepAction: Sendable, Equatable {
    case installHelper
    case startNetd
    case createSandbox
    case endStop
    case applyFirewall
    case open(Screen)
}

/// The next setup step as Home shows it: plain words below Expert, the doctor's words and command in Expert.
public struct HomeStep: Sendable, Equatable {
    public var title: String
    public var detail: String
    /// A command to run in a terminal, where the app cannot do the step itself.
    public var command: String?
    public var action: HomeStepAction?
    public var actionTitle: String?
    public var isDone: Bool

    public init(_ step: SetupStep, mode: InterfaceMode) {
        isDone = step.isDone
        let expert = mode == .expert
        switch step {
        case .installHelper:
            action = .installHelper
            actionTitle = "Install Helper…"
        case .startNetd:
            action = .startNetd
            actionTitle = "Start"
        case .createSandbox:
            action = .createSandbox
            actionTitle = "Create Sandbox"
        case .endPanic:
            action = expert ? step.screen.map(HomeStepAction.open) : .endStop
            actionTitle = expert ? step.screen.map { "Open \($0.title)" } : "End Stop"
        case .applyFirewall:
            action = expert ? step.screen.map(HomeStepAction.open) : .applyFirewall
            actionTitle = expert ? step.screen.map { "Open \($0.title)" } : "Apply"
        case .enableFirewall:
            // Below Expert the protection picker on Home is the action.
            action = expert ? step.screen.map(HomeStepAction.open) : nil
            actionTitle = expert ? step.screen.map { "Open \($0.title)" } : nil
        case .checking, .installSandvault, .ready:
            action = nil
            actionTitle = nil
        }
        if expert {
            title = step.title
            detail = step.detail
            command = step.suggestedCommand
            return
        }
        switch step {
        case .checking:
            (title, detail, command) = ("Checking your Mac", "This takes a few seconds.", nil)
        case .installSandvault(let fix):
            (title, detail, command) = ("Install sandvault first", "Sandvault Config works with the sandvault command line tool. Install it, then come back.", fix)
        case .createSandbox:
            (title, detail, command) = ("Create your sandbox", "A separate Mac user for agents and tools. macOS asks for your password.", nil)
        case .installHelper:
            (title, detail, command) = ("Let Sandvault protect the sandbox", "A small helper applies the protection. macOS asks for your password once.", nil)
        case .endPanic:
            (title, detail, command) = ("Emergency Stop is on", "The sandbox has no network. End the stop to bring the protection back.", nil)
        case .startNetd:
            (title, detail, command) = ("Start the network monitor", "It checks every website the sandbox opens. Without it, websites do not work.", nil)
        case .enableFirewall:
            (title, detail, command) = ("Turn on protection", "Choose a protection level above.", nil)
        case .applyFirewall:
            (title, detail, command) = ("Apply the protection again", "The protection in effect differs from the one you chose.", nil)
        case .ready:
            (title, detail, command) = ("Everything is set up", "The sandbox is ready and protected.", nil)
        }
    }
}

/// The line at the bottom of the sidebar: netd's own summary in Expert, plain words otherwise.
public struct SidebarStatus: Sendable, Equatable {
    public var text: String
    public var tint: Tint

    public init(mode: InterfaceMode, protection: ProtectionLevel?, panicActive: Bool, netdMissing: Bool, netdSummary: String) {
        if panicActive {
            (text, tint) = ("Emergency Stop is on. The sandbox has no network.", .red)
        } else if mode == .expert {
            (text, tint) = (netdSummary, netdMissing ? .orange : .green)
        } else if netdMissing {
            (text, tint) = ("Network monitor stopped. Websites do not work.", .orange)
        } else if let protection {
            (text, tint) = protection == .off ? ("Protection is off", .orange) : ("Protection on · \(protection.title)", .green)
        } else {
            (text, tint) = ("Custom protection", .blue)
        }
    }
}

extension ProtectionLevel {
    /// The level that ends an emergency stop: the one before the stop when the mode offers it, else Ask.
    public static func resume(from before: ProtectionLevel?, mode: InterfaceMode) -> ProtectionLevel {
        guard let before, choices(for: mode).contains(before) else { return .ask }
        return before
    }
}

extension ActivityItem {
    /// The newest websites for Home: host names only (no direct connections or pings), at most `limit`.
    public static func recentWebsites(_ items: [ActivityItem], limit: Int = 5) -> [ActivityItem] {
        Array(items.filter { $0.kind == .host }.prefix(limit))
    }
}
