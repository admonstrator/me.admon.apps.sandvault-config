import SandvaultCore

/// How much of the app the window shows (D53). Each mode adds pages and settings to the one before it.
public enum InterfaceMode: String, Codable, CaseIterable, Identifiable, Comparable, Sendable {
    case easy, advanced, expert

    public var id: String { rawValue }

    public var title: String {
        switch self {
        case .easy: "Easy"
        case .advanced: "Advanced"
        case .expert: "Expert"
        }
    }

    public var symbolName: String {
        switch self {
        case .easy: "leaf"
        case .advanced: "slider.horizontal.3"
        case .expert: "terminal"
        }
    }

    /// One line for the mode cards in Settings and on first launch.
    public var explanation: String {
        switch self {
        case .easy: "The sandbox with safe defaults. You see every website it uses and decide about new ones."
        case .advanced: "Adds Activity, Look inside HTTPS, sandbox presets, tools and the Lab."
        case .expert: "Every setting: firewall and proxy, sandbox rules, processes, network, keys and diagnostics."
        }
    }

    public static func < (lhs: InterfaceMode, rhs: InterfaceMode) -> Bool {
        allCases.firstIndex(of: lhs)! < allCases.firstIndex(of: rhs)!
    }
}

/// A titled group of sidebar pages.
public struct SidebarSection: Identifiable, Equatable, Sendable {
    public var id: String { title }
    public var title: String
    public var screens: [Screen]

    public init(title: String, screens: [Screen]) {
        self.title = title
        self.screens = screens
    }

    /// The sidebar of `mode`; sections without a page in that mode are left out.
    /// `.settings` is its own window, not a sidebar page.
    public static func sidebar(for mode: InterfaceMode) -> [SidebarSection] {
        let all = [
            SidebarSection(title: "Protect", screens: [.overview, .websites, .activity]),
            SidebarSection(title: "Work", screens: [.handoff, .sandbox, .lab, .tools]),
            SidebarSection(title: "Expert", screens: [.firewall, .rules, .processes, .network, .migration, .diagnostics]),
        ]
        return all.compactMap { section in
            let screens = section.screens.filter { $0.minimumMode <= mode }
            return screens.isEmpty ? nil : SidebarSection(title: section.title, screens: screens)
        }
    }
}

extension ProtectionLevel {
    /// The levels the protection picker offers; Easy leaves out Off, which drops every safeguard.
    public static func choices(for mode: InterfaceMode) -> [ProtectionLevel] {
        mode == .easy ? [.ask, .watch, .blockAll] : [.ask, .watch, .blockAll, .off]
    }
}

extension SandboxSetup {
    /// The presets first launch and the Sandbox page offer; Unrestricted only in Expert.
    public static func choices(for mode: InterfaceMode) -> [SandboxSetup] {
        mode == .expert ? allCases : [.everyday, .careful, .offline]
    }
}
