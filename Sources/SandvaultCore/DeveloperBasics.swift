/// Websites most development work needs, allowed without asking unless a rule says otherwise (D53).
///
/// Only the web ports 80 and 443 and DNS; a user rule for the same host always wins, and other ports still follow
/// the rules and the default action. A group is on unless its id is in `DeveloperBasicsSettings.disabledGroups`,
/// so a group added in a later version starts on.
public struct DeveloperBasicsGroup: Sendable, Equatable, Identifiable {
    public var id: String
    public var title: String
    public var symbolName: String
    /// `example.com` or `*.example.com`, like `DomainRule.pattern`.
    public var patterns: [String]

    public init(id: String, title: String, symbolName: String, patterns: [String]) {
        self.id = id
        self.title = title
        self.symbolName = symbolName
        self.patterns = patterns
    }

    public static let catalog: [DeveloperBasicsGroup] = [
        DeveloperBasicsGroup(
            id: "github", title: "GitHub", symbolName: "chevron.left.forwardslash.chevron.right",
            patterns: ["*.github.com", "*.githubusercontent.com", "*.githubassets.com", "ghcr.io"]
        ),
        DeveloperBasicsGroup(id: "npm", title: "npm", symbolName: "shippingbox", patterns: ["*.npmjs.org", "*.npmjs.com", "*.yarnpkg.com"]),
        DeveloperBasicsGroup(id: "python", title: "Python packages", symbolName: "shippingbox", patterns: ["*.pypi.org", "*.pythonhosted.org"]),
        DeveloperBasicsGroup(id: "homebrew", title: "Homebrew", symbolName: "mug", patterns: ["*.brew.sh", "ghcr.io"]),
        DeveloperBasicsGroup(id: "rust", title: "Rust crates", symbolName: "gearshape.2", patterns: ["*.crates.io", "*.rust-lang.org"]),
        DeveloperBasicsGroup(id: "go", title: "Go modules", symbolName: "shippingbox", patterns: ["*.golang.org", "*.go.dev"]),
        DeveloperBasicsGroup(id: "docker", title: "Docker Hub", symbolName: "cube.box", patterns: ["*.docker.io", "*.docker.com"]),
        DeveloperBasicsGroup(
            id: "ai", title: "AI services", symbolName: "sparkles",
            patterns: ["*.anthropic.com", "*.claude.ai", "*.openai.com", "chatgpt.com", "generativelanguage.googleapis.com"]
        ),
    ]

    public static func group(id: String) -> DeveloperBasicsGroup? {
        catalog.first { $0.id == id }
    }
}

public struct DeveloperBasicsSettings: Codable, Sendable, Equatable {
    /// Off: no group applies, whatever `disabledGroups` says.
    public var enabled: Bool
    /// Ids of `DeveloperBasicsGroup.catalog` entries switched off.
    public var disabledGroups: [String]

    public init(enabled: Bool = true, disabledGroups: [String] = []) {
        self.enabled = enabled
        self.disabledGroups = disabledGroups
    }

    enum CodingKeys: String, CodingKey { case enabled, disabledGroups }

    public init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        enabled = try c.value(.enabled, default: true)
        disabledGroups = try c.value(.disabledGroups, default: [])
    }

    public func isOn(_ group: DeveloperBasicsGroup) -> Bool {
        enabled && !disabledGroups.contains(group.id)
    }

    /// The groups that apply, in catalog order.
    public var activeGroups: [DeveloperBasicsGroup] {
        DeveloperBasicsGroup.catalog.filter(isOn)
    }

    public mutating func set(_ group: DeveloperBasicsGroup, on: Bool) {
        disabledGroups.removeAll { $0 == group.id }
        if !on { disabledGroups.append(group.id) }
    }
}
