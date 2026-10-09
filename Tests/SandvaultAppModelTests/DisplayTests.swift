import Foundation
import SandvaultCore
import SandvaultEnforce
import SandvaultNet
import Testing
@testable import SandvaultAppModel

@MainActor
@Suite struct DisplayTests {
    @Test func netdLinkSummary() async {
        let world = TestWorld()
        defer { world.cleanUp() }
        world.netd.running.set(false)
        let link = NetdLink(connector: world.netd, clock: world.clock.clock)
        #expect(link.summary == "Not connected to sandvault-netd")
        link.start()
        defer { link.stop() }
        #expect(await eventually { link.summary.hasPrefix("sandvault-netd not reachable (not installed: sandvault-netd is not running") })
    }

    @Test func applyPlanSummary() async throws {
        let world = TestWorld()
        defer { world.cleanUp() }
        let firewall = world.model().firewall
        await firewall.setMode(.open)
        await firewall.prepareApply()
        let plan = try #require(firewall.pendingApply)
        #expect(plan.summary == "Anchor com.apple/sandvault-config for uid 601; loopback ports 3000")

        world.policy.helperStatus.mutate {
            $0.firewallMode = .open
            $0.pfEnabled = true
            $0.panicActive = true
        }
        await firewall.refreshStatus()
        #expect(firewall.loadedSummary == "open, pf enabled, PANIC active")
        #expect(firewall.caSummary == "not created (turning inspection on creates it)")
    }

    @Test func suggestionRepoToolAndMigrationSummaries() {
        let suggestion = RuleSuggestion(
            id: "file:literal:/opt/data/x", proposal: .file(FileRule(path: "/opt/data/x", match: .literal, access: .readWrite, effect: .allow)),
            occurrences: 2, processes: ["node"], examples: [], lastSeen: Date()
        )
        #expect(suggestion.summary == "allow read-write literal /opt/data/x")

        let record = HandoffRecord(hostPath: "/Users/alice/src/app", repoName: "app", sandboxPath: "/Users/Shared/sv-alice/repos/app", agent: .claude)
        let repo = RepoStatus(record: record, name: "app", sandboxPath: record.sandboxPath, branch: "main", dirty: true, unfetchedCommits: 1, behindOrigin: 2)
        #expect(repo.summary == "main · 1 new commit to fetch · 2 behind origin · uncommitted changes")
        #expect(RepoStatus(record: nil, name: "x", sandboxPath: "/x").summary == "detached · not handed off from this Mac")

        let tool = ToolStatus(name: "jq", hostPath: "/opt/homebrew/bin/jq", location: .homebrew, reachableInSandbox: true, reason: "")
        #expect(tool.summary == "/opt/homebrew/bin/jq (homebrew) · reachable in the sandbox")

        let entry = MigrationEntry(item: .claudeMemory, source: "/Users/alice/.claude/CLAUDE.md", destination: ".claude/CLAUDE.md", bytes: 1500, overwrites: true)
        #expect(entry.summary == "/Users/alice/.claude/CLAUDE.md -> user/.claude/CLAUDE.md (1.5 kB), replaces the existing file")
        #expect(ProfileDrift.missing.tint == .orange)
    }

    @Test func netdAgentSummary() async {
        let world = TestWorld()
        defer { world.cleanUp() }
        let settings = world.model().settings
        await settings.refresh()
        #expect(settings.netdAgentSummary == "not installed")
        await settings.installNetd()
        #expect(settings.netdAgentSummary == "installed, not loaded")
    }
}
