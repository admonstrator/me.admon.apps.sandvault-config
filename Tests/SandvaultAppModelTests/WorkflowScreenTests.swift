import Foundation
import SandvaultCore
import Testing
@testable import SandvaultAppModel

@MainActor
@Suite struct WorkflowScreenTests {
    nonisolated static func report(_ findings: [ReadinessFinding]) -> ReadinessReport {
        ReadinessReport(repositoryPath: "/Users/alice/src/app", repositoryName: "app", findings: findings)
    }

    @Test func handOffButtonFollowsTheReadinessReport() async throws {
        let world = TestWorld()
        defer { world.cleanUp() }
        let handoff = world.model().handoff
        #expect(handoff.disabledReason == "Choose or drop a repository folder.")

        world.workflow.readinessHandler.set { _ in
            Self.report([
                ReadinessFinding(kind: .symlinkOutside, severity: .blocker, path: "data", message: "data points outside the repository"),
                ReadinessFinding(kind: .envrc, severity: .blocker, path: ".envrc", message: ".envrc runs host code"),
                ReadinessFinding(kind: .uncommittedChanges, severity: .warning, message: "3 files changed"),
            ])
        }
        await handoff.select("/Users/alice/src/app")
        #expect(handoff.availability == .available)
        #expect(handoff.blockers.count == 2)
        #expect(!handoff.canHandOff)
        #expect(handoff.disabledReason == "Resolve the 2 blockers first.")

        world.workflow.readinessHandler.set { _ in Self.report([ReadinessFinding(kind: .uncommittedChanges, severity: .warning, message: "3 files changed")]) }
        await handoff.recheck()
        #expect(handoff.canHandOff)
        #expect(handoff.disabledReason == nil)
    }

    @Test func handOffSendsTheRequestAndRefreshesTheRepos() async throws {
        let world = TestWorld()
        defer { world.cleanUp() }
        try world.store.save(AppConfig(handoff: HandoffSettings(terminal: .ghostty, defaultAgent: .codex, svOptions: ["--browser"])))
        let record = HandoffRecord(hostPath: "/Users/alice/src/app", repoName: "app", sandboxPath: "/Users/Shared/sv-alice/repos/app", agent: .codex)
        world.workflow.readinessHandler.set { _ in Self.report([]) }
        world.workflow.handOffHandler.set { request in
            HandoffResult(record: record, briefingPath: "/Users/Shared/sv-alice/tmp/handoff-app.md", command: ["sv-clone", request.source], launched: true)
        }
        world.workflow.reposHandler.set { [RepoStatus(record: record, name: "app", sandboxPath: record.sandboxPath, unfetchedCommits: 2)] }
        let model = world.model()

        await model.handoff.select("/Users/alice/src/app")
        #expect(model.handoff.agent == .codex)
        model.handoff.task = "  Fix the failing test  \n"
        model.handoff.includeUncommitted = true
        await model.handoff.handOff()

        let request = try #require(world.workflow.requests.get().first)
        #expect(request == HandoffRequest(
            source: "/Users/alice/src/app", agent: .codex, task: "Fix the failing test", includeUncommitted: true,
            terminal: .ghostty, svOptions: ["--browser"], deployKey: .none
        ))
        #expect(model.handoff.message?.title == "Handed off app to Codex")
        #expect(model.repos.repositories.map(\.name) == ["app"])
    }

    @Test func missingServicesShowNotAvailableYet() async {
        let world = TestWorld()
        defer { world.cleanUp() }
        let model = world.model()

        await model.handoff.select("/Users/alice/src/app")
        #expect(!model.handoff.availability.isAvailable)
        #expect(model.handoff.disabledReason == "Hand-off is not available in this build yet.")
        #expect(model.handoff.message == nil)

        await model.repos.refresh()
        model.tools.query = "jq"
        await model.tools.check()
        await model.migration.preview()
        await model.keys.refresh()
        #expect(!model.repos.availability.isAvailable)
        #expect(!model.tools.availability.isAvailable)
        #expect(!model.migration.availability.isAvailable)
        #expect(!model.keys.availability.isAvailable)
        #expect([model.repos.message, model.tools.message, model.migration.message, model.keys.message].allSatisfy { $0 == nil })
    }

    @Test func fetchBackNeedsAHostRepository() async {
        let world = TestWorld()
        defer { world.cleanUp() }
        let model = world.model()
        await model.repos.fetchBack(RepoStatus(record: nil, name: "scratch", sandboxPath: "/Users/Shared/sv-alice/repos/scratch"))
        #expect(model.repos.message?.kind == .info)

        let record = HandoffRecord(hostPath: "/Users/alice/src/app", repoName: "app", sandboxPath: "/Users/Shared/sv-alice/repos/app", agent: .claude)
        world.workflow.reposHandler.set { [RepoStatus(record: record, name: "app", sandboxPath: record.sandboxPath, unfetchedCommits: 2)] }
        world.workflow.fetchHandler.set { record in RepoStatus(record: record, name: "app", sandboxPath: record.sandboxPath, unfetchedCommits: 0) }
        await model.repos.refresh()
        await model.repos.fetchBack(model.repos.repositories[0])
        #expect(model.repos.repositories[0].unfetchedCommits == 0)
        #expect(model.repos.message?.kind == .success)
    }

    @Test func toolsCheckAndGrant() async throws {
        let world = TestWorld()
        defer { world.cleanUp() }
        world.workflow.toolHandler.set { name in
            ToolStatus(name: name, hostPath: "/Users/alice/.cargo/bin/\(name)", location: .hostHome, reachableInSandbox: false, reason: "in the host home", options: [.copy])
        }
        world.workflow.grantHandler.set { name, method in ToolGrant(name: name, source: "/Users/alice/.cargo/bin/\(name)", method: method) }
        let tools = world.model().tools
        tools.query = " rg "
        await tools.check()
        #expect(tools.status?.name == "rg")
        await tools.grant(.copy)
        #expect(tools.message?.title == "Granted rg")
    }

    @Test func migrationPreviewSeparatesBlockedEntriesAndAppliesThePlan() async throws {
        let world = TestWorld()
        defer { world.cleanUp() }
        let entries = [
            MigrationEntry(item: .claudeSettings, source: "/Users/alice/.claude/settings.json", destination: ".claude/settings.json", bytes: 300),
            MigrationEntry(item: .claudeSettings, source: "/Users/alice/.claude/.credentials.json", destination: ".claude/.credentials.json", bytes: 90, blockedReason: "credential"),
        ]
        let requested = Locked<[MigrationItem]>([])
        world.workflow.planHandler.set { items in
            requested.set(items)
            return MigrationPlan(entries: entries)
        }
        world.workflow.applyHandler.set { plan in plan.copyable }
        let migration = world.model().migration
        migration.toggle(.zshrc)
        await migration.preview()
        #expect(requested.get() == MigrationItem.allCases.filter { $0 != .zshrc })
        #expect(migration.copyable.count == 1)
        #expect(migration.blocked.map(\.blockedReason) == ["credential"])

        await migration.apply()
        #expect(migration.copied == [entries[0]])
        #expect(migration.message?.title == "Copied 1 file into the shared workspace")
        #expect(migration.plan == nil)
    }

    @Test func keysAddAndRemove() async {
        let world = TestWorld()
        defer { world.cleanUp() }
        world.workflow.keysValue.set([])
        let keys = world.model().keys
        #expect(!(await keys.add(name: "", publicKey: "ssh-ed25519 AAAA")))
        #expect(await keys.add(name: "laptop", publicKey: "ssh-ed25519 AAAA laptop\n"))
        #expect(keys.keys.map(\.name) == ["laptop"])
        await keys.remove(keys.keys[0])
        #expect(keys.keys.isEmpty)
    }
}
