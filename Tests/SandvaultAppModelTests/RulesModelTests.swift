import Foundation
import SandvaultCore
import SandvaultEnforce
import Testing
@testable import SandvaultAppModel

@MainActor
@Suite struct RulesModelTests {
    static func violation(_ operation: String, _ target: String, attributed: Bool = true, pid: Int32 = 42) -> SandboxViolation {
        SandboxViolation(
            timestamp: Date(timeIntervalSince1970: 1_800_000_000), process: "node", pid: pid, operation: operation, target: target,
            attributedToSandbox: attributed, raw: "Sandbox: node(\(pid)) deny(1) \(operation) \(target)"
        )
    }

    @Test func learnModeSuggestsAndAcceptTurnsTheProposalIntoAConfigRule() async throws {
        let world = TestWorld()
        defer { world.cleanUp() }
        let rules = world.model().rules

        rules.startLearning()
        #expect(rules.isLearning)
        let feed = try #require(world.violations.continuation.get())
        feed.yield(Self.violation("mach-lookup", "com.example.agent"))
        feed.yield(Self.violation("process-exec*", "/opt/tools/bin/fmt"))
        feed.yield(Self.violation("mach-lookup", "com.other.daemon", attributed: false, pid: 77))
        #expect(await eventually { rules.observed.count == 3 })

        // Unattributed violations only count when asked for.
        #expect(rules.suggestions.count == 2)
        rules.includeUnattributed = true
        #expect(rules.suggestions.count == 3)
        rules.includeUnattributed = false

        let mach = try #require(rules.suggestions.first { $0.id == "mach:com.example.agent" })
        await rules.accept(mach)
        let saved = try world.store.load().sandbox
        #expect(saved.machRules.map(\.name) == ["com.example.agent"])
        #expect(saved.machRules[0].effect == .allow)
        #expect(!rules.suggestions.contains { $0.id == mach.id })
        #expect(rules.rules.count == 1)
        // Sandbox rules do not concern netd.
        #expect(world.netd.reloads.get() == 0)

        let exec = try #require(rules.suggestions.first)
        rules.dismiss(exec)
        #expect(rules.suggestions.isEmpty)
        #expect(try world.store.load().sandbox.execRules.isEmpty)

        rules.stopLearning()
        #expect(!rules.isLearning)
        #expect(await eventually { world.violations.terminated.get() })
    }

    @Test func aFailingLogStreamEndsLearningWithAMessage() async throws {
        let world = TestWorld()
        defer { world.cleanUp() }
        let rules = world.model().rules
        rules.startLearning()
        let feed = try #require(world.violations.continuation.get())
        feed.finish(throwing: SandvaultError.permissionDenied("reading the unified log: Must be admin to run 'stream' command"))
        #expect(await eventually { !rules.isLearning })
        #expect(rules.learnError?.kind == .error)
    }

    @Test func learnFromRecentReadsTheLog() async {
        let world = TestWorld()
        defer { world.cleanUp() }
        world.violations.recentResult.set([Self.violation("mach-lookup", "com.example.agent")])
        let rules = world.model().rules
        await rules.learnFromRecent()
        #expect(rules.suggestions.map(\.id) == ["mach:com.example.agent"])
    }

    @Test func editsShowDriftAndApplySendsTheConfig() async throws {
        let world = TestWorld()
        defer { world.cleanUp() }
        try "(version 1)\n(allow default)\n".write(toFile: world.profilePath, atomically: true, encoding: .utf8)
        let rules = world.model().rules
        rules.refreshPlan()
        #expect(rules.plan?.drift == .inSync)

        #expect(await rules.addExecRule(path: "/usr/bin/osascript", effect: .deny, note: "no AppleScript"))
        #expect(rules.plan?.drift == .missing)
        #expect(rules.plan?.unifiedDiff.contains("+(deny process-exec (literal \"/usr/bin/osascript\"))") == true)

        #expect(!(await rules.addFileRule(path: "relative/path", match: .subpath, access: .read, effect: .allow, note: "")))
        #expect(rules.message?.kind == .warning)

        await rules.apply()
        #expect(world.policy.calls.get() == ["applyProfile"])
        #expect(world.policy.states.get().first?.sandbox.execRules.map(\.path) == ["/usr/bin/osascript"])
        #expect(rules.message == .success("done", detail: nil).withID(rules.message?.id))

        await rules.reset()
        #expect(world.policy.calls.get() == ["applyProfile", "resetProfile"])

        let id = try #require(rules.rules.first?.id)
        await rules.removeRule(id)
        #expect(rules.rules.isEmpty)
        #expect(rules.plan?.drift == .inSync)
    }

    @Test func presetAndAutoReapply() async throws {
        let world = TestWorld()
        defer { world.cleanUp() }
        let rules = world.model().rules
        await rules.setPreset(.hardened)
        await rules.setAutoReapply(true)
        let saved = try world.store.load().sandbox
        #expect(saved.preset == .hardened)
        #expect(saved.autoReapply)
        // No profile on this machine: the plan says so instead of failing.
        #expect(rules.plan?.drift == .profileMissing)
    }
}

extension UserMessage {
    /// The same message with another id, for equality checks.
    func withID(_ id: UUID?) -> UserMessage {
        var copy = self
        if let id { copy.id = id }
        return copy
    }
}
