import Foundation
import Testing
@testable import SandvaultCore
@testable import SandvaultEnforce

@Suite struct RuleEditingTests {
    @Test func addValidatesAndMovesRepeatsToTheEnd() throws {
        var settings = SandboxSettings()
        let first = try settings.add(FileRule(path: "/opt/a", access: .read, effect: .allow))
        try settings.add(FileRule(path: "/opt/a", access: .read, effect: .deny))
        // Re-adding the allow moves it after the deny, so it wins again (last match wins) without a duplicate.
        #expect(try settings.add(FileRule(path: "/opt/a", access: .read, effect: .allow, note: "again")) == first)
        #expect(settings.fileRules.map(\.effect) == [.deny, .allow])
        #expect(throws: SandvaultError.self) { try settings.add(FileRule(path: "opt/a", access: .read, effect: .allow)) }
        #expect(throws: SandvaultError.self) { try settings.add(MachRule(name: "bad name", effect: .deny)) }
        #expect(throws: SandvaultError.self) { try settings.add(ExecRule(path: "/bin/../bin/sh")) }
        #expect(settings.fileRules.count == 2)
    }

    @Test func suggestionsBecomeRules() throws {
        var settings = SandboxSettings()
        let suggestion = RuleSuggestion(
            id: "s1", proposal: .mach(MachRule(id: fixedID(20), name: "com.apple.FontServer", effect: .allow)),
            occurrences: 3, processes: ["python3"], examples: [], lastSeen: Date()
        )
        #expect(try settings.add(suggestion.proposal) == fixedID(20))
        #expect(settings.rules.map(\.summary) == ["mach com.apple.FontServer"])
        try settings.add(.file(FileRule(id: fixedID(21), path: "/Users/alice/data", access: .readWrite, effect: .allow)))
        try settings.add(.exec(ExecRule(id: fixedID(22), path: "/usr/bin/osascript")))
        #expect(settings.rules.map(\.summary) == ["read-write subpath /Users/alice/data", "mach com.apple.FontServer", "exec /usr/bin/osascript"])
    }

    @Test func removeByUniquePrefix() throws {
        var settings = SandboxSettings(
            fileRules: [FileRule(id: fixedID(31), path: "/a", access: .read, effect: .allow)],
            machRules: [MachRule(id: UUID(uuidString: "ABCDEF00-0000-4000-8000-000000000001")!, name: "x.y", effect: .deny)]
        )
        #expect(throws: SandvaultError.invalidInput("rule id prefix needs at least 4 characters")) { try settings.removeRule(idPrefix: "abc") }
        #expect(throws: SandvaultError.invalidInput("no rule with id ffff")) { try settings.removeRule(idPrefix: "ffff") }
        try settings.add(ExecRule(id: UUID(uuidString: "ABCDEF00-0000-4000-8000-000000000002")!, path: "/bin/x"))
        #expect(throws: SandvaultError.invalidInput("2 rules match abcdef00; use more characters")) { try settings.removeRule(idPrefix: "abcdef00") }
        #expect(try settings.removeRule(idPrefix: "ABCDEF00-0000-4000-8000-000000000002").kind == "exec")
        #expect(try settings.removeRule(idPrefix: "0000").kind == "file")
        #expect(settings.rules.count == 1)
    }

    @Test func portExceptions() throws {
        var policy = NetworkPolicy()
        let id = try policy.add(PortException(proto: .tcp, destination: "140.82.112.0/20", port: 22))
        #expect(try policy.add(PortException(proto: .tcp, destination: "140.82.112.0/20", port: 22)) == id)
        #expect(throws: SandvaultError.self) { try policy.add(PortException(proto: .tcp, destination: "github.com", port: 22)) }
        #expect(throws: SandvaultError.self) { try policy.add(PortException(proto: .udp, destination: "any", port: 0)) }
        #expect(try policy.removeException(idPrefix: String(id.uuidString.prefix(6))).id == id)
        #expect(policy.portExceptions.isEmpty)
    }
}
