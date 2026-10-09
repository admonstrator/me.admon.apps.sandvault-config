import Foundation
import Testing
@testable import SandvaultCore
@testable import SandvaultEnforce

@Suite struct ProfileMergeTests {
    let svProfile: String
    let body: String

    init() throws {
        svProfile = try Fixture.text("sandbox-sandvault-alice.sb")
        body = try #require(try SBPLGenerator.block(for: SBPLGeneratorTests.rules))
    }

    @Test func fixtureIsSvsProfileForAlice() {
        #expect(svProfile.hasPrefix(";; Sandbox profile for sandvault\n(version 1)\n(allow default)\n"))
        #expect(svProfile.contains("(subpath \"/Users/Shared/sv-alice\")"))
        #expect(svProfile.contains("(subpath \"/Users/sandvault-alice\")"))
        #expect(svProfile.hasSuffix("(with no-sandbox))\n"))
    }

    @Test func candidateAppendsTheBlockAndKeepsSvsText() throws {
        let candidate = ProfileMerge.candidate(profile: svProfile, body: body)
        #expect(candidate.hasPrefix(svProfile))
        #expect(candidate.hasSuffix(ManagedBlock.sandboxProfile.end + "\n"))
        #expect(ManagedBlock.sandboxProfile.extract(from: candidate) == body)
        #expect(ProfileMerge.svPart(of: candidate) == svProfile)
        #expect(ProfileMerge.svPartSHA256(of: candidate) == ProfileMerge.svPartSHA256(of: svProfile))
        // Applying twice changes nothing; resetting restores sv's bytes.
        #expect(ProfileMerge.candidate(profile: candidate, body: body) == candidate)
        #expect(ProfileMerge.candidate(profile: candidate, body: nil) == svProfile)
        try Fixture.expectGolden(LineDiff.unified(old: svProfile, new: candidate, oldName: "sandbox-sandvault-alice.sb", newName: "candidate"), "profile-apply.diff")
    }

    @Test func driftStates() {
        let applied = ProfileMerge.candidate(profile: svProfile, body: body)
        #expect(ProfileMerge.drift(profile: svProfile, body: nil) == .inSync)
        #expect(ProfileMerge.drift(profile: svProfile, body: body) == .missing)
        #expect(ProfileMerge.drift(profile: applied, body: body) == .inSync)
        #expect(ProfileMerge.drift(profile: applied, body: body + "\n(allow file-read* (subpath \"/x\"))") == .outdated)
        #expect(ProfileMerge.drift(profile: applied, body: nil) == .unexpected)
        #expect(ProfileMerge.drift(profile: nil, body: body) == .profileMissing)
    }

    @Test func svRebuildIsDetectedThroughTheStoredHash() throws {
        let root = try TempRoot()
        defer { root.cleanup() }
        let profilePath = root.path + root.alice.sandboxProfilePath
        let recordPath = root.path + "/record.json"
        var record = HelperRecord()
        record.svPartSHA256 = ProfileMerge.svPartSHA256(of: svProfile)
        try JSONCoding.encoder.encode(record).write(to: URL(fileURLWithPath: recordPath))
        let inspector = ProfileInspector(profilePath: profilePath, recordPath: recordPath)

        try root.write(ProfileMerge.candidate(profile: svProfile, body: body), to: root.alice.sandboxProfilePath)
        var plan = try inspector.plan(for: SBPLGeneratorTests.rules)
        #expect(plan.drift == .inSync)
        #expect(!plan.svPartChanged)
        #expect(!plan.hasChanges)

        // sv --rebuild of a newer sv: different text, our block gone.
        try root.write(svProfile.replacingOccurrences(of: "(allow sysctl-read)", with: "(allow sysctl-read)\n(allow iokit-open)"), to: root.alice.sandboxProfilePath)
        plan = try inspector.plan(for: SBPLGeneratorTests.rules)
        #expect(plan.drift == .missing)
        #expect(plan.svPartChanged)
        #expect(plan.hasChanges)
        #expect(plan.diff.filter { $0.kind == .added }.count == body.components(separatedBy: "\n").count + 3)
        #expect(plan.diff.allSatisfy { $0.kind != .removed })
    }

    @Test func missingProfileAndInvalidConfig() throws {
        let inspector = ProfileInspector(profilePath: "/nonexistent/sandbox.sb", recordPath: "/nonexistent/record.json")
        let plan = try inspector.plan(for: SBPLGeneratorTests.rules)
        #expect(plan.drift == .profileMissing)
        #expect(plan.current == nil && plan.diff.isEmpty && !plan.hasChanges && !plan.svPartChanged)
        let bad = SandboxSettings(fileRules: [FileRule(path: "/tmp/../etc", access: .read, effect: .allow)])
        #expect(throws: SandvaultError.self) { try inspector.plan(for: bad) }
    }

    @Test func markerTextInARuleIsRejected() {
        let path = "/tmp/" + ManagedBlock.sandboxProfile.end
        #expect(throws: SandvaultError.self) {
            try SBPLGenerator.block(for: SandboxSettings(fileRules: [FileRule(path: path, access: .read, effect: .allow)]))
        }
    }
}

@Suite struct LineDiffTests {
    @Test func equalTextsHaveNoDiff() {
        #expect(LineDiff.unified(old: "a\nb\n", new: "a\nb\n", oldName: "x", newName: "y") == "")
        #expect(LineDiff.lines(old: "a\n", new: "a\n") == [DiffLine(kind: .context, text: "a", oldLine: 1, newLine: 1)])
    }

    @Test func replacementShowsRemovalFirst() {
        let diff = LineDiff.unified(old: "a\nb\nc\n", new: "a\nB\nc\n", oldName: "old", newName: "new")
        #expect(diff == "--- old\n+++ new\n@@ -1,3 +1,3 @@\n a\n-b\n+B\n c\n")
    }

    @Test func distantChangesGetSeparateHunks() {
        var lines = (1...20).map(String.init)
        let old = lines.joined(separator: "\n") + "\n"
        lines[1] = "two"
        lines[17] = "eighteen"
        let new = lines.joined(separator: "\n") + "\n"
        let diff = LineDiff.unified(old: old, new: new, oldName: "o", newName: "n")
        #expect(diff.components(separatedBy: "\n").filter { $0.hasPrefix("@@") } == ["@@ -1,5 +1,5 @@", "@@ -15,6 +15,6 @@"])
    }

    @Test func appendToEmpty() {
        #expect(LineDiff.unified(old: "", new: "x\n", oldName: "o", newName: "n") == "--- o\n+++ n\n@@ -0,0 +1,1 @@\n+x\n")
    }
}
