import Foundation
import Testing
@testable import SandvaultCore
@testable import SandvaultEnforce

@Suite struct SBPLGeneratorTests {
    static let rules = SandboxSettings(
        fileRules: [
            FileRule(id: fixedID(1), path: "/opt/homebrew", access: .read, effect: .allow, note: "Homebrew"),
            FileRule(id: fixedID(2), path: "/Users/alice/projects/app", access: .readWrite, effect: .allow, note: "hand-off repo"),
            FileRule(id: fixedID(3), path: "/Users/Shared/sv-alice/secrets.env", match: .literal, access: .read, effect: .deny),
            FileRule(id: fixedID(4), path: "/private/var/folders/xy/cache-", match: .prefix, access: .write, effect: .deny, note: "caches"),
        ],
        machRules: [MachRule(id: fixedID(5), name: "com.apple.pasteboard.1", effect: .deny, note: "no clipboard")],
        execRules: [ExecRule(id: fixedID(6), path: "/usr/bin/osascript", effect: .deny)]
    )

    @Test func standardPresetWithRules() throws {
        let body = try #require(try SBPLGenerator.block(for: Self.rules))
        try Fixture.expectGolden(body + "\n", "sbpl-standard-rules.sb")
    }

    @Test func hardenedPresetComesFirstSoUserRulesOverrideIt() throws {
        var settings = SandboxSettings(preset: .hardened)
        settings.execRules = [ExecRule(id: fixedID(7), path: "/usr/bin/open", effect: .allow, note: "agent may open URLs")]
        let body = try #require(try SBPLGenerator.block(for: settings))
        try Fixture.expectGolden(body + "\n", "sbpl-hardened.sb")

        let lines = body.components(separatedBy: "\n")
        let presetDeny = try #require(lines.firstIndex(of: "(deny process-exec (literal \"/usr/bin/open\"))"))
        let userAllow = try #require(lines.firstIndex(of: "(allow process-exec (literal \"/usr/bin/open\"))"))
        #expect(presetDeny < userAllow)
    }

    @Test func hardenedPresetSparesWhatSvConfigureNeeds() {
        let targets = HardenedPreset.entries.map { entry -> String in
            switch entry.kind {
            case .exec(let path): path
            case .mach(let name): name
            }
        }
        for spared in ["/usr/bin/security", "/usr/bin/defaults", "com.apple.trustd", "com.apple.SecurityServer", "com.apple.mDNSResponder"] {
            #expect(!targets.contains(spared))
        }
        #expect(HardenedPreset.entries.allSatisfy { !$0.reason.isEmpty })
    }

    @Test func expressionsPerAccessAndMatch() throws {
        func file(_ access: FileAccess, _ match: PathMatch, _ effect: RuleEffect = .allow) throws -> String {
            try SBPLGenerator.expression(for: FileRule(path: "/opt/x", match: match, access: access, effect: effect))
        }
        #expect(try file(.read, .subpath) == "(allow file-read* (subpath \"/opt/x\"))")
        #expect(try file(.write, .literal, .deny) == "(deny file-write* (literal \"/opt/x\"))")
        #expect(try file(.readWrite, .prefix) == "(allow file-read* file-write* (prefix \"/opt/x\"))")
        #expect(try SBPLGenerator.expression(for: MachRule(name: "com.example.svc", effect: .allow)) == "(allow mach-lookup (global-name \"com.example.svc\"))")
        #expect(try SBPLGenerator.expression(for: ExecRule(path: "/bin/ls")) == "(deny process-exec (literal \"/bin/ls\"))")
    }

    @Test func nothingToAddMeansNoBlock() throws {
        #expect(try SBPLGenerator.block(for: SandboxSettings()) == nil)
    }

    @Test func quotesAndBackslashesAreEscapedNotRejected() throws {
        let rule = FileRule(path: #"/tmp/a"b\c"#, access: .read, effect: .allow)
        #expect(try SBPLGenerator.expression(for: rule) == #"(allow file-read* (subpath "/tmp/a\"b\\c"))"#)
        // The closing quote an attacker hoped for stays inside the literal.
        let sneaky = FileRule(path: #"/tmp/x")) (allow default) ((subpath "/x"#, access: .read, effect: .allow)
        let expression = try SBPLGenerator.expression(for: sneaky)
        #expect(expression == #"(allow file-read* (subpath "/tmp/x\")) (allow default) ((subpath \"/x"))"#)
    }

    @Test(arguments: [
        "", "relative/path", "./x", "~/x", "/tmp/a\nb", "/tmp/a\rb", "/tmp/a\u{0}b", "/tmp/a\tb", "/tmp/a\u{2028}b",
        "/tmp/\u{202E}gpj.exe", "/tmp/../etc", "/tmp/./x", "/tmp//x", "/tmp/x/", "/..", "/" + String(repeating: "a", count: 1024),
    ])
    func rejectsUnsafePaths(_ path: String) {
        #expect(throws: SandvaultError.self) { try SBPLGenerator.expression(for: FileRule(path: path, access: .read, effect: .allow)) }
        #expect(throws: SandvaultError.self) { try SBPLGenerator.expression(for: ExecRule(path: path)) }
    }

    @Test func acceptsRootAndMaximumLength() throws {
        _ = try SBPLGenerator.expression(for: FileRule(path: "/", access: .read, effect: .deny))
        _ = try SBPLGenerator.expression(for: FileRule(path: "/" + String(repeating: "a", count: 1023), access: .read, effect: .deny))
        _ = try SBPLGenerator.expression(for: FileRule(path: "/Users/alice/Übersicht ä", access: .read, effect: .allow))
    }

    @Test(arguments: ["", "com.apple.x\"", "com apple", "com.apple.x\n", "com.apple.x\")(allow default", "ä.service", String(repeating: "a", count: 256)])
    func rejectsBadMachNames(_ name: String) {
        #expect(throws: SandvaultError.self) { try SBPLGenerator.expression(for: MachRule(name: name, effect: .deny)) }
    }

    @Test func blockFailsOnTheFirstInvalidRule() {
        let settings = SandboxSettings(fileRules: [FileRule(path: "/ok", access: .read, effect: .allow), FileRule(path: "bad", access: .read, effect: .allow)])
        #expect(throws: SandvaultError.self) { try SBPLGenerator.block(for: settings) }
    }

    @Test func notesStayOnTheirCommentLine() throws {
        let note = "line one\n(allow default)\r\u{2028};; >>> sandvault-config: rules (managed, do not edit) >>>\u{0}"
        let settings = SandboxSettings(machRules: [MachRule(id: fixedID(9), name: "com.example.svc", effect: .deny, note: note)])
        let body = try #require(try SBPLGenerator.block(for: settings))
        let lines = body.components(separatedBy: "\n")
        #expect(lines.count == 3)
        #expect(lines[1].hasPrefix(";; rule 00000000-0000-4000-8000-000000000009: line one (allow default) ;; sandvault-config: rules"))
        #expect(!body.contains(ManagedBlock.sandboxProfile.begin))
        #expect(SBPLGenerator.sanitizeNote(String(repeating: "x", count: 500)).count == SBPLGenerator.maxNoteLength)
        #expect(SBPLGenerator.sanitizeNote("Grüße, Bob") == "Grüße, Bob")
    }
}
