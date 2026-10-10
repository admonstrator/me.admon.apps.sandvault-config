import Foundation
import SandvaultCore
import SandvaultEnforce
import Testing
@testable import SandvaultAppModel

@Suite struct LearnPhrasingTests {
    static let environment = SandvaultEnvironment(hostUser: "alice", hostHome: "/Users/alice")
    static let seen = Date(timeIntervalSince1970: 1_800_000_000)

    static func suggestion(_ proposal: RuleSuggestion.Proposal, _ examples: [String], processes: [String] = ["claude"], occurrences: Int = 7) -> RuleSuggestion {
        RuleSuggestion(id: "test", proposal: proposal, occurrences: occurrences, processes: processes, examples: examples, lastSeen: seen)
    }

    static func card(_ suggestion: RuleSuggestion) -> LearnCard {
        LearnCard.make(suggestion, environment: environment)
    }

    @Test func aFolderInTheHomeFolder() {
        let rule = FileRule(path: "/Users/alice/Documents/Notes", match: .subpath, access: .write, effect: .allow)
        let card = Self.card(Self.suggestion(.file(rule), [
            "file-write-create /Users/alice/Documents/Notes/todo.md", "file-write-data /Users/alice/Documents/Notes/ideas.md",
        ]))
        #expect(card.sentence == "claude wanted to create and change files in ~/Documents/Notes")
        #expect(card.place == "~/Documents/Notes" && card.kind == .folder)
        #expect(card.reason == "7 times, most recently \(Format.time(Self.seen)). The folder is in your home folder, outside the sandbox.")
        #expect(!card.warning)
        #expect(card.choices.map(\.title) == ["Allow This Folder", "Allow Reading Only"])
        #expect(card.choices[0].proposal == .file(rule))
        guard case .file(let readOnly) = card.choices[1].proposal else { Issue.record("expected a file rule"); return }
        #expect(readOnly.access == .read && readOnly.match == .subpath && readOnly.path == rule.path && readOnly.id == rule.id)
        #expect(card.details == card.suggestion.examples)
    }

    @Test func sshKeysAreAWarningWithOneChoice() {
        let rule = FileRule(path: "/Users/alice/.ssh/id_ed25519", match: .literal, access: .read, effect: .allow)
        let card = Self.card(Self.suggestion(.file(rule), ["file-read-data /Users/alice/.ssh/id_ed25519"], occurrences: 1))
        #expect(card.sentence == "claude wanted to read your SSH keys and settings: ~/.ssh/id_ed25519")
        #expect(card.warning && card.kind == .sensitive)
        #expect(card.reason.hasPrefix("Once, most recently "))
        #expect(card.reason.hasSuffix("Anyone with these files can log in to your servers as you."))
        #expect(card.choices.map(\.title) == ["Allow Anyway"])
    }

    @Test func oneFileReadOnly() {
        let npmrc = Self.card(Self.suggestion(
            .file(FileRule(path: "/Users/alice/.npmrc", match: .literal, access: .read, effect: .allow)),
            ["file-read-data /Users/alice/.npmrc"], processes: ["node"], occurrences: 2
        ))
        #expect(npmrc.sentence == "node wanted to read your npm settings: ~/.npmrc")
        #expect(npmrc.reason.hasSuffix("May hold a login token for the registry."))
        #expect(npmrc.choices.map(\.title) == ["Allow Anyway"])

        let rule = FileRule(path: "/Users/alice/Projects/site/config.yml", match: .literal, access: .read, effect: .allow)
        let plain = Self.card(Self.suggestion(.file(rule), ["file-read-data /Users/alice/Projects/site/config.yml"], processes: ["node", "claude"]))
        #expect(plain.sentence == "node and claude wanted to read the file ~/Projects/site/config.yml")
        #expect(plain.kind == .file)
        #expect(plain.reason.hasSuffix("The file is in your home folder, outside the sandbox."))
        #expect(plain.choices.map(\.title) == ["Allow This File", "Allow This Folder"])
        guard case .file(let folder) = plain.choices[1].proposal else { Issue.record("expected a file rule"); return }
        #expect(folder.path == "/Users/alice/Projects/site" && folder.match == .subpath && folder.access == .read)

        // A file directly in the home folder never offers the whole home.
        let top = Self.card(Self.suggestion(.file(FileRule(path: "/Users/alice/notes.txt", match: .literal, access: .read, effect: .allow)), []))
        #expect(top.choices.map(\.title) == ["Allow This File"])
    }

    @Test func readAndDeleteInAFolder() {
        let rule = FileRule(path: "/private/tmp/build", match: .subpath, access: .readWrite, effect: .allow)
        let card = Self.card(Self.suggestion(.file(rule), ["file-read-data /private/tmp/build/a", "file-write-unlink /private/tmp/build/b"], processes: ["make", "cc", "ld"]))
        #expect(card.sentence == "make and 2 others wanted to read and delete files in /private/tmp/build")
        #expect(card.reason.hasSuffix("The folder is in a temporary folder."))
        #expect(card.choices.map(\.title) == ["Allow This Folder", "Allow Reading Only"])
    }

    @Test func programsAndServices() {
        let brew = Self.card(Self.suggestion(.exec(ExecRule(path: "/opt/homebrew/bin/brew", effect: .allow)), ["process-exec* /opt/homebrew/bin/brew"], processes: ["zsh"], occurrences: 2))
        #expect(brew.sentence == "zsh wanted to start the program brew")
        #expect(brew.reason == "Twice, most recently \(Format.time(Self.seen)). Installed with Homebrew, in /opt/homebrew/bin.")
        #expect(brew.choices.map(\.title) == ["Allow This Program"])

        let notification = Self.card(Self.suggestion(.mach(MachRule(name: "com.apple.usernoted.client", effect: .allow)), ["mach-lookup com.apple.usernoted.client"]))
        #expect(notification.sentence == "claude wanted to show a notification")
        #expect(notification.place == nil && !notification.warning)
        #expect(notification.reason.hasSuffix("Talks to the macOS notification service."))
        #expect(notification.choices.map(\.title) == ["Allow"])

        let keychain = Self.card(Self.suggestion(.mach(MachRule(name: "com.apple.SecurityServer", effect: .allow)), []))
        #expect(keychain.sentence == "claude wanted to use the Keychain")
        #expect(keychain.warning && keychain.choices.map(\.title) == ["Allow Anyway"])

        #expect(MachService.known("com.apple.pasteboard.1")?.action == "use the clipboard")
        #expect(MachService.known("com.apple.locationd.registration")?.action == "find out where this Mac is")
        #expect(MachService.known("com.apple.distributed_notifications@1v3")?.action == "send messages to other apps")
        #expect(MachService.known("com.apple.pasteboard") == nil)

        let unknown = Self.card(Self.suggestion(.mach(MachRule(name: "com.example.helper", effect: .allow)), []))
        #expect(unknown.sentence == "claude wanted to talk to the system service com.example.helper")
        #expect(unknown.reason.hasSuffix("A service without a known name."))
    }

    @Test func verbsFromTheDeniedOperations() {
        #expect(LearnCard.fileVerbs(.read, examples: []) == ["read"])
        #expect(LearnCard.fileVerbs(.write, examples: []) == ["change"])
        #expect(LearnCard.fileVerbs(.write, examples: ["file-write-create /a"]) == ["create"])
        #expect(LearnCard.fileVerbs(.readWrite, examples: ["file-read-data /a", "file-write-mode /a", "file-write-unlink /b"]) == ["read", "change", "delete"])
        #expect(LearnCard.actor([]) == "A program")
        #expect(LearnCard.times(1_200) == "1,200 times")
    }
}

@MainActor
@Suite struct LearnCardModelTests {
    @Test func allowAChoiceKeepBlockedAndUndo() async throws {
        let world = TestWorld()
        defer { world.cleanUp() }
        let rules = world.model().rules
        rules.startLearning()
        #expect(rules.watchingText(now: world.clock.current.get().addingTimeInterval(240)) == "Watching for 4m 00s")
        let feed = try #require(world.violations.continuation.get())
        for name in ["todo.md", "ideas.md"] {
            feed.yield(SandboxViolation(
                timestamp: world.clock.current.get(), process: "claude", pid: 4, operation: "file-write-create",
                target: "/Users/alice/Documents/Notes/\(name)", attributedToSandbox: true, raw: "deny(1) file-write-create /Users/alice/Documents/Notes/\(name)"
            ))
        }
        feed.yield(SandboxViolation(
            timestamp: world.clock.current.get(), process: "claude", pid: 4, operation: "mach-lookup", target: "com.apple.usernoted.client",
            attributedToSandbox: true, raw: "deny(1) mach-lookup com.apple.usernoted.client"
        ))
        #expect(await eventually { rules.learnCards.count == 2 })

        let folder = try #require(rules.learnCards.first { $0.kind == .folder })
        #expect(folder.sentence == "claude wanted to create files in ~/Documents/Notes")
        let readOnly = try #require(folder.choices.last)
        await rules.allow(folder, readOnly)
        let saved = try world.store.load().sandbox.fileRules
        #expect(saved.map(\.path) == ["/Users/alice/Documents/Notes"])
        #expect(saved.first?.access == .read)
        #expect(rules.decisions[folder.id] == .allowed(choice: "Allow Reading Only", ruleID: saved.first?.id))
        #expect(!rules.suggestions.contains { $0.id == folder.id })
        #expect(rules.learnCards.count == 2)

        let service = try #require(rules.learnCards.first { $0.kind == .service })
        rules.keepBlocked(service)
        #expect(rules.decisions[service.id] == .keptBlocked)
        #expect(rules.suggestions.isEmpty)
        #expect(try world.store.load().sandbox.machRules.isEmpty)

        await rules.undo(folder)
        #expect(try world.store.load().sandbox.fileRules.isEmpty)
        #expect(rules.decisions[folder.id] == nil)
        await rules.undo(service)
        #expect(rules.suggestions.count == 2)

        rules.stopLearning()
        #expect(rules.watchingText(now: world.clock.current.get()) == nil)
    }

    @Test func undoLeavesARuleThatExistedBefore() async throws {
        let world = TestWorld()
        defer { world.cleanUp() }
        let existing = MachRule(name: "com.apple.usernoted.client", effect: .allow)
        try world.store.save(AppConfig(sandbox: SandboxSettings(machRules: [existing])))
        let rules = world.model().rules
        rules.startLearning()
        try #require(world.violations.continuation.get()).yield(SandboxViolation(
            timestamp: world.clock.current.get(), process: "claude", pid: 4, operation: "mach-lookup", target: existing.name,
            attributedToSandbox: true, raw: ""
        ))
        #expect(await eventually { rules.learnCards.count == 1 })
        let card = rules.learnCards[0]
        await rules.allow(card, card.choices[0])
        #expect(rules.decisions[card.id] == .allowed(choice: "Allow", ruleID: nil))
        await rules.undo(card)
        #expect(try world.store.load().sandbox.machRules.map(\.id) == [existing.id])
    }
}
