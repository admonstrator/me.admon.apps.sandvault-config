import Foundation
import SandvaultCore
import Testing
@testable import SandvaultWorkflow

@Suite struct SecretScanTests {
    static let token36 = "abcdefghijklmnopqrstuvwxyzABCDEF0123"

    @Test(arguments: [
        ("key: sk-ant-api03-\(token36)", "an Anthropic API key"),
        ("export GH=ghp_\(token36)", "a GitHub token"),
        ("github_pat_11ABCDEFG0123456789_abcdef", "a GitHub token"),
        ("gho_\(token36)", "a GitHub OAuth token"),
        ("xoxb-123456789012-1234567890123-abcdefghijkl", "a Slack token"),
        ("aws AKIAIOSFODNN7EXAMPLE", "an AWS access key"),
        ("-----BEGIN OPENSSH PRIVATE KEY-----", "a private key"),
        ("-----BEGIN RSA PRIVATE KEY-----", "a private key"),
        ("{\"env\": {\"ANTHROPIC_API_KEY\": \"key-123456789012\"}}", "a secret in a JSON value"),
        ("{\"token\" : \"0123456789abcdef\"}", "a secret in a JSON value"),
        ("{\"client_secret\": \"abcdefghijklmnop\"}", "a secret in a JSON value"),
        ("export OPENAI_API_KEY=sk-proj-abcdefghijkl", "a secret in a shell assignment"),
        ("export DB_PASSWORD='hunter2hunter2'", "a secret in a shell assignment"),
    ])
    func findsEachPattern(text: String, label: String) {
        #expect(SecretScan.contentReason("line one\n" + text) == "contains what looks like \(label) (line 2)")
    }

    @Test func letsHarmlessTextThrough() {
        for text in [
            "Never paste tokens like ghp_ or sk-ant- into chats.",
            "{\"apiKeyHelper\": \"~/bin/print-api-key\"}",
            "{\"apiKeyHelper\": \"/Users/alice/bin/print-api-key\"}",
            "{\"maxTokens\": 4096}",
            "export GITHUB_TOKEN=$(security find-generic-password -s gh -w)",
            "export PASSWORD_STORE_DIR=/Users/alice/.password-store",
            "export TOKEN_LIMIT=100000",
            "-----BEGIN PUBLIC KEY-----",
        ] {
            #expect(SecretScan.contentReason(text) == nil, "\(text)")
        }
        #expect(SecretScan.contentReason("//registry.npmjs.org/:_authToken=${NPM_TOKEN}", fileName: ".npmrc") == "npm auth token (_authToken)")
    }

    @Test func credentialFileNames() {
        for name in [".credentials.json", "server.pem", "tls.key", "cert.p12", "id_ed25519", "id_rsa", ".netrc", ".env", ".env.local"] {
            #expect(SecretScan.fileNameReason(name) != nil, "\(name)")
        }
        for name in ["id_ed25519.pub", "settings.json", "CLAUDE.md", ".env.example", "key.md"] {
            #expect(SecretScan.fileNameReason(name) == nil, "\(name)")
        }
    }
}

@Suite struct MigrationTests {
    func migration(_ sandbox: Sandbox, _ runner: CommandRunner = FakeCommandRunner()) -> ConfigMigration {
        ConfigMigration(environment: sandbox.environment, runner: runner, shared: sandbox.shared)
    }

    func populate(_ sandbox: Sandbox) throws {
        let claude = sandbox.home + "/.claude"
        try sandbox.write("{\"model\": \"opus\", \"apiKeyHelper\": \"~/bin/key\"}\n", to: claude + "/settings.json")
        try sandbox.write("# Memory\nBe brief.\n", to: claude + "/CLAUDE.md")
        try sandbox.write("Review the diff.\n", to: claude + "/commands/review.md")
        try sandbox.write("Deploy with ghp_\(SecretScanTests.token36)\n", to: claude + "/commands/deploy.md")
        try sandbox.write("---\nname: s\n---\n", to: claude + "/skills/s/SKILL.md")
        try sandbox.write("#!/bin/sh\necho hi\n", to: claude + "/skills/s/run.sh", mode: 0o755)
        try sandbox.write("cert", to: claude + "/skills/s/server.pem")
        try sandbox.write(String(repeating: "x", count: (1 << 20) + 1), to: claude + "/skills/s/big.txt")
        try FileManager.default.createSymbolicLink(atPath: claude + "/skills/s/ssh", withDestinationPath: sandbox.home + "/.ssh")
        try sandbox.write("export OPENAI_API_KEY=sk-proj-abcdefghijklmnop\n", to: sandbox.home + "/.zshrc")
        try sandbox.write("eval \"$(/opt/homebrew/bin/brew shellenv)\"\n", to: sandbox.home + "/.zprofile")
        let defaults = SandvaultDefaults.block.replace(in: "export EDITOR=vim\n", with: "export SANDVAULT_ARGS=--ssh")
        try sandbox.write(defaults, to: sandbox.home + "/.zshenv")
    }

    func gitRunner() -> FakeCommandRunner {
        let fake = FakeCommandRunner()
        fake.on([GitSafe.gitPath, "config", "--global", "--get", "user.name"], stdout: "Alice \"Al\" Example\n")
        fake.on([GitSafe.gitPath, "config", "--global", "--get", "user.email"], stdout: "alice@example.com\n")
        return fake
    }

    @Test func planBlocksCredentialsAndExplainsWhy() async throws {
        let sandbox = try Sandbox()
        defer { sandbox.cleanup() }
        try populate(sandbox)
        let plan = try await migration(sandbox).plan(MigrationItem.allCases)
        let byDestination = Dictionary(uniqueKeysWithValues: plan.entries.map { ($0.destination, $0) })

        #expect(byDestination[".claude/settings.json"]?.blockedReason == nil)
        #expect(byDestination[".claude/CLAUDE.md"]?.blockedReason == nil)
        #expect(byDestination[".claude/commands/review.md"]?.blockedReason == nil)
        #expect(byDestination[".claude/commands/deploy.md"]?.blockedReason == "contains what looks like a GitHub token (line 1)")
        #expect(byDestination[".claude/agents"]?.blockedReason == "not found on the host")
        #expect(byDestination[".claude/skills/s/SKILL.md"]?.blockedReason == nil)
        #expect(byDestination[".claude/skills/s/server.pem"]?.blockedReason == "certificate or key file")
        #expect(byDestination[".claude/skills/s/big.txt"]?.blockedReason == "larger than 1 MB")
        #expect(byDestination[".claude/skills/s/ssh"]?.blockedReason?.hasPrefix("symlink to") == true)
        #expect(byDestination[".zshrc"]?.blockedReason == "contains what looks like a secret in a shell assignment (line 1)")
        #expect(byDestination[".zprofile"]?.blockedReason == nil)
        #expect(byDestination[".gitconfig"]?.blockedReason?.hasPrefix("no git identity") == true)
        #expect(plan.entries.allSatisfy { !$0.overwrites })
    }

    @Test func applyWritesThroughSharedFilesAndKeepsTheNetworkBlock() async throws {
        let sandbox = try Sandbox()
        defer { sandbox.cleanup() }
        try populate(sandbox)
        let user = sandbox.workspace + "/user"
        let network = "export http_proxy='http://127.0.0.1:18080'"
        try sandbox.write(ManagedBlock.zshenv.replace(in: "# old sandbox content\n", with: network), to: user + "/.zshenv")
        let service = migration(sandbox, gitRunner())

        let plan = try await service.plan(MigrationItem.allCases)
        #expect(plan.entries.first { $0.item == .zshenv }?.overwrites == true)
        let written = try await service.apply(plan)
        #expect(Set(written.map(\.destination)) == [
            ".claude/settings.json", ".claude/CLAUDE.md", ".claude/commands/review.md", ".claude/skills/s/SKILL.md",
            ".claude/skills/s/run.sh", ".zprofile", ".zshenv", ".gitconfig",
        ])
        #expect(try sandbox.read(user + "/.claude/commands/review.md") == "Review the diff.\n")
        #expect(FileKind.mode(user + "/.claude/skills/s/run.sh") == 0o750)
        #expect(FileKind.mode(user + "/.claude/CLAUDE.md") == 0o640)
        #expect(FileKind.of(user + "/.claude/commands/deploy.md") == .missing)
        #expect(FileKind.of(user + "/.zshrc") == .missing)

        let zshenv = try sandbox.read(user + "/.zshenv")
        #expect(zshenv.hasPrefix("export EDITOR=vim\n"))
        #expect(ManagedBlock.zshenv.extract(from: zshenv) == network)
        #expect(!zshenv.contains("SANDVAULT_ARGS") && !zshenv.contains("old sandbox content"))
        #expect(try sandbox.read(user + "/.gitconfig") == """
        # Written by Sandvault Config from the host's git identity.
        [user]
        \tname = "Alice \\"Al\\" Example"
        \temail = "alice@example.com"

        """)
    }

    @Test func applyChecksEveryFileAgain() async throws {
        let sandbox = try Sandbox()
        defer { sandbox.cleanup() }
        try populate(sandbox)
        let service = migration(sandbox)
        let plan = try await service.plan([.claudeCommands, .claudeMemory])
        try sandbox.write("Now with sk-ant-api03-\(SecretScanTests.token36)\n", to: sandbox.home + "/.claude/commands/review.md")
        // Only entries the plan approved are written, even if more became copyable.
        let subset = MigrationPlan(entries: plan.entries.filter { $0.item == .claudeCommands })
        let written = try await service.apply(subset)
        #expect(written.isEmpty)
        #expect(FileKind.of(sandbox.workspace + "/user/.claude/CLAUDE.md") == .missing)
    }

    @Test func refusesAPlantedSymlink() async throws {
        let sandbox = try Sandbox()
        defer { sandbox.cleanup() }
        try populate(sandbox)
        let hostDirectory = sandbox.home + "/elsewhere"
        try FileManager.default.createDirectory(atPath: hostDirectory, withIntermediateDirectories: true)
        try FileManager.default.createSymbolicLink(atPath: sandbox.workspace + "/user", withDestinationPath: hostDirectory)
        let service = migration(sandbox)
        let plan = try await service.plan([.zprofile, .zshenv])
        #expect(plan.entries.first { $0.item == .zshenv }?.blockedReason?.hasPrefix("cannot read the shared .zshenv safely") == true)
        await #expect(throws: SandvaultError.self) { try await service.apply(plan) }
        #expect(try FileManager.default.contentsOfDirectory(atPath: hostDirectory).isEmpty)
    }

    @Test func gitconfigQuoting() {
        #expect(ConfigMigration.gitconfig([("name", "a\\b")]) == "# Written by Sandvault Config from the host's git identity.\n[user]\n\tname = \"a\\\\b\"\n")
        #expect(ConfigMigration.gitconfig([("name", "evil\n[core]\n\tfsmonitor = x")]) == nil)
    }
}
