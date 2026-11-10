import Foundation
import SandvaultCore
import Testing
@testable import SandvaultWorkflow

@Suite struct ProgramTests {
    func hostLookup(_ name: String) -> [String] { ["/bin/zsh", "-lc", "command -v -- \(name)"] }

    /// `name` resolves on the host and in the sandbox, so it needs no grant.
    func available(_ fake: FakeCommandRunner, _ sandbox: Sandbox, _ name: String) {
        fake.on(hostLookup(name), stdout: "/opt/homebrew/bin/\(name)\n")
        fake.on(ToolAccess.sandboxLookupInvocation(sandbox.environment, name: name).argv,
                stdout: "sandvault-config:lookup\n/opt/homebrew/bin/\(name)\n")
    }

    @Test func scanFindsLookedUpCommandsAndLoopbackPorts() {
        let script = """
        #!/usr/bin/env zsh
        LMS_HOST="${LMS_HOST:-http://localhost:1234}"
        command -v jq  >/dev/null || die "jq fehlt"
        command -v fzf >/dev/null || die "fzf fehlt"
        command -v jq >/dev/null
        LMS_BIN="$(command -v lms 2>/dev/null)"
        curl http://127.0.0.1:8080/x http://example.com:9999/
        """
        let found = ProgramMigration.scan(script)
        #expect(found.commands == ["jq", "fzf", "lms"])
        #expect(found.ports == [1234, 8080])
    }

    @Test func filePathsStayBelowTheHome() throws {
        try ProgramMigration.validate(file: ".lmstudio/.internal/http-server.json")
        for bad in ["", "/etc/passwd", "../x", "a/../b", "a//b", "./a", "a\nb"] {
            #expect(throws: SandvaultError.self, "\(bad)") { try ProgramMigration.validate(file: bad) }
        }
    }

    @Test func migrateCopiesFilesOpensPortsAndRemoveUndoesIt() async throws {
        let sandbox = try Sandbox()
        defer { sandbox.cleanup() }
        let fake = FakeCommandRunner()
        available(fake, sandbox, "claude-lm")
        available(fake, sandbox, "jq")
        try sandbox.write("{\"port\": 41343}\n", to: sandbox.home + "/.lmstudio/.internal/http-server.json")
        try sandbox.write("opaque\n", to: sandbox.home + "/.lmstudio/.internal/lms-key-2")
        let service = ProgramMigration(environment: sandbox.environment, runner: fake, configStore: sandbox.configStore, shared: sandbox.shared)
        var program = CustomProgram(
            name: "claude-lm", dependencies: ["jq"], hostPorts: [1234, 41343],
            files: [".lmstudio/.internal/http-server.json", ".lmstudio/.internal/lms-key-2"], takesPrompt: true
        )
        let user = sandbox.layout.absolute(sandbox.layout.userRelative)

        // Without the allow the key stays out; everything else goes through.
        let first = try await service.migrate(program)
        #expect(first.steps.filter { !$0.done }.map(\.subject) == [".lmstudio/.internal/lms-key-2"])
        #expect(first.firewallChanged)
        #expect(first.program.migratedAt == nil)
        #expect(FileManager.default.fileExists(atPath: user + "/.lmstudio/.internal/http-server.json"))
        #expect(!FileManager.default.fileExists(atPath: user + "/.lmstudio/.internal/lms-key-2"))
        var config = try sandbox.configStore.load()
        #expect(config.network.portExceptions.map(\.port) == [1234, 41343])
        #expect(config.network.portExceptions.allSatisfy { $0.destination == "127.0.0.1" && $0.note == "program claude-lm" })

        program.allowedSecrets = [".lmstudio/.internal/lms-key-2"]
        let second = try await service.migrate(program)
        #expect(second.succeeded && !second.firewallChanged && second.program.migratedAt != nil)
        #expect(try sandbox.read(user + "/.lmstudio/.internal/lms-key-2") == "opaque\n")
        #expect(try sandbox.configStore.load().programs.map(\.name) == ["claude-lm"])
        // The saved entry comes back for editing (config.json keeps whole seconds).
        var saved = try await service.suggest("claude-lm")
        #expect(saved.migratedAt != nil)
        saved.migratedAt = nil
        #expect(saved == program)

        // An exception the user made stays when the program goes.
        config = try sandbox.configStore.load()
        config.network.portExceptions.append(PortException(proto: .tcp, destination: "10.0.0.2", port: 22))
        try sandbox.configStore.save(config)
        try await service.remove("claude-lm")
        config = try sandbox.configStore.load()
        #expect(config.programs.isEmpty)
        #expect(config.network.portExceptions.map(\.destination) == ["10.0.0.2"])
        #expect(!FileManager.default.fileExists(atPath: user + "/.lmstudio/.internal/lms-key-2"))
    }

    @Test func allowedSecretsMustBeAmongTheFiles() async throws {
        let sandbox = try Sandbox()
        defer { sandbox.cleanup() }
        let service = ProgramMigration(environment: sandbox.environment, runner: FakeCommandRunner(), configStore: sandbox.configStore, shared: sandbox.shared)
        await #expect(throws: SandvaultError.self) {
            try await service.migrate(CustomProgram(name: "x", allowedSecrets: [".ssh/id_ed25519"]))
        }
    }

    @Test func programsStartThroughSvShell() throws {
        let request = HandoffRequest(source: "/r", agent: .claude, svOptions: ["--browser"], program: "claude-lm")
        #expect(HandoffCommandLine.arguments(source: "/r", request: request, prompt: "go")
            == ["sv-clone", "/r", "--", "--browser", "shell", "--", "claude-lm", "go"])
        #expect(HandoffCommandLine.arguments(source: "/r", request: request, prompt: nil)
            == ["sv-clone", "/r", "--", "--browser", "shell", "--", "claude-lm"])
        #expect(try SandboxLifecycle.commandLine(.program("claude-lm", directory: "/Users/Shared/sv-alice"), svOptions: [])
            == "sv shell /Users/Shared/sv-alice -- claude-lm")
        #expect(throws: SandvaultError.self) { try SandboxLifecycle.commandLine(.program("x; rm", directory: nil), svOptions: []) }
    }

    @Test func oldConfigsHaveNoPrograms() throws {
        let config = try JSONCoding.decoder.decode(AppConfig.self, from: Data("{}".utf8))
        #expect(config.programs.isEmpty)
        let program = try JSONCoding.decoder.decode(CustomProgram.self, from: Data(#"{"name":"claude-lm"}"#.utf8))
        #expect(program == CustomProgram(name: "claude-lm"))
    }
}
