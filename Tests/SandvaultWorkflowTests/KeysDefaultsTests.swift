import Foundation
import SandvaultCore
import Testing
@testable import SandvaultWorkflow

@Suite struct KeyTests {
    func store(_ sandbox: Sandbox, _ runner: CommandRunner) -> AuthorizedKeyStore {
        AuthorizedKeyStore(environment: sandbox.environment, runner: runner)
    }

    func keygen() throws -> FakeCommandRunner {
        let fake = FakeCommandRunner()
        fake.on(["/usr/bin/ssh-keygen", "-l", "-f"], stdout: try fixture("ssh-keygen-l-ed25519.txt"))
        return fake
    }

    @Test func parsesKnownTypes() throws {
        for type in ["ssh-ed25519", "ssh-rsa", "ecdsa-sha2-nistp256", "sk-ssh-ed25519@openssh.com"] {
            let parsed = try AuthorizedKeyStore.parse(publicKey(type) + "\n")
            #expect(parsed.type == type && parsed.comment == "alice@laptop")
        }
        let spaced = try AuthorizedKeyStore.parse("  " + publicKey(comment: "work  laptop").replacingOccurrences(of: " ", with: "\t", options: [], range: nil) + "  ")
        #expect(spaced.comment == "work laptop")
        #expect(try AuthorizedKeyStore.parse(publicKey(comment: nil)).comment == nil)
    }

    @Test func refusesAnythingElse() {
        let key = publicKey()
        let ed25519Blob = key.split(separator: " ")[1]
        for text in [
            "-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1rZXktdjEAAAAA\n-----END OPENSSH PRIVATE KEY-----\n",
            key + "\n" + publicKey("ssh-rsa"),
            "command=\"/bin/sh\" " + key,
            "ssh-dss AAAAB3NzaC1kc3MAAACBAP alice",
            "ssh-ed25519 not-base64!! alice",
            "ssh-rsa \(ed25519Blob) mismatched",
            key + " \u{1B}[2J",
            "",
        ] {
            #expect(throws: SandvaultError.self, "\(text)") { try AuthorizedKeyStore.parse(text) }
        }
        for name in ["", ".hidden", "../x", "a/b", "a b", String(repeating: "k", count: 65)] {
            #expect(throws: SandvaultError.self, "\(name)") { try AuthorizedKeyStore.validate(name: name) }
        }
        #expect(throws: Never.self) { try AuthorizedKeyStore.validate(name: "laptop-2.work_1") }
    }

    @Test func addListRemove() async throws {
        let sandbox = try Sandbox()
        defer { sandbox.cleanup() }
        let fake = try keygen()
        let directory = sandbox.environment.authorizedKeysDir
        let added = try await store(sandbox, fake).add(name: "laptop", publicKey: publicKey(comment: "alice@laptop") + "\n")
        #expect(added == AuthorizedKey(name: "laptop", type: "ssh-ed25519", fingerprint: "SHA256:Ozf4Wvqe0W7S6JQrHmpFzwvQKx1E1lT4nbSdvQX9Xk4", comment: "alice@laptop"))
        #expect(FileKind.mode(directory + "/laptop") == 0o600)
        #expect(try sandbox.read(directory + "/laptop") == publicKey(comment: "alice@laptop") + "\n")
        await #expect(throws: SandvaultError.self) { try await store(sandbox, fake).add(name: "laptop", publicKey: publicKey()) }

        try sandbox.write("-----BEGIN OPENSSH PRIVATE KEY-----\n", to: directory + "/oops")
        try sandbox.write("garbage\n", to: directory + "/junk")
        fake.on(["/usr/bin/ssh-keygen", "-l", "-f", directory + "/junk"], stdout: "", exitCode: 255, stderr: "junk is not a public key file.\n")
        let keys = try await store(sandbox, fake).keys()
        #expect(keys.map(\.name) == ["junk", "laptop", "oops"])
        #expect(keys[0].type == "invalid (sv ignores it)")
        #expect(keys[1] == added)
        #expect(keys[2].type == "private key (sv refuses to start)")

        try await store(sandbox, fake).remove(name: "laptop")
        #expect(FileKind.of(directory + "/laptop") == .missing)
        await #expect(throws: SandvaultError.self) { try await store(sandbox, fake).remove(name: "laptop") }
    }

    @Test func keyThatSshKeygenRejectsIsNotKept() async throws {
        let sandbox = try Sandbox()
        defer { sandbox.cleanup() }
        let fake = FakeCommandRunner()
        fake.on(["/usr/bin/ssh-keygen", "-l", "-f"], stdout: "", exitCode: 255)
        await #expect(throws: SandvaultError.self) { try await store(sandbox, fake).add(name: "laptop", publicKey: publicKey()) }
        #expect(FileKind.of(sandbox.environment.authorizedKeysDir + "/laptop") == .missing)
        #expect(try await store(sandbox, fake).keys().isEmpty)
    }
}

@Suite struct DefaultsTests {
    @Test func roundTripKeepsTheRestOfTheFile() throws {
        let sandbox = try Sandbox()
        defer { sandbox.cleanup() }
        let file = sandbox.home + "/.zshenv"
        try sandbox.write("export EDITOR=vim\n", to: file, mode: 0o600)
        let defaults = SandvaultDefaults(environment: sandbox.environment)
        #expect(try defaults.read() == SandvaultDefaults.State(file: file, arguments: nil, assignedOutsideBlock: false))

        let state = try defaults.set(["--ssh", "--browser"])
        #expect(state.arguments == ["--ssh", "--browser"])
        #expect(try sandbox.read(file) == """
        export EDITOR=vim

        # >>> sandvault-config: defaults (managed, do not edit) >>>
        export SANDVAULT_ARGS='--ssh --browser'
        # <<< sandvault-config: defaults <<<

        """)
        #expect(FileKind.mode(file) == 0o600)
        #expect(try defaults.set(["-v"]).arguments == ["-v"])
        #expect(try sandbox.read(file).contains("export SANDVAULT_ARGS=-v\n"))

        #expect(try defaults.clear())
        #expect(try sandbox.read(file) == "export EDITOR=vim\n")
        #expect(try !defaults.clear())
    }

    @Test func validatesAgainstSvsOptions() throws {
        let sandbox = try Sandbox()
        defer { sandbox.cleanup() }
        let defaults = SandvaultDefaults(environment: sandbox.environment)
        for options in [["--no-sandbox"], ["-x"], ["--rebuild"], ["--fix-permissions"], ["--version"], ["--ssh", "--evil"], ["claude"], ["--ssh;rm"]] {
            #expect(throws: SandvaultError.self, "\(options)") { try defaults.set(options) }
        }
        #expect(FileKind.of(sandbox.home + "/.zshenv") == .missing)
        #expect(throws: Never.self) { try SvOptions.validate(["-s", "-vv", "--lightpanda", "-I", "-N", "--no-build"]) }
    }

    @Test func emptySetClearsAndOutsideAssignmentsAreNoticed() throws {
        let sandbox = try Sandbox()
        defer { sandbox.cleanup() }
        let file = sandbox.home + "/.zshenv"
        try sandbox.write("export SANDVAULT_ARGS=\"--ssh\"\n", to: file)
        let defaults = SandvaultDefaults(environment: sandbox.environment)
        try defaults.set(["--browser"])
        #expect(try defaults.read().assignedOutsideBlock)
        #expect(try defaults.set([]).arguments == nil)
        #expect(try sandbox.read(file) == "export SANDVAULT_ARGS=\"--ssh\"\n")
    }

    @Test func editsTheTargetOfALinkedZshenv() throws {
        let sandbox = try Sandbox()
        defer { sandbox.cleanup() }
        let target = sandbox.home + "/dotfiles/zshenv"
        try sandbox.write("export A=1\n", to: target)
        try FileManager.default.createSymbolicLink(atPath: sandbox.home + "/.zshenv", withDestinationPath: target)
        try SandvaultDefaults(environment: sandbox.environment).set(["--ssh"])
        #expect(FileKind.of(sandbox.home + "/.zshenv") == .symlink)
        #expect(try sandbox.read(target).contains("export SANDVAULT_ARGS=--ssh"))
    }

    @Test func parsesTheBlockBody() {
        #expect(SandvaultDefaults.arguments(inBody: "export SANDVAULT_ARGS='--ssh --browser'") == ["--ssh", "--browser"])
        #expect(SandvaultDefaults.arguments(inBody: "export SANDVAULT_ARGS=\"-v\"") == ["-v"])
        #expect(SandvaultDefaults.arguments(inBody: "") == [])
        #expect(SandvaultDefaults.body(for: ["--ssh"]) == "export SANDVAULT_ARGS=--ssh")
    }
}
