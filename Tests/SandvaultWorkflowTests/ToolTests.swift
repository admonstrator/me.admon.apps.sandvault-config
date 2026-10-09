import Foundation
import SandvaultCore
import Testing
@testable import SandvaultWorkflow

@Suite struct ToolTests {
    let brew = "/opt/homebrew/bin/brew"
    static let machO = Data([0xCF, 0xFA, 0xED, 0xFE, 0x0C, 0x00, 0x00, 0x01])

    func hostLookup(_ name: String) -> [String] { ["/bin/zsh", "-lc", "command -v -- \(name)"] }

    func lookup(_ sandbox: Sandbox, _ name: String) -> [String] {
        ToolAccess.sandboxLookupInvocation(sandbox.environment, name: name).argv
    }

    func result(_ fixtureName: String?, exitCode: Int32 = 0) throws -> CommandResult {
        CommandResult(exitCode: exitCode, stdout: try fixtureName.map(fixture) ?? "")
    }

    func service(_ sandbox: Sandbox, _ runner: CommandRunner) -> ToolAccess {
        ToolAccess(environment: sandbox.environment, runner: runner, configStore: sandbox.configStore, shared: sandbox.shared, brewPath: brew)
    }

    @Test func sandboxLookupRunsSandboxedWithSvsEnvironment() {
        let environment = SandvaultEnvironment(hostUser: "alice", hostHome: "/Users/alice")
        #expect(ToolAccess.sandboxLookupInvocation(environment, name: "jq").argv == [
            "/usr/bin/sudo", "-n", "-u", "sandvault-alice", "/usr/bin/env", "-i",
            "HOME=/Users/sandvault-alice", "USER=sandvault-alice", "SHELL=/bin/zsh", "SHARED_WORKSPACE=/Users/Shared/sv-alice",
            "PATH=/usr/bin:/bin:/usr/sbin:/sbin", "/usr/bin/sandbox-exec", "-f", "/var/sandvault/sandbox-sandvault-alice.sb",
            "/bin/zsh", "-c", "source ~/.zshenv; source ~/.zprofile; print -r -- sandvault-config:lookup; command -v -- jq",
        ])
    }

    @Test func availableToolNeedsNothing() async throws {
        let sandbox = try Sandbox()
        defer { sandbox.cleanup() }
        let fake = FakeCommandRunner()
        fake.on(hostLookup("jq"), stdout: "/opt/homebrew/bin/jq\n")
        fake.on(lookup(sandbox, "jq"), .result(try result("sandbox-lookup-found.txt")))
        let status = try await service(sandbox, fake).status(of: "jq")
        #expect(status.reachableInSandbox)
        #expect(status.location == .homebrew)
        #expect(status.options == [.available])
        #expect(status.reason == "the sandbox finds it at /opt/homebrew/bin/jq")
        // No brew call when nothing is needed, and only offered methods are accepted.
        #expect(!fake.invocations.contains { $0.executable == brew })
        await #expect(throws: SandvaultError.self) { try await service(sandbox, fake).grant("jq", method: .brew) }
        let grant = try await service(sandbox, fake).grant("jq", method: .available)
        #expect(grant.method == .available && grant.source == "/opt/homebrew/bin/jq")
        #expect(try sandbox.configStore.load().tools.map(\.name) == ["jq"])
    }

    @Test func selfContainedBinaryInTheHomeCanBeCopied() async throws {
        let sandbox = try Sandbox()
        defer { sandbox.cleanup() }
        let path = sandbox.home + "/bin/gh"
        try FileManager.default.createDirectory(atPath: sandbox.home + "/bin", withIntermediateDirectories: true)
        try Self.machO.write(to: URL(fileURLWithPath: path))
        let fake = FakeCommandRunner()
        fake.on(hostLookup("gh"), stdout: path + "\n")
        fake.on(["/usr/bin/otool", "-L", path], .result(try result("otool-L-system-only.txt")))
        fake.on(lookup(sandbox, "gh"), .result(try result("sandbox-lookup-missing.txt", exitCode: 1)))
        fake.on([brew, "info", "--json=v2", "gh"], stdout: "", exitCode: 1, stderr: try fixture("brew-info-missing.stderr.txt"))

        let status = try await service(sandbox, fake).status(of: "gh")
        #expect(!status.reachableInSandbox)
        #expect(status.location == .hostHome)
        #expect(status.kind == "Mach-O, system libraries only")
        #expect(status.options == [.copy])
        #expect(status.reason.contains("which the sandbox cannot read"))
    }

    @Test func linkedBinaryNeedsHomebrew() async throws {
        let sandbox = try Sandbox()
        defer { sandbox.cleanup() }
        let path = sandbox.home + "/.local/bin/jq"
        try FileManager.default.createDirectory(atPath: sandbox.home + "/.local/bin", withIntermediateDirectories: true)
        try Self.machO.write(to: URL(fileURLWithPath: path))
        let fake = FakeCommandRunner()
        fake.on(hostLookup("jq"), stdout: path + "\n")
        fake.on(["/usr/bin/otool", "-L", path], .result(try result("otool-L-homebrew.txt")))
        fake.on(lookup(sandbox, "jq"), .result(try result("sandbox-lookup-missing.txt", exitCode: 1)))
        fake.on([brew, "info", "--json=v2", "jq"], .result(try result("brew-info-jq.json")))

        let status = try await service(sandbox, fake).status(of: "jq")
        #expect(status.kind == "Mach-O linked against /opt/homebrew/opt/oniguruma/lib/libonig.5.dylib")
        #expect(status.formula == "jq")
        #expect(status.options == [.brew])
    }

    @Test func scriptsDependOnTheirInterpreter() async throws {
        let sandbox = try Sandbox()
        defer { sandbox.cleanup() }
        let good = sandbox.home + "/bin/tidy"
        let bad = sandbox.home + "/bin/lint"
        try sandbox.write("#!/usr/bin/env python3\nprint('hi')\n", to: good, mode: 0o755)
        try sandbox.write("#!\(sandbox.home)/.pyenv/shims/python -u\n", to: bad, mode: 0o755)
        let fake = FakeCommandRunner()
        fake.on(hostLookup("tidy"), stdout: good + "\n")
        fake.on(hostLookup("lint"), stdout: bad + "\n")
        for name in ["tidy", "lint"] { fake.on(lookup(sandbox, name), .result(try result("sandbox-lookup-missing.txt", exitCode: 1))) }
        fake.on(lookup(sandbox, "python3"), stdout: "sandvault-config:lookup\n/usr/bin/python3\n")
        fake.on([brew, "info", "--json=v2"], stdout: "", exitCode: 1)

        let tidy = try await service(sandbox, fake).status(of: "tidy")
        #expect(tidy.kind == "script for /usr/bin/env python3")
        #expect(tidy.options == [.copy])
        let lint = try await service(sandbox, fake).status(of: "lint")
        #expect(lint.kind == "script for \(sandbox.home)/.pyenv/shims/python -u (not runnable in the sandbox)")
        #expect(lint.options.isEmpty)
    }

    @Test func failedSandboxCheckIsReportedAsUnknown() async throws {
        let sandbox = try Sandbox()
        defer { sandbox.cleanup() }
        let fake = FakeCommandRunner()
        fake.on(hostLookup("jq"), stdout: "", exitCode: 1)
        fake.on(lookup(sandbox, "jq"), stdout: "", exitCode: 1, stderr: "sudo: a password is required\n")
        fake.on([brew, "info", "--json=v2", "jq"], .result(try result("brew-info-jq.json")))
        let status = try await service(sandbox, fake).status(of: "jq")
        #expect(status.hostPath == nil && status.location == .missing)
        #expect(status.reason == "could not check inside the sandbox: sudo: a password is required")
        #expect(status.options == [.brew])
    }

    @Test func grantCopiesThroughSharedFilesAndChecksAgain() async throws {
        let sandbox = try Sandbox()
        defer { sandbox.cleanup() }
        let path = sandbox.home + "/bin/gh"
        try FileManager.default.createDirectory(atPath: sandbox.home + "/bin", withIntermediateDirectories: true)
        try (Self.machO + Data(repeating: 1, count: 4096)).write(to: URL(fileURLWithPath: path))
        let runner = MixedRunner()
        runner.fake.on(hostLookup("gh"), stdout: path + "\n")
        runner.fake.on(["/usr/bin/otool", "-L", path], .result(try result("otool-L-system-only.txt")))
        runner.fake.on([brew, "info", "--json=v2", "gh"], stdout: "", exitCode: 1)
        runner.queue(lookup(sandbox, "gh"), try result("sandbox-lookup-missing.txt", exitCode: 1),
                     CommandResult(exitCode: 0, stdout: "sandvault-config:lookup\n\(sandbox.workspace)/user/bin/gh\n"))

        let grant = try await service(sandbox, runner).grant("gh", method: .copy)
        #expect(grant.method == .copy && grant.source == path)
        let copy = sandbox.workspace + "/user/bin/gh"
        #expect(try Data(contentsOf: URL(fileURLWithPath: copy)) == Data(contentsOf: URL(fileURLWithPath: path)))
        #expect(FileKind.mode(copy) == 0o750)
        #expect(try sandbox.configStore.load().tools.map(\.name) == ["gh"])
    }

    @Test func grantInstallsWithBrew() async throws {
        let sandbox = try Sandbox()
        defer { sandbox.cleanup() }
        let runner = MixedRunner()
        runner.fake.on(hostLookup("jq"), stdout: "", exitCode: 1)
        runner.fake.on([brew, "info", "--json=v2", "jq"], .result(try result("brew-info-jq.json")))
        runner.fake.on([brew, "install", "jq"], stdout: "==> Pouring jq--1.7.1.arm64_sonoma.bottle.tar.gz\n")
        runner.queue(lookup(sandbox, "jq"), try result("sandbox-lookup-missing.txt", exitCode: 1), try result("sandbox-lookup-found.txt"))

        let grant = try await service(sandbox, runner).grant("jq", method: .brew)
        #expect(grant.method == .brew && grant.source == "jq")
        #expect(runner.invocations.contains { $0.argv == [brew, "install", "jq"] })
    }

    @Test func grantThatDoesNotHelpIsNotRecorded() async throws {
        let sandbox = try Sandbox()
        defer { sandbox.cleanup() }
        let runner = MixedRunner()
        runner.fake.on(hostLookup("jq"), stdout: "", exitCode: 1)
        runner.fake.on([brew, "info", "--json=v2", "jq"], .result(try result("brew-info-jq.json")))
        runner.fake.on([brew, "install", "jq"], stdout: "")
        runner.queue(lookup(sandbox, "jq"), try result("sandbox-lookup-missing.txt", exitCode: 1))
        await #expect(throws: SandvaultError.self) { try await service(sandbox, runner).grant("jq", method: .brew) }
        await #expect(throws: SandvaultError.self) { try await service(sandbox, runner).grant("jq", method: .copy) }
        #expect(try sandbox.configStore.load().tools.isEmpty)
    }

    @Test func rejectsBadNames() async throws {
        let sandbox = try Sandbox()
        defer { sandbox.cleanup() }
        for name in ["", ".", "..", "../x", "a b", "a;b", "$(id)", String(repeating: "a", count: 65)] {
            await #expect(throws: SandvaultError.self, "\(name)") { try await service(sandbox, FakeCommandRunner()).status(of: name) }
        }
    }

    @Test func parsers() throws {
        #expect(ToolAccess.libraries(otool: try fixture("otool-L-universal.txt")) == ["@rpath/libtool-core.dylib", "/usr/lib/libSystem.B.dylib"])
        #expect(ToolAccess.libraries(otool: try fixture("otool-L-system-only.txt")).count == 4)
        #expect(ToolAccess.formulaName(brewInfo: try fixtureData("brew-info-jq.json")) == "jq")
        #expect(ToolAccess.formulaName(brewInfo: Data("not json".utf8)) == nil)
        #expect(ToolAccess.cellarFormula("/opt/homebrew/Cellar/ripgrep/14.1.1/bin/rg") == "ripgrep")
        #expect(ToolAccess.cellarFormula("/usr/bin/git") == nil)
        #expect(ToolAccess.isMachO(Data([0xCA, 0xFE, 0xBA, 0xBE])) && ToolAccess.isMachO(Self.machO) && !ToolAccess.isMachO(Data("#!/bin/sh".utf8)))
        #expect(ToolAccess.shebang(Data("#!/usr/bin/env -S node --x\nrest".utf8)) == ["/usr/bin/env", "-S", "node", "--x"])
        #expect(ToolAccess.shebang(Data("#! /bin/sh\n".utf8)) == ["/bin/sh"])
        #expect(ToolAccess.shebang(Data("#!python\n".utf8)) == nil)
        let alice = SandvaultEnvironment(hostUser: "alice", hostHome: "/Users/alice")
        #expect(ToolAccess.location(of: "/usr/local/bin/rg", resolved: "/usr/local/Cellar/ripgrep/14/bin/rg", environment: alice) == .homebrew)
        #expect(ToolAccess.location(of: "/usr/local/bin/docker", resolved: "/Applications/Docker.app/x", environment: alice) == .system)
        #expect(ToolAccess.location(of: "/Users/alice/bin/x", resolved: "/Users/alice/bin/x", environment: alice) == .hostHome)
        #expect(ToolAccess.location(of: "/Users/Shared/sv-alice/user/bin/x", resolved: "/Users/Shared/sv-alice/user/bin/x", environment: alice) == .sharedUser)
        #expect(ToolAccess.parseLookup(CommandResult(exitCode: 0, stdout: "noise from .zprofile\nsandvault-config:lookup\n/usr/bin/git\n")) == .found("/usr/bin/git"))
        #expect(ToolAccess.parseLookup(CommandResult(exitCode: 1, stdout: "sandvault-config:lookup\n")) == .missing)
    }
}
