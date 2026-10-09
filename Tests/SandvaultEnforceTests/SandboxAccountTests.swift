import Foundation
import Testing
@testable import SandvaultCore
@testable import SandvaultEnforce

@Suite struct SandboxAccountTests {
    let alice = SandvaultEnvironment(hostUser: "alice", hostHome: "/Users/alice")
    let dscl = ["/usr/bin/dscl", ".", "-read", "/Users/sandvault-alice", "UniqueID"]
    let id = ["/usr/bin/id", "-u", "sandvault-alice"]

    @Test func parsesDsclAndIdOutput() throws {
        #expect(SandboxAccount.parseDsclUniqueID(try Fixture.text("dscl-read-uniqueid.txt")) == 601)
        #expect(SandboxAccount.parseDsclUniqueID("UniqueID:\n 601\n") == 601)
        #expect(SandboxAccount.parseDsclUniqueID("No such key: UniqueID\n") == nil)
        #expect(SandboxAccount.parseDsclUniqueID("UniqueID: -2\n") == nil)
        #expect(SandboxAccount.parseID(try Fixture.text("id-u.txt")) == 601)
        #expect(SandboxAccount.parseID("id: sandvault-alice: no such user\n") == nil)
    }

    @Test func resolvesThroughDscl() async throws {
        let fake = FakeCommandRunner()
        fake.on(dscl, stdout: try Fixture.text("dscl-read-uniqueid.txt"))
        #expect(try await SandboxAccount.resolveUID(environment: alice, runner: fake) == 601)
        #expect(fake.invocations.map(\.argv) == [dscl])
    }

    @Test func fallsBackToID() async throws {
        let fake = FakeCommandRunner()
        fake.on(dscl, stdout: "", exitCode: 56, stderr: "<dscl_cmd> DS Error: -14136 (eDSRecordNotFound)")
        fake.on(id, stdout: "601\n")
        #expect(try await SandboxAccount.resolveUID(environment: alice, runner: fake) == 601)
        #expect(fake.invocations.map(\.argv) == [dscl, id])
    }

    @Test func failsWithoutAccountAndRefusesSystemUIDs() async throws {
        let fake = FakeCommandRunner()
        fake.on(dscl, stdout: "", exitCode: 56)
        fake.on(id, stdout: "", exitCode: 1, stderr: "id: sandvault-alice: no such user")
        await #expect(throws: SandvaultError.self) { try await SandboxAccount.resolveUID(environment: alice, runner: fake) }

        let root = FakeCommandRunner()
        root.on(dscl, stdout: "UniqueID: 0\n")
        await #expect(throws: SandvaultError.invalidInput("uid 0 is not a plausible sandbox account (expected 500 or above)")) {
            try await SandboxAccount.resolveUID(environment: alice, runner: root)
        }
    }
}
