import Foundation
import SandvaultCore
import Testing
@testable import SandvaultObserve

/// A healthy sandvault install of `alice`; each test breaks one thing.
struct DoctorSetup {
    let runner = FakeCommandRunner()
    var files: [String: String] = [:]
    var executables: Set<String> = ["/opt/homebrew/bin/sv", "/opt/homebrew/bin/brew"]
    var permissions: [String: Int] = ["/opt/homebrew/bin": 0o755]

    static let userRecord = Invocations.dsclRead("/Users/sandvault-alice", ["UniqueID", "PrimaryGroupID", "NFSHomeDirectory", "UserShell"]).argv
    static let groupRecord = Invocations.dsclRead("/Groups/sandvault-alice", ["PrimaryGroupID"]).argv
    static let sshGroup = Invocations.dsclRead("/Groups/com.apple.access_ssh").argv
    static let staff = Invocations.checkMember("sandvault-alice", group: "staff").argv
    static let hostInGroup = Invocations.checkMember("alice", group: "sandvault-alice").argv
    static let sshMember = Invocations.checkMember("sandvault-alice", group: "com.apple.access_ssh").argv
    static let sudoTrue = ["/usr/bin/sudo", "-n", "-u", "sandvault-alice", "/usr/bin/true"]
    static let ls = ["/bin/ls", "-led", "/Users/Shared/sv-alice"]

    init() throws {
        runner.on(["/opt/homebrew/bin/sv", "--version"], stdout: try fixture("sv-version.txt"))
        runner.on(Self.userRecord, stdout: try fixture("dscl-user.txt"))
        runner.on(Self.groupRecord, stdout: try fixture("dscl-group.txt"))
        runner.on(Self.sshGroup, stdout: "", exitCode: 56, stderr: try fixture("dscl-record-missing.txt"))
        runner.on(Self.staff, stdout: try fixture("dseditgroup-not-member.txt"), exitCode: 67)
        runner.on(Self.hostInGroup, stdout: try fixture("dseditgroup-member.txt"))
        runner.on(Self.sudoTrue, stdout: "")
        runner.on(Self.ls, stdout: try fixture("ls-led-workspace.txt"))
        runner.on(["/bin/sh", "-c", "umask"], stdout: "0022\n")
        files[alice.installMarker] = ""
        files[alice.sudoersFile] = try fixture("sudoers.txt")
        files[alice.sandboxProfilePath] = try fixture("sandbox-profile.sb")
    }

    func checks() async -> [Check] {
        await ObserveChecks(
            environment: alice, runner: runner, files: .fixed(files: files, executables: executables, permissions: permissions),
            searchPaths: ["/usr/bin", "/opt/homebrew/bin"]
        ).checks()
    }

    func check(_ id: String) async -> Check? {
        await checks().first { $0.id == id }
    }
}

@Suite struct DoctorTests {
    @Test func healthyInstallPasses() async throws {
        let checks = try await DoctorSetup().checks()
        #expect(checks.map(\.id) == ObserveChecks.ids)
        let notOK = checks.filter { $0.state != .ok }.map { "\($0.id)=\($0.state)" }
        #expect(notOK == ["profile.managed-block=skipped", "ssh.remote-login=skipped"])
        #expect(checks.first { $0.id == "sv.installed" }?.detail == "sv 1.32.0 at /opt/homebrew/bin/sv")
        #expect(checks.first { $0.id == "account.user" }?.detail == "uid 601, gid 600, home /Users/sandvault-alice, shell /bin/zsh")
        #expect(CheckReport(checks: checks).worst == .skipped)
    }

    @Test func everyProblemComesWithAFix() async throws {
        var setup = try DoctorSetup()
        setup.executables = []
        setup.files = [:]
        let checks = await setup.checks()
        for check in checks where check.state >= .warning {
            #expect(check.fix != nil, "\(check.id) has no fix")
        }
    }

    @Test func svMissingOrOld() async throws {
        var setup = try DoctorSetup()
        setup.executables.remove("/opt/homebrew/bin/sv")
        #expect(await setup.check("sv.installed")?.state == .failure)
        #expect(await setup.check("sv.installed")?.fix == "brew install sandvault")

        let old = try DoctorSetup()
        old.runner.on(["/opt/homebrew/bin/sv", "--version"], stdout: "sv version 1.31.4\n")
        let check = await old.check("sv.installed")
        #expect(check?.state == .warning)
        #expect(check?.detail.contains("1.31.4") == true)

        let broken = try DoctorSetup()
        broken.runner.on(["/opt/homebrew/bin/sv", "--version"], .failure(.timedOut("/opt/homebrew/bin/sv --version")))
        #expect(await broken.check("sv.installed")?.state == .unknown)
    }

    @Test func installMarkerMissing() async throws {
        var setup = try DoctorSetup()
        setup.files[alice.installMarker] = nil
        let check = await setup.check("sv.install-marker")
        #expect(check?.state == .failure)
        #expect(check?.fix == "sv build")
    }

    @Test func accountsMissingOrInconsistent() async throws {
        let missing = try DoctorSetup()
        missing.runner.on(DoctorSetup.userRecord, stdout: "", exitCode: 56, stderr: try fixture("dscl-record-missing.txt"))
        missing.runner.on(DoctorSetup.groupRecord, stdout: "", exitCode: 56, stderr: try fixture("dscl-record-missing.txt"))
        #expect(await missing.check("account.user")?.state == .failure)
        #expect(await missing.check("account.group")?.state == .failure)

        let mismatch = try DoctorSetup()
        mismatch.runner.on(DoctorSetup.groupRecord, stdout: "PrimaryGroupID: 20\n")
        #expect(await mismatch.check("account.group")?.state == .warning)

        let shell = try DoctorSetup()
        shell.runner.on(DoctorSetup.userRecord, stdout: try fixture("dscl-user.txt").replacingOccurrences(of: "/bin/zsh", with: "/bin/bash"))
        #expect(await shell.check("account.user")?.state == .warning)

        let home = try DoctorSetup()
        home.runner.on(DoctorSetup.userRecord, stdout: try fixture("dscl-user.txt").replacingOccurrences(of: "/Users/sandvault-alice", with: "/var/empty"))
        #expect(await home.check("account.user")?.state == .failure)
    }

    @Test func staffMembershipFails() async throws {
        let setup = try DoctorSetup()
        setup.runner.on(DoctorSetup.staff, stdout: "yes sandvault-alice is a member of staff\n")
        let check = await setup.check("account.not-staff")
        #expect(check?.state == .failure)
        #expect(check?.fix == "sudo dseditgroup -o edit -d sandvault-alice -t user staff")
    }

    @Test func hostOutsideTheGroupFails() async throws {
        let setup = try DoctorSetup()
        setup.runner.on(DoctorSetup.hostInGroup, stdout: "no alice is NOT a member of sandvault-alice\n", exitCode: 67)
        #expect(await setup.check("account.host-in-group")?.state == .failure)

        let unknown = try DoctorSetup()
        unknown.runner.on(DoctorSetup.hostInGroup, stdout: "", exitCode: 64, stderr: "Group not found.\n")
        #expect(await unknown.check("account.host-in-group")?.state == .unknown)
    }

    @Test func sudoersFileProblems() async throws {
        var missing = try DoctorSetup()
        missing.files[alice.sudoersFile] = nil
        #expect(await missing.check("sudoers.file")?.state == .failure)

        var noEnv = try DoctorSetup()
        noEnv.files[alice.sudoersFile] = try fixture("sudoers.txt").replacingOccurrences(of: "NOPASSWD: /usr/bin/env", with: "NOPASSWD: /usr/bin/vim")
        #expect(await noEnv.check("sudoers.file")?.state == .failure)

        var noKill = try DoctorSetup()
        noKill.files[alice.sudoersFile] = try fixture("sudoers.txt").replacingOccurrences(of: "/usr/bin/pkill -9 -u sandvault-alice", with: "")
        #expect(await noKill.check("sudoers.file")?.state == .warning)
    }

    @Test func sudoThatAsksForAPasswordFails() async throws {
        let setup = try DoctorSetup()
        setup.runner.on(DoctorSetup.sudoTrue, stdout: "", exitCode: 1, stderr: "sudo: a password is required\n")
        let check = await setup.check("sudoers.works")
        #expect(check?.state == .failure)
        #expect(check?.detail == "sudo: a password is required")
    }

    @Test func profilePresenceAndManagedBlock() async throws {
        var missing = try DoctorSetup()
        missing.files[alice.sandboxProfilePath] = nil
        #expect(await missing.check("profile.present")?.state == .failure)
        #expect(await missing.check("profile.managed-block")?.state == .unknown)

        var managed = try DoctorSetup()
        let profile = try fixture("sandbox-profile.sb")
        managed.files[alice.sandboxProfilePath] = ManagedBlock.sandboxProfile.replace(in: profile, with: "(deny file-read* (subpath \"/x\"))")
        #expect(await managed.check("profile.managed-block")?.state == .ok)

        var damaged = try DoctorSetup()
        damaged.files[alice.sandboxProfilePath] = profile + ManagedBlock.sandboxProfile.begin + "\n(deny default)\n"
        #expect(await damaged.check("profile.managed-block")?.state == .warning)
    }

    @Test func workspacePermissionProblems() async throws {
        let noACL = try DoctorSetup()
        noACL.runner.on(DoctorSetup.ls, stdout: try fixture("ls-led-workspace-no-acl.txt"))
        #expect(await noACL.check("workspace.permissions")?.state == .warning)

        let wrongOwner = try DoctorSetup()
        wrongOwner.runner.on(DoctorSetup.ls, stdout: try fixture("ls-led-workspace.txt").replacingOccurrences(of: "alice  sandvault-alice", with: "alice  staff"))
        #expect(await wrongOwner.check("workspace.permissions")?.state == .failure)

        let open = try DoctorSetup()
        open.runner.on(DoctorSetup.ls, stdout: try fixture("ls-led-workspace.txt").replacingOccurrences(of: "drwxrwx---@", with: "drwxrwxr-x@"))
        let check = await open.check("workspace.permissions")
        #expect(check?.state == .warning)
        #expect(check?.detail.contains("775") == true)

        let missing = try DoctorSetup()
        missing.runner.on(DoctorSetup.ls, stdout: "", exitCode: 1, stderr: "ls: /Users/Shared/sv-alice: No such file or directory\n")
        #expect(await missing.check("workspace.permissions")?.state == .failure)
    }

    @Test func remoteLoginIsNeverAFailure() async throws {
        let member = try DoctorSetup()
        member.runner.on(DoctorSetup.sshGroup, stdout: "GroupMembership: alice sandvault-alice\n")
        member.runner.on(DoctorSetup.sshMember, stdout: "yes sandvault-alice is a member of com.apple.access_ssh\n")
        #expect(await member.check("ssh.remote-login")?.state == .ok)

        let outsider = try DoctorSetup()
        outsider.runner.on(DoctorSetup.sshGroup, stdout: "GroupMembership: alice\n")
        outsider.runner.on(DoctorSetup.sshMember, stdout: "no sandvault-alice is NOT a member of com.apple.access_ssh\n")
        #expect(await outsider.check("ssh.remote-login")?.state == .warning)
    }

    @Test func restrictiveUmaskWarns() async throws {
        let setup = try DoctorSetup()
        setup.runner.on(["/bin/sh", "-c", "umask"], stdout: "0077\n")
        #expect(await setup.check("umask")?.state == .warning)
    }

    @Test func homebrewPermissions() async throws {
        var closed = try DoctorSetup()
        closed.permissions["/opt/homebrew/bin"] = 0o750
        let check = await closed.check("homebrew.permissions")
        #expect(check?.state == .warning)
        #expect(check?.fix == "sudo chmod -R o+rX /opt/homebrew")

        var absent = try DoctorSetup()
        absent.executables.remove("/opt/homebrew/bin/brew")
        #expect(await absent.check("homebrew.permissions")?.state == .skipped)
    }

    @Test func missingToolsAreUnknownNotFailures() async throws {
        // What Linux looks like: no dscl, dseditgroup, sudo or ls responses at all.
        var setup = try DoctorSetup()
        setup.files = [alice.installMarker: "", alice.sudoersFile: try fixture("sudoers.txt"), alice.sandboxProfilePath: try fixture("sandbox-profile.sb")]
        let bare = ObserveChecks(
            environment: alice, runner: FakeCommandRunner(),
            files: .fixed(files: setup.files, executables: setup.executables, permissions: setup.permissions),
            searchPaths: ["/opt/homebrew/bin"]
        )
        let states = Dictionary(uniqueKeysWithValues: await bare.checks().map { ($0.id, $0.state) })
        for id in ["sv.installed", "account.user", "account.group", "account.not-staff", "account.host-in-group", "sudoers.works",
                   "workspace.permissions", "umask"] {
            #expect(states[id] == .unknown, "\(id)")
        }
        #expect(states["ssh.remote-login"] == .skipped)
    }
}

@Suite struct ObserveFactoryTests {
    @Test func factoriesReturnWorkingImplementations() async throws {
        let fake = try observeRunner()
        let attributor = Observe.makeProcessAttributor(environment: alice, runner: fake)
        #expect(await attributor.process(forLocalPort: 52100, proto: .tcp)?.name == "codex")
        #expect(Observe.makeCheckProvider(environment: alice, runner: fake) is ObserveChecks)
        #expect(Observe.makeLocalPortSource(environment: alice, runner: fake) is SandboxLocalPortSource)
    }

    @Test func statusSummaryCombinesSnapshots() async throws {
        let checks = [
            Check(id: "sv.installed", title: "sandvault installed", state: .ok, detail: "sv 1.32.0"),
            Check(id: "umask", title: "umask", state: .warning, detail: "umask 077"),
        ]
        let summary = await StatusSummary.collect(environment: alice, runner: try observeRunner(), firewallMode: .proxyOnly, checks: checks)
        #expect(summary.installation?.detail == "sv 1.32.0")
        #expect(summary.sessions.count == 2)
        #expect(summary.processCount == 7)
        #expect(summary.listeningPorts == [3000, 5173, 8080, 9229])
        #expect(summary.firewallMode == .proxyOnly)
        #expect(summary.worstCheck == .warning)
        #expect(summary.problems.map(\.id) == ["umask"])
        #expect(summary.errors.isEmpty)
    }

    @Test func statusSummaryReportsUnreadableParts() async throws {
        let fake = try observeRunner()
        fake.on(Invocations.lsof(alice).argv, stdout: "", exitCode: 1, stderr: "sudo: a password is required\n")
        let summary = await StatusSummary.collect(environment: alice, runner: fake, firewallMode: .off, checks: [])
        #expect(summary.processCount == 7)
        #expect(summary.listeningPorts.isEmpty)
        #expect(summary.errors.count == 1)
    }
}
