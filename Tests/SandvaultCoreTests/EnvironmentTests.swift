import Testing
@testable import SandvaultCore

@Suite struct EnvironmentTests {
    @Test func hostUserFromUSER() {
        let env = SandvaultEnvironment.current(environment: ["USER": "alice", "HOME": "/Users/alice"])
        #expect(env.hostUser == "alice")
        #expect(env.hostHome == "/Users/alice")
        #expect(env.sandvaultUser == "sandvault-alice")
        #expect(env.sandvaultGroup == "sandvault-alice")
    }

    @Test func hostUserInsideSandbox() {
        let env = SandvaultEnvironment.current(environment: ["USER": "sandvault-alice", "HOME": "/Users/sandvault-alice"])
        #expect(env.hostUser == "alice")
        #expect(env.hostHome == "/Users/alice")
    }

    @Test func hostUserUnderSudo() {
        let env = SandvaultEnvironment.current(environment: ["USER": "root", "SUDO_USER": "alice", "HOME": "/var/root"])
        #expect(env.hostUser == "alice")
        #expect(env.hostHome == "/Users/alice")
    }

    @Test func pathsMatchUpstreamSv() {
        let env = SandvaultEnvironment(hostUser: "alice", hostHome: "/Users/alice")
        #expect(env.sharedWorkspace == "/Users/Shared/sv-alice")
        #expect(env.svPrivateDir == "/Users/Shared/sv-alice/_sandvault")
        #expect(env.sharedReposDir == "/Users/Shared/sv-alice/repos")
        #expect(env.sandboxProfilePath == "/var/sandvault/sandbox-sandvault-alice.sb")
        #expect(env.buildHomeScriptPath == "/var/sandvault/buildhome-sandvault-alice")
        #expect(env.sudoersFile == "/etc/sudoers.d/50-nopasswd-for-sandvault-alice")
        #expect(env.installMarker == "/Users/alice/.config/codeofhonor/sandvault/install")
        #expect(env.authorizedKeysDir == "/Users/alice/.config/codeofhonor/sandvault/authorized_keys.d")
        #expect(env.sessionStateDir == "/Users/alice/.local/state/sandvault")
        #expect(env.sshKeyPrivate == "/Users/alice/.ssh/id_ed25519_sandvault")
    }

    @Test func appPaths() {
        let paths = AppPaths(environment: SandvaultEnvironment(hostUser: "alice", hostHome: "/Users/alice"))
        #expect(paths.configFile == "/Users/alice/Library/Application Support/me.admon.apps.sandvault-config/config.json")
        #expect(paths.effectiveControlSocket == paths.controlSocket)
        #expect(paths.helperSudoersFile == "/etc/sudoers.d/60-sandvault-config-alice")
        #expect(paths.sharedZshenv == "/Users/Shared/sv-alice/user/.zshenv")
        #expect(AppPaths.pfAnchor == "com.apple/sandvault-config")

        let long = AppPaths(environment: SandvaultEnvironment(hostUser: String(repeating: "x", count: 40), hostHome: "/Users/" + String(repeating: "x", count: 40)))
        #expect(long.effectiveControlSocket == long.controlSocketFallback)
    }
}
