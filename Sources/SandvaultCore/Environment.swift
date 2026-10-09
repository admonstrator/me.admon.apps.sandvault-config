import Foundation

/// Reverse-DNS identity shared by the app bundle, the helper, the LaunchAgent/Daemon labels and the pf anchor.
public enum BundleIdentity {
    public static let bundleID = "me.admon.apps.sandvault-config"
    public static let displayName = "Sandvault Config"
    public static let version = "0.0.0"
}

/// The sandvault layout as created by upstream `sv` (webcoyote/sandvault v1.32.0, `sv` lines 129-209).
/// Every path that `sv` owns is derived here and nowhere else.
public struct SandvaultEnvironment: Sendable, Equatable, Codable {
    /// The account that owns the sandbox (`$USER` on the host, or the suffix of `sandvault-<name>` inside it).
    public var hostUser: String
    /// Home directory of the host user (`/Users/<hostUser>` on macOS).
    public var hostHome: String

    public init(hostUser: String, hostHome: String) {
        self.hostUser = hostUser
        self.hostHome = hostHome
    }

    /// Derives the environment the same way `sv` does: inside the sandbox `USER` is `sandvault-<name>`.
    public static func current(environment: [String: String] = ProcessInfo.processInfo.environment) -> SandvaultEnvironment {
        let user = environment["SUDO_USER"].flatMap { $0.isEmpty ? nil : $0 } ?? environment["USER"] ?? NSUserName()
        let host = user.hasPrefix(sandvaultPrefix) ? String(user.dropFirst(sandvaultPrefix.count)) : user
        let home: String
        if environment["SUDO_USER"] != nil || user != host {
            home = "/Users/\(host)"
        } else {
            home = environment["HOME"] ?? "/Users/\(host)"
        }
        return SandvaultEnvironment(hostUser: host, hostHome: home)
    }

    public static let sandvaultPrefix = "sandvault-"

    // MARK: Accounts

    public var sandvaultUser: String { "sandvault-\(hostUser)" }
    public var sandvaultGroup: String { "sandvault-\(hostUser)" }
    public var sandvaultHome: String { "/Users/\(sandvaultUser)" }

    // MARK: Shared workspace

    public var sharedWorkspace: String { "/Users/Shared/sv-\(hostUser)" }
    /// Sandvault-private subdirectory of the shared workspace (setup scripts, deploy keys).
    public var svPrivateDir: String { "\(sharedWorkspace)/_sandvault" }
    /// User configuration copied into the sandbox home on every session (`guest/home/configure`).
    public var sharedUserDir: String { "\(sharedWorkspace)/user" }
    /// Where `sv-clone` puts repositories.
    public var sharedReposDir: String { "\(sharedWorkspace)/repos" }
    /// Files Sandvault Config publishes for the sandbox (public CA bundle, hand-off briefings). Sandbox-writable.
    public var sharedConfigDir: String { "\(sharedWorkspace)/_sandvault-config" }

    // MARK: Root-owned files written by sv

    public var sandboxProfilePath: String { "/var/sandvault/sandbox-\(sandvaultUser).sb" }
    public var buildHomeScriptPath: String { "/var/sandvault/buildhome-\(sandvaultUser)" }
    public var sudoersFile: String { "/etc/sudoers.d/50-nopasswd-for-\(sandvaultUser)" }

    // MARK: Host-only files written by sv

    public var installMarker: String { "\(hostHome)/.config/codeofhonor/sandvault/install" }
    public var authorizedKeysDir: String { "\(hostHome)/.config/codeofhonor/sandvault/authorized_keys.d" }
    /// Per-session state (browser profiles and logs).
    public var sessionStateDir: String { "\(hostHome)/.local/state/sandvault" }
    public var sshKeyPrivate: String { "\(hostHome)/.ssh/id_ed25519_sandvault" }
    public var sshKeyPublic: String { "\(sshKeyPrivate).pub" }

    /// `sv` connects over SSH to the IPv4 loopback literal (issue #188 upstream).
    public static let sshHost = "127.0.0.1"
}

/// Paths owned by Sandvault Config itself.
public struct AppPaths: Sendable, Equatable, Codable {
    public var environment: SandvaultEnvironment

    public init(environment: SandvaultEnvironment) {
        self.environment = environment
    }

    // MARK: Host-only (unreadable for the sandbox: the sv profile denies reads under /Users/<host>)

    public var appSupportDir: String { "\(environment.hostHome)/Library/Application Support/\(BundleIdentity.bundleID)" }
    public var configFile: String { "\(appSupportDir)/config.json" }
    /// Unix domain socket of sandvault-netd. macOS limits socket paths to 104 bytes; see `controlSocketFallback`.
    public var controlSocket: String { "\(appSupportDir)/control.sock" }
    public var controlSocketFallback: String { "\(environment.hostHome)/.local/state/sandvault-config/control.sock" }
    public var logDir: String { "\(appSupportDir)/logs" }
    public var connectionLog: String { "\(logDir)/connections.jsonl" }
    /// CA key and certificate for TLS inspection (key file mode 0600).
    public var caDir: String { "\(appSupportDir)/ca" }
    public var profileBackupDir: String { "\(appSupportDir)/backups" }

    /// The control socket path that fits the platform limit.
    public var effectiveControlSocket: String {
        controlSocket.utf8.count < 104 ? controlSocket : controlSocketFallback
    }

    // MARK: Root-owned (installed once with administrator rights)

    public static let helperPath = "/Library/PrivilegedHelperTools/\(BundleIdentity.bundleID).helper"
    public var helperSudoersFile: String { "/etc/sudoers.d/60-sandvault-config-\(environment.hostUser)" }
    public static let rootStateDir = "/Library/Application Support/\(BundleIdentity.bundleID)"
    public static let launchDaemonPlist = "/Library/LaunchDaemons/\(BundleIdentity.bundleID).pf.plist"
    /// Sub-anchor of `com.apple/*`, which the stock /etc/pf.conf evaluates; pf.conf itself is never edited.
    public static let pfAnchor = "com.apple/sandvault-config"

    // MARK: Sandbox-visible, sandbox-writable (treat contents as untrusted when read back)

    public var publicCABundle: String { "\(environment.sharedConfigDir)/ca-bundle.pem" }
    public var publicCACertificate: String { "\(environment.sharedConfigDir)/sandvault-config-ca.pem" }
    public var handoffDir: String { "\(environment.sharedWorkspace)/tmp" }
    /// The sandbox sources this file on every session start (`guest/home/.zshenv`).
    public var sharedZshenv: String { "\(environment.sharedUserDir)/.zshenv" }

    /// LaunchAgent label of sandvault-netd.
    public static let netdLabel = "\(BundleIdentity.bundleID).netd"
}
