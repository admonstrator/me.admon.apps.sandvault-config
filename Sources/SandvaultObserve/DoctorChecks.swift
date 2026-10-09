import Foundation
import SandvaultCore

/// Is sandvault set up correctly? One `Check` per question, each with a fix where the user can act.
/// Every command has a timeout; a command that is missing (Linux) or times out yields `.unknown`.
public struct ObserveChecks: CheckProvider {
    public var environment: SandvaultEnvironment
    public var runner: CommandRunner
    public var files: HostFiles
    /// Directories searched for `sv`: `PATH` plus the Homebrew prefixes (GUI apps get a minimal PATH).
    public var searchPaths: [String]

    /// The tested upstream release line.
    public static let supportedSvVersion = "1.32."

    public static let ids = [
        "sv.installed", "sv.install-marker", "account.user", "account.group", "account.not-staff", "account.host-in-group",
        "sudoers.file", "sudoers.works", "profile.present", "profile.managed-block", "workspace.permissions",
        "ssh.remote-login", "umask", "homebrew.permissions",
    ]

    public init(
        environment: SandvaultEnvironment, runner: CommandRunner, files: HostFiles = .live,
        searchPaths: [String]? = nil
    ) {
        self.environment = environment
        self.runner = runner
        self.files = files
        let path = ProcessInfo.processInfo.environment["PATH"]?.split(separator: ":").map(String.init) ?? []
        self.searchPaths = searchPaths ?? (path + ["/opt/homebrew/bin", "/usr/local/bin"])
    }

    public func checks() async -> [Check] {
        async let sv = svInstalled()
        async let accounts = accountChecks()
        async let notStaff = notStaff()
        async let hostInGroup = hostInGroup()
        async let sudoWorks = sudoersWorks()
        async let workspace = workspacePermissions()
        async let ssh = remoteLogin()
        async let umask = umaskCheck()
        var all: [Check] = [await sv, installMarker()]
        all += await accounts
        all += [await notStaff, await hostInGroup, sudoersFile(), await sudoWorks]
        all += profileChecks()
        all += [await workspace, await ssh, await umask, homebrewPermissions()]
        return all
    }

    // MARK: - sv

    func svInstalled() async -> Check {
        let id = "sv.installed", title = "sandvault installed"
        var seen: Set<String> = []
        guard let path = searchPaths.filter({ seen.insert($0).inserted }).map({ "\($0)/sv" }).first(where: files.isExecutable) else {
            return Check(id: id, title: title, state: .failure, detail: "`sv` not found in PATH, /opt/homebrew/bin or /usr/local/bin",
                         fix: "brew install sandvault")
        }
        let result: CommandResult
        switch await run(Invocations.svVersion(path)) {
        case .unavailable(let why): return Check(id: id, title: title, state: .unknown, detail: "\(path): \(why)")
        case .finished(let finished): result = finished
        }
        guard result.succeeded, let version = SvVersionParser.parse(result.stdoutString) else {
            return Check(id: id, title: title, state: .warning, detail: "\(path) --version failed: \(result.message)")
        }
        guard version.hasPrefix(Self.supportedSvVersion) else {
            return Check(id: id, title: title, state: .warning,
                         detail: "sv \(version) at \(path); this tool is tested with \(Self.supportedSvVersion)x, most features should still work",
                         fix: "brew upgrade sandvault")
        }
        return Check(id: id, title: title, state: .ok, detail: "sv \(version) at \(path)")
    }

    func installMarker() -> Check {
        let id = "sv.install-marker", title = "sv installation finished"
        guard files.exists(environment.installMarker) else {
            return Check(id: id, title: title, state: .failure, detail: "\(environment.installMarker) is missing", fix: "sv build")
        }
        return Check(id: id, title: title, state: .ok, detail: environment.installMarker)
    }

    // MARK: - Accounts

    func accountChecks() async -> [Check] {
        let user = environment.sandvaultUser, group = environment.sandvaultGroup
        let userCheck: Check
        var userGID: String?
        switch await run(Invocations.dsclRead("/Users/\(user)", ["UniqueID", "PrimaryGroupID", "NFSHomeDirectory", "UserShell"])) {
        case .unavailable(let why):
            userCheck = Check(id: "account.user", title: "Sandbox user", state: .unknown, detail: why)
        case .finished(let result) where !result.succeeded:
            userCheck = Check(id: "account.user", title: "Sandbox user", state: .failure, detail: "\(user) does not exist (\(result.message))",
                              fix: "sv build --rebuild")
        case .finished(let result):
            let record = DsclParser.parse(result.stdoutString)
            let uid = record["UniqueID"]?.first ?? "?"
            userGID = record["PrimaryGroupID"]?.first
            let home = record["NFSHomeDirectory"]?.joined(separator: " ") ?? "?"
            let shell = record["UserShell"]?.first ?? "?"
            let detail = "uid \(uid), gid \(userGID ?? "?"), home \(home), shell \(shell)"
            if home != environment.sandvaultHome {
                userCheck = Check(id: "account.user", title: "Sandbox user", state: .failure,
                                  detail: "\(detail); expected home \(environment.sandvaultHome)", fix: "sv build --rebuild")
            } else if shell != "/bin/zsh" {
                userCheck = Check(id: "account.user", title: "Sandbox user", state: .warning,
                                  detail: "\(detail); sv expects /bin/zsh", fix: "sv build --rebuild")
            } else {
                userCheck = Check(id: "account.user", title: "Sandbox user", state: .ok, detail: detail)
            }
        }

        let groupCheck: Check
        switch await run(Invocations.dsclRead("/Groups/\(group)", ["PrimaryGroupID"])) {
        case .unavailable(let why):
            groupCheck = Check(id: "account.group", title: "Sandbox group", state: .unknown, detail: why)
        case .finished(let result) where !result.succeeded:
            groupCheck = Check(id: "account.group", title: "Sandbox group", state: .failure, detail: "\(group) does not exist (\(result.message))",
                               fix: "sv build --rebuild")
        case .finished(let result):
            let gid = DsclParser.parse(result.stdoutString)["PrimaryGroupID"]?.first ?? "?"
            if let userGID, userGID != gid {
                groupCheck = Check(id: "account.group", title: "Sandbox group", state: .warning,
                                   detail: "\(user) has primary group \(userGID), \(group) is \(gid)", fix: "sv build --rebuild")
            } else {
                groupCheck = Check(id: "account.group", title: "Sandbox group", state: .ok, detail: "\(group), gid \(gid)")
            }
        }
        return [userCheck, groupCheck]
    }

    func notStaff() async -> Check {
        let id = "account.not-staff", title = "Sandbox user not in staff"
        let user = environment.sandvaultUser
        switch await membership(user, "staff") {
        case .unavailable(let why): return Check(id: id, title: title, state: .unknown, detail: why)
        case .known(true):
            return Check(id: id, title: title, state: .failure, detail: "\(user) is in staff, which can read most of your files",
                         fix: "sudo dseditgroup -o edit -d \(user) -t user staff")
        case .known(false): return Check(id: id, title: title, state: .ok, detail: "\(user) is not in staff")
        }
    }

    func hostInGroup() async -> Check {
        let id = "account.host-in-group", title = "Host user in sandbox group"
        let host = environment.hostUser, group = environment.sandvaultGroup
        switch await membership(host, group) {
        case .unavailable(let why): return Check(id: id, title: title, state: .unknown, detail: why)
        case .known(true): return Check(id: id, title: title, state: .ok, detail: "\(host) is in \(group)")
        case .known(false):
            return Check(id: id, title: title, state: .failure, detail: "\(host) is not in \(group); the shared workspace is not yours to use",
                         fix: "sudo dseditgroup -o edit -a \(host) -t user \(group)")
        }
    }

    // MARK: - sudoers

    func sudoersFile() -> Check {
        let id = "sudoers.file", title = "sv sudoers rule"
        let path = environment.sudoersFile
        guard let text = files.read(path, 1 << 16) else {
            if files.exists(path) {
                return Check(id: id, title: title, state: .warning, detail: "\(path) is not readable", fix: "sv build --rebuild")
            }
            return Check(id: id, title: title, state: .failure, detail: "\(path) is missing", fix: "sv build --rebuild")
        }
        let rules = Set(text.split(separator: "\n").map { $0.split(whereSeparator: \.isWhitespace).joined(separator: " ") }
            .filter { !$0.hasPrefix("#") && !$0.isEmpty })
        let host = environment.hostUser, sandbox = environment.sandvaultUser
        guard rules.contains("\(host) ALL=(\(sandbox)) NOPASSWD: /usr/bin/env") else {
            return Check(id: id, title: title, state: .failure, detail: "\(path) lacks the /usr/bin/env rule that inspection depends on",
                         fix: "sv build --rebuild")
        }
        let canKillAll = rules.contains { $0.hasPrefix("\(host) ALL=(root) NOPASSWD: /bin/launchctl bootout user/") }
            && rules.contains("\(host) ALL=(root) NOPASSWD: /usr/bin/pkill -9 -u \(sandbox)")
        guard canKillAll else {
            return Check(id: id, title: title, state: .warning, detail: "\(path) lacks the launchctl/pkill rules that `svctl kill --all` uses",
                         fix: "sv build --rebuild")
        }
        return Check(id: id, title: title, state: .ok, detail: path)
    }

    func sudoersWorks() async -> Check {
        let id = "sudoers.works", title = "Passwordless sudo to the sandbox user"
        switch await run(Invocations.sudoWorks(environment)) {
        case .unavailable(let why): return Check(id: id, title: title, state: .unknown, detail: why)
        case .finished(let result) where result.succeeded:
            return Check(id: id, title: title, state: .ok, detail: "sudo -n -u \(environment.sandvaultUser) works")
        case .finished(let result):
            return Check(id: id, title: title, state: .failure, detail: result.message, fix: "sv build --rebuild")
        }
    }

    // MARK: - Profile

    func profileChecks() -> [Check] {
        let path = environment.sandboxProfilePath
        guard let text = files.read(path, 1 << 20) else {
            let present = files.exists(path)
                ? Check(id: "profile.present", title: "Sandbox profile", state: .warning, detail: "\(path) is not readable",
                        fix: "sv --fix-permissions")
                : Check(id: "profile.present", title: "Sandbox profile", state: .failure,
                        detail: "\(path) is missing; sessions run without sandbox-exec restrictions until sv recreates it", fix: "sv build --rebuild")
            return [present, Check(id: "profile.managed-block", title: "Managed rule block", state: .unknown, detail: "profile not readable")]
        }
        let present = text.contains("(version 1)")
            ? Check(id: "profile.present", title: "Sandbox profile", state: .ok, detail: path)
            : Check(id: "profile.present", title: "Sandbox profile", state: .warning, detail: "\(path) does not look like an SBPL profile",
                    fix: "sv build --rebuild")
        let block = ManagedBlock.sandboxProfile
        let managed: Check
        if block.contains(in: text) {
            managed = Check(id: "profile.managed-block", title: "Managed rule block", state: .ok, detail: "present")
        } else if text.contains(block.begin) || text.contains(block.end) {
            managed = Check(id: "profile.managed-block", title: "Managed rule block", state: .warning,
                            detail: "only one of the two markers is present; the block is damaged")
        } else {
            managed = Check(id: "profile.managed-block", title: "Managed rule block", state: .skipped,
                            detail: "absent; sv's profile is used unchanged")
        }
        return [present, managed]
    }

    // MARK: - Workspace, SSH, umask, Homebrew

    func workspacePermissions() async -> Check {
        let id = "workspace.permissions", title = "Shared workspace permissions"
        let path = environment.sharedWorkspace
        let result: CommandResult
        switch await run(Invocations.listDirectory(path)) {
        case .unavailable(let why): return Check(id: id, title: title, state: .unknown, detail: why)
        case .finished(let finished): result = finished
        }
        guard result.succeeded, let listing = LsParser.parseDirectory(result.stdoutString) else {
            return Check(id: id, title: title, state: .failure, detail: "\(path): \(result.message)", fix: "sv build --rebuild")
        }
        let host = environment.hostUser, group = environment.sandvaultGroup
        guard listing.owner == host, listing.group == group else {
            return Check(id: id, title: title, state: .failure,
                         detail: "\(path) is owned by \(listing.owner):\(listing.group), expected \(host):\(group)", fix: "sv build --rebuild")
        }
        let mode = String(listing.permissions, radix: 8)
        guard listing.permissions & 0o770 == 0o770 else {
            return Check(id: id, title: title, state: .failure, detail: "\(path) has mode \(mode); owner and group need rwx",
                         fix: "sv build --rebuild")
        }
        let principal = "group:\(group)"
        let entries = listing.acl.filter { $0.principal == principal && $0.allow }
        let writable = entries.contains { $0.rights.contains("add_file") || $0.rights.contains("write") }
        let inheritsToFiles = entries.contains { $0.rights.contains("file_inherit") }
        guard writable, inheritsToFiles else {
            return Check(id: id, title: title, state: .warning,
                         detail: "\(path) lacks the inheritable ACL for \(group); files you create there may not be writable for the sandbox",
                         fix: "sv build --rebuild")
        }
        guard listing.permissions == 0o770 else {
            return Check(id: id, title: title, state: .warning, detail: "\(path) has mode \(mode), sv uses 770 (others should have no access)",
                         fix: "chmod 770 \(path)")
        }
        return Check(id: id, title: title, state: .ok, detail: "\(host):\(group), mode 770, group ACL inherited")
    }

    /// Only `sv --ssh` needs Remote Login, so this is never a failure.
    func remoteLogin() async -> Check {
        let id = "ssh.remote-login", title = "Remote Login (only for sv --ssh)"
        let user = environment.sandvaultUser
        guard case .finished(let group) = await run(Invocations.dsclRead("/Groups/com.apple.access_ssh")), group.succeeded else {
            return Check(id: id, title: title, state: .skipped, detail: "Remote Login is off or open to all users")
        }
        switch await membership(user, "com.apple.access_ssh") {
        case .known(true): return Check(id: id, title: title, state: .ok, detail: "\(user) may log in over SSH")
        case .known(false):
            return Check(id: id, title: title, state: .warning, detail: "Remote Login is limited to selected users and \(user) is not one; `sv --ssh` fails",
                         fix: "sudo dseditgroup -o edit -a \(user) -t user com.apple.access_ssh")
        case .unavailable(let why): return Check(id: id, title: title, state: .skipped, detail: why)
        }
    }

    func umaskCheck() async -> Check {
        let id = "umask", title = "umask"
        let result: CommandResult
        switch await run(Invocations.umask) {
        case .unavailable(let why): return Check(id: id, title: title, state: .unknown, detail: why)
        case .finished(let finished): result = finished
        }
        let text = result.stdoutString.trimmingCharacters(in: .whitespacesAndNewlines)
        guard result.succeeded, let mask = Int(text, radix: 8) else {
            return Check(id: id, title: title, state: .unknown, detail: "cannot read umask: \(result.message)")
        }
        // Same test as sv: group or others lose read access to new files.
        guard mask & 0o044 == 0 else {
            return Check(id: id, title: title, state: .warning, detail: "umask \(text) is more restrictive than 022; sv and Homebrew files may become unreadable for the sandbox",
                         fix: "umask 022 (in ~/.zprofile), or run `sv --fix-permissions`")
        }
        return Check(id: id, title: title, state: .ok, detail: "umask \(text)")
    }

    func homebrewPermissions() -> Check {
        let id = "homebrew.permissions", title = "Homebrew readable for the sandbox"
        guard let prefix = ["/opt/homebrew", "/usr/local"].first(where: { files.isExecutable("\($0)/bin/brew") }) else {
            return Check(id: id, title: title, state: .skipped, detail: "Homebrew not installed")
        }
        guard let permissions = files.permissions("\(prefix)/bin") else {
            return Check(id: id, title: title, state: .unknown, detail: "cannot read \(prefix)/bin")
        }
        let mode = String(permissions & 0o7777, radix: 8)
        // Same test as sv: neither read nor search for others.
        guard permissions & 0o005 != 0 else {
            return Check(id: id, title: title, state: .warning, detail: "\(prefix)/bin has mode \(mode); the sandbox cannot use Homebrew tools",
                         fix: "sudo chmod -R o+rX \(prefix)")
        }
        return Check(id: id, title: title, state: .ok, detail: "\(prefix)/bin mode \(mode)")
    }

    // MARK: - Running commands

    enum Outcome {
        case finished(CommandResult)
        case unavailable(String)
    }

    func run(_ invocation: CommandInvocation) async -> Outcome {
        do {
            return .finished(try await runner.run(invocation))
        } catch SandvaultError.commandNotRunnable(let command, _) {
            return .unavailable("\(command.split(separator: " ").first ?? "") is not available on this system")
        } catch SandvaultError.timedOut(let command) {
            return .unavailable("timed out: \(command)")
        } catch {
            return .unavailable("\(error)")
        }
    }

    enum Membership {
        case known(Bool)
        case unavailable(String)
    }

    func membership(_ user: String, _ group: String) async -> Membership {
        switch await run(Invocations.checkMember(user, group: group)) {
        case .unavailable(let why): return .unavailable(why)
        case .finished(let result):
            if let member = MembershipParser.isMember(result.stdoutString) { return .known(member) }
            return .unavailable("dseditgroup: \(result.message)")
        }
    }
}
