import Foundation
import SandvaultCore

/// Every command line this module runs. Kept in one place so tests can assert exact argv
/// (sudoers rules only match the exact argument list).
enum Invocations {
    /// All processes of all users (`/bin/ps` is setuid on macOS, so arguments of other users are visible).
    static let psAll = CommandInvocation(
        "/bin/ps", ["-axww", "-o", "pid=,ppid=,user=,ruser=,%cpu=,%mem=,rss=,etime=,state=,command="], timeout: 10
    )

    /// Command line plus appended environment of the sandbox user's processes. `ps -E` shows the
    /// environment only for processes of the calling user, hence the sudo hop.
    static func psEnvironment(_ environment: SandvaultEnvironment) -> CommandInvocation {
        .asSandvault(environment, "/bin/ps", ["-E", "-ww", "-U", environment.sandvaultUser, "-o", "pid=,command="], timeout: 10)
    }

    /// `-w`: no warnings. As the sandbox user lsof cannot stat file systems in the host's home (Xcode's
    /// CoreDevice DeviceFS) and says so on every run.
    static func lsof(_ environment: SandvaultEnvironment) -> CommandInvocation {
        .asSandvault(environment, "/usr/sbin/lsof", ["-w", "-nP", "-i", "-a", "-u", environment.sandvaultUser, "-F", "pcPtnT"], timeout: 10)
    }

    static let nettop = CommandInvocation("/usr/bin/nettop", ["-P", "-L", "1", "-x", "-J", "bytes_in,bytes_out"], timeout: 15)

    static func kill(_ environment: SandvaultEnvironment, pids: [Int32], force: Bool) -> CommandInvocation {
        .asSandvault(environment, "/bin/kill", [force ? "-KILL" : "-TERM"] + pids.map(String.init), timeout: 10)
    }

    static func renice(_ environment: SandvaultEnvironment, pid: Int32, nice: Int) -> CommandInvocation {
        .asSandvault(environment, "/usr/bin/renice", ["+\(nice)", "-p", String(pid)], timeout: 10)
    }

    static func taskpolicyBackground(_ environment: SandvaultEnvironment, pid: Int32) -> CommandInvocation {
        .asSandvault(environment, "/usr/sbin/taskpolicy", ["-b", "-p", String(pid)], timeout: 10)
    }

    /// sv's sudoers: `<host> ALL=(root) NOPASSWD: /bin/launchctl bootout user/<uid>`.
    static func launchctlBootout(uid: Int) -> CommandInvocation {
        CommandInvocation("/usr/bin/sudo", ["-n", "/bin/launchctl", "bootout", "user/\(uid)"], timeout: 30)
    }

    /// sv's sudoers: `<host> ALL=(root) NOPASSWD: /usr/bin/pkill -9 -u sandvault-<host>`.
    static func pkillAll(_ environment: SandvaultEnvironment) -> CommandInvocation {
        CommandInvocation("/usr/bin/sudo", ["-n", "/usr/bin/pkill", "-9", "-u", environment.sandvaultUser], timeout: 30)
    }

    static func dsclRead(_ record: String, _ attributes: [String] = []) -> CommandInvocation {
        CommandInvocation("/usr/bin/dscl", [".", "-read", record] + attributes, timeout: 10)
    }

    static func checkMember(_ user: String, group: String) -> CommandInvocation {
        CommandInvocation("/usr/sbin/dseditgroup", ["-o", "checkmember", "-m", user, group], timeout: 10)
    }

    static func sudoWorks(_ environment: SandvaultEnvironment) -> CommandInvocation {
        CommandInvocation("/usr/bin/sudo", ["-n", "-u", environment.sandvaultUser, "/usr/bin/true"], timeout: 10)
    }

    static func listDirectory(_ path: String) -> CommandInvocation {
        CommandInvocation("/bin/ls", ["-led", path], timeout: 10)
    }

    static func svVersion(_ executable: String) -> CommandInvocation {
        CommandInvocation(executable, ["--version"], timeout: 10)
    }

    /// The umask this process inherited (from the terminal for svctl). A fixed string, nothing interpolated.
    static let umask = CommandInvocation("/bin/sh", ["-c", "umask"], timeout: 5)

    /// Sandbox denials: kernel reports (`Sandbox:` sender, pid 0) and the sandbox reporting subsystem.
    static let violationPredicate =
        #"((processID == 0) AND (senderImagePath CONTAINS "/Sandbox")) OR (subsystem == "com.apple.sandbox.reporting")"#

    static let logStream = CommandInvocation(
        "/usr/bin/log", ["stream", "--style", "ndjson", "--predicate", violationPredicate], timeout: nil
    )
}

extension CommandResult {
    /// sudo refused before running anything (missing or broken sudoers rule).
    var sudoRefused: Bool {
        !succeeded && (stderrString.contains("a password is required") || stderrString.hasPrefix("sudo:"))
    }

    /// First non-empty line of stderr, else of stdout.
    var message: String {
        for text in [stderrString, stdoutString] {
            let trimmed = text.trimmingCharacters(in: .whitespacesAndNewlines)
            if !trimmed.isEmpty { return trimmed.split(separator: "\n").first.map(String.init) ?? trimmed }
        }
        return "exit \(exitCode)"
    }
}

extension SandvaultError {
    static func sudoMissing(_ environment: SandvaultEnvironment) -> SandvaultError {
        .permissionDenied("passwordless sudo to \(environment.sandvaultUser) does not work; run `sv build --rebuild`")
    }
}
