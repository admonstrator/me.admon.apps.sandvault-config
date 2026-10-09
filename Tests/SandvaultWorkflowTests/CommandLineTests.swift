import Foundation
import SandvaultCore
import Testing
@testable import SandvaultWorkflow

/// Words a hostile or careless path, task or option could contain.
let nastyWords = [
    "", "plain", "two words", "it's", "'", "''", "\"double\"", "$HOME", "${HOME}", "$(id)", "`id`", "a;b", "a&&b", "a|b",
    "back\\slash", "\\'", "new\nline", "tab\there", "*.swift", "?", "[ab]", "~", "~root", "=ls", "%1", "!!", "#comment",
    "-n", "--", "ünïcödé", "trailing ", " leading", "a'b'c", "x'\\''y",
]

/// What a POSIX shell makes of `line`: the words `printf` receives.
func shellWords(_ line: String, shell: String = "/bin/sh") async throws -> [String] {
    let result = try await ProcessCommandRunner().checked(CommandInvocation(shell, ["-c", "printf '%s\\0' " + line]))
    return result.stdout.split(separator: 0, omittingEmptySubsequences: false).dropLast().map { String(decoding: $0, as: UTF8.self) }
}

@Suite struct ShellQuotingTests {
    @Test func plainWordsStayBare() {
        #expect(ShellQuoting.quote("sv-clone") == "sv-clone")
        #expect(ShellQuoting.quote("/Users/alice/src/app") == "/Users/alice/src/app")
        #expect(ShellQuoting.quote("git@github.com:org/repo.git") == "git@github.com:org/repo.git")
        #expect(ShellQuoting.quote("--browser") == "--browser")
    }

    @Test func everythingElseIsSingleQuoted() {
        #expect(ShellQuoting.quote("") == "''")
        #expect(ShellQuoting.quote("two words") == "'two words'")
        #expect(ShellQuoting.quote("it's") == "'it'\\''s'")
        #expect(ShellQuoting.quote("$HOME") == "'$HOME'")
        #expect(ShellQuoting.quote("=ls") == "'=ls'")
        #expect(ShellQuoting.quote("~") == "'~'")
    }

    @Test(arguments: ["/bin/sh", "/bin/bash"])
    func roundTripsThroughARealShell(shell: String) async throws {
        #expect(try await shellWords(ShellQuoting.join(nastyWords), shell: shell) == nastyWords)
        for word in nastyWords {
            #expect(try await shellWords(ShellQuoting.quote(word), shell: shell) == [word], "\(word)")
        }
    }
}

@Suite struct HandoffCommandLineTests {
    let prompt = "Read /Users/Shared/sv-alice/tmp/handoff-app.md and continue the task described there."

    @Test func buildsSvCloneArguments() {
        let request = HandoffRequest(source: "/Users/alice/src/app", agent: .claude, svOptions: ["--browser", "-v"])
        #expect(HandoffCommandLine.arguments(source: "/Users/alice/src/app", request: request, prompt: nil)
            == ["sv-clone", "/Users/alice/src/app", "--", "--browser", "-v", "claude"])
        #expect(HandoffCommandLine.arguments(source: "/Users/alice/src/app", request: request, prompt: prompt)
            == ["sv-clone", "/Users/alice/src/app", "--", "--browser", "-v", "claude", "--", prompt])
    }

    @Test func deployKeyFlags() {
        var request = HandoffRequest(source: "git@github.com:org/app.git", agent: .codex, deployKey: .readOnly)
        #expect(HandoffCommandLine.arguments(source: request.source, request: request, prompt: nil) == ["sv-clone", "-k", "git@github.com:org/app.git", "--", "codex"])
        request.deployKey = .readWrite
        #expect(HandoffCommandLine.arguments(source: request.source, request: request, prompt: nil).prefix(2) == ["sv-clone", "-w"])
    }

    @Test func promptArgumentsPerAgent() {
        #expect(HandoffCommandLine.promptArguments(.claude, "p") == ["p"])
        #expect(HandoffCommandLine.promptArguments(.codex, "p") == ["p"])
        #expect(HandoffCommandLine.promptArguments(.pi, "p") == ["p"])
        #expect(HandoffCommandLine.promptArguments(.gemini, "p") == ["--prompt-interactive", "p"])
        #expect(HandoffCommandLine.promptArguments(.opencode, "p") == ["--prompt", "p"])
        #expect(HandoffCommandLine.promptArguments(.muse, "p") == nil)
        // For `sv shell`, words after `--` are a command; a prompt there would be executed.
        #expect(HandoffCommandLine.promptArguments(.shell, "p") == nil)
        let request = HandoffRequest(source: "/r", agent: .shell)
        #expect(HandoffCommandLine.arguments(source: "/r", request: request, prompt: prompt) == ["sv-clone", "/r", "--", "shell"])
    }

    @Test func hostilePathsSurviveTheShell() async throws {
        let source = "/Users/alice/my repo/it's $(touch pwned) `id`"
        let request = HandoffRequest(source: source, agent: .claude)
        let argv = HandoffCommandLine.arguments(source: source, request: request, prompt: "Read /x/handoff-it's.md")
        #expect(try await shellWords(ShellQuoting.join(argv)) == argv)
    }
}

@Suite struct TerminalLaunchTests {
    let command = ShellQuoting.join(["sv-clone", "/Users/alice/my app", "--", "claude", "--", "Read \"x\" and it's $HOME"])

    @Test func terminalAppGetsTheCommandAsAnArgument() {
        let invocation = TerminalLaunch.invocation(.terminal, command: command)
        #expect(invocation.executable == "/usr/bin/osascript")
        #expect(invocation.arguments == [
            "-e", "on run argv", "-e", "tell application \"Terminal\"", "-e", "activate", "-e", "do script (item 1 of argv)",
            "-e", "end tell", "-e", "end run", command,
        ])
    }

    @Test func iTermWritesIntoANewWindow() {
        let invocation = TerminalLaunch.invocation(.iterm2, command: command)
        #expect(invocation.executable == "/usr/bin/osascript")
        #expect(invocation.arguments.last == command)
        #expect(invocation.arguments.contains("set newWindow to (create window with default profile)"))
        #expect(invocation.arguments.contains("tell current session of newWindow to write text (item 1 of argv)"))
        // The command is never spliced into AppleScript source.
        #expect(!invocation.arguments.dropLast().contains { $0.contains("sv-clone") })
    }

    @Test func ghosttyRunsZshThatKeepsTheWindowOpen() async throws {
        let invocation = TerminalLaunch.invocation(.ghostty, command: command)
        #expect(invocation.argv.prefix(6) == [
            "/usr/bin/open", "-na", "Ghostty.app", "--args", "--window-save-state=never", "--quit-after-last-window-closed=true",
        ])
        let value = try #require(invocation.arguments.last?.split(separator: "=", maxSplits: 1).last.map(String.init))
        #expect(invocation.arguments.last?.hasPrefix("--command=") == true)
        // Ghostty hands the value to a shell; that shell must see zsh -lc '<command>; exec "$SHELL" -l'.
        let words = try await shellWords(value)
        #expect(words == ["/bin/zsh", "-lc", command + "; exec \"$SHELL\" -l"])
        #expect(try await shellWords(command) == ["sv-clone", "/Users/alice/my app", "--", "claude", "--", "Read \"x\" and it's $HOME"])
    }
}
