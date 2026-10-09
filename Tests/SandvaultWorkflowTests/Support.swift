import Foundation
import SandvaultCore
@testable import SandvaultWorkflow

struct MissingFixture: Error {
    let name: String
}

func fixture(_ name: String) throws -> String {
    String(decoding: try fixtureData(name), as: UTF8.self)
}

func fixtureData(_ name: String) throws -> Data {
    guard let url = Bundle.module.url(forResource: name, withExtension: nil, subdirectory: "Fixtures") else {
        throw MissingFixture(name: name)
    }
    return try Data(contentsOf: url)
}

/// A temporary host home, shared workspace and config file for one test.
struct Sandbox {
    let base: String
    let home: String
    let workspace: String
    let environment: SandvaultEnvironment
    let shared: SharedFiles
    let configStore: ConfigStore

    init() throws {
        let temporary = FileManager.default.temporaryDirectory.appendingPathComponent("svwf-\(UUID().uuidString)").path
        try FileManager.default.createDirectory(atPath: temporary, withIntermediateDirectories: true)
        // Canonical, so expectations match realpath'd results (macOS: /var -> /private/var).
        base = HostPath.resolved(temporary) ?? temporary
        home = base + "/home"
        workspace = base + "/sv-alice"
        for directory in [home, workspace] {
            try FileManager.default.createDirectory(atPath: directory, withIntermediateDirectories: true)
        }
        environment = SandvaultEnvironment(hostUser: "alice", hostHome: home)
        shared = SharedFiles(root: workspace)
        configStore = ConfigStore(path: home + "/config.json")
    }

    var layout: SharedLayout { SharedLayout(environment: environment, shared: shared) }

    func cleanup() {
        try? FileManager.default.removeItem(atPath: base)
    }

    func write(_ text: String, to path: String, mode: Int = 0o644) throws {
        try FileManager.default.createDirectory(atPath: (path as NSString).deletingLastPathComponent, withIntermediateDirectories: true)
        try Data(text.utf8).write(to: URL(fileURLWithPath: path))
        try FileManager.default.setAttributes([.posixPermissions: mode], ofItemAtPath: path)
    }

    func read(_ path: String) throws -> String {
        try String(contentsOfFile: path, encoding: .utf8)
    }
}

/// Runs real git for test setup (author, branch and file protocol fixed, no host config).
enum TestGit {
    static let runner = ProcessCommandRunner()

    @discardableResult
    static func run(_ directory: String, _ arguments: [String]) async throws -> String {
        let environment = [
            "HOME": directory, "PATH": "/usr/bin:/bin", "GIT_CONFIG_NOSYSTEM": "1",
            "GIT_AUTHOR_NAME": "Test", "GIT_AUTHOR_EMAIL": "test@example.com",
            "GIT_COMMITTER_NAME": "Test", "GIT_COMMITTER_EMAIL": "test@example.com",
        ]
        let result = try await runner.checked(CommandInvocation(GitSafe.gitPath, [
            "-c", "init.defaultBranch=main", "-c", "commit.gpgsign=false", "-c", "protocol.file.allow=always", "-C", directory,
        ] + arguments, environment: environment))
        return result.trimmedOutput
    }

    /// A repository with one commit, an `origin` remote and the given files.
    static func repository(at path: String, files: [String: String] = ["README.md": "hello\n"], origin: String? = "https://example.com/org/app.git") async throws {
        try FileManager.default.createDirectory(atPath: path, withIntermediateDirectories: true)
        try await run(path, ["init", "-q"])
        for (name, content) in files {
            let file = path + "/" + name
            try FileManager.default.createDirectory(atPath: (file as NSString).deletingLastPathComponent, withIntermediateDirectories: true)
            try Data(content.utf8).write(to: URL(fileURLWithPath: file))
        }
        try await run(path, ["add", "-A"])
        try await run(path, ["commit", "-q", "-m", "initial"])
        if let origin { try await run(path, ["remote", "add", "origin", origin]) }
    }
}

/// Real git for `/usr/bin/git`, scripted responses for everything else (terminals, sudo, brew, otool).
final class MixedRunner: CommandRunner, @unchecked Sendable {
    let fake = FakeCommandRunner()
    private let real = ProcessCommandRunner()
    private let lock = NSLock()
    private var queues: [[String]: [CommandResult]] = [:]
    private var recorded: [CommandInvocation] = []

    /// Results served in order for an exact argv; the last one repeats.
    func queue(_ argv: [String], _ results: CommandResult...) {
        lock.withLock { queues[argv, default: []] += results }
    }

    var invocations: [CommandInvocation] { lock.withLock { recorded } }

    func run(_ invocation: CommandInvocation) async throws -> CommandResult {
        let queued: CommandResult? = lock.withLock {
            recorded.append(invocation)
            guard var queue = queues[invocation.argv], let first = queue.first else { return nil }
            if queue.count > 1 { queue.removeFirst() }
            queues[invocation.argv] = queue
            return first
        }
        if let queued { return queued }
        if invocation.executable == GitSafe.gitPath { return try await real.run(invocation) }
        return try await fake.run(invocation)
    }

    func lines(_ invocation: CommandInvocation) -> AsyncThrowingStream<String, Error> {
        fake.lines(invocation)
    }
}

/// An ssh public key line with a well-formed blob for `type`.
func publicKey(_ type: String = "ssh-ed25519", comment: String? = "alice@laptop") -> String {
    func field(_ bytes: [UInt8]) -> [UInt8] {
        let count = UInt32(bytes.count)
        return [UInt8(count >> 24), UInt8(count >> 16 & 0xFF), UInt8(count >> 8 & 0xFF), UInt8(count & 0xFF)] + bytes
    }
    let blob = field(Array(type.utf8)) + field([UInt8](repeating: 7, count: 32))
    return ([type, Data(blob).base64EncodedString()] + (comment.map { [$0] } ?? [])).joined(separator: " ")
}
