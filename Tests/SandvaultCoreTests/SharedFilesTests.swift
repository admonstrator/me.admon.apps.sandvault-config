import Foundation
import Testing
@testable import SandvaultCore

@Suite struct SharedFilesTests {
    let base: URL
    let shared: SharedFiles
    let outside: URL

    init() throws {
        base = FileManager.default.temporaryDirectory.appendingPathComponent("svctl-shared-\(UUID().uuidString)")
        let root = base.appendingPathComponent("sv-alice")
        outside = base.appendingPathComponent("host-home")
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: true)
        try FileManager.default.createDirectory(at: outside, withIntermediateDirectories: true)
        try Data("host secret".utf8).write(to: outside.appendingPathComponent(".zshrc"))
        shared = SharedFiles(root: root.path)
    }

    func cleanup() { try? FileManager.default.removeItem(at: base) }

    @Test func writesReadsAndReplaces() throws {
        defer { cleanup() }
        try shared.write(Data("one".utf8), to: "user/.zshenv")
        #expect(try shared.read("user/.zshenv") == Data("one".utf8))
        try shared.write(Data("two".utf8), to: "user/.zshenv", permissions: 0o640)
        #expect(try shared.read("user/.zshenv") == Data("two".utf8))
        let attributes = try FileManager.default.attributesOfItem(atPath: shared.root + "/user/.zshenv")
        #expect((attributes[.posixPermissions] as? NSNumber)?.intValue == 0o640)
        #expect(try FileManager.default.contentsOfDirectory(atPath: shared.root + "/user") == [".zshenv"])
        #expect(try shared.read("user/missing") == nil)
        #expect(try shared.read("nowhere/missing") == nil)
    }

    @Test func neverWritesThroughASymlinkedFile() throws {
        defer { cleanup() }
        try FileManager.default.createDirectory(atPath: shared.root + "/user", withIntermediateDirectories: true)
        try FileManager.default.createSymbolicLink(atPath: shared.root + "/user/.zshenv", withDestinationPath: outside.appendingPathComponent(".zshrc").path)

        #expect(throws: SandvaultError.self) { try shared.read("user/.zshenv") }
        try shared.write(Data("ours".utf8), to: "user/.zshenv")
        // The link itself was replaced; the host file is untouched.
        #expect(try String(contentsOf: outside.appendingPathComponent(".zshrc"), encoding: .utf8) == "host secret")
        #expect(try shared.read("user/.zshenv") == Data("ours".utf8))
    }

    @Test func neverDescendsIntoASymlinkedDirectory() throws {
        defer { cleanup() }
        try FileManager.default.createSymbolicLink(atPath: shared.root + "/user", withDestinationPath: outside.path)
        #expect(throws: SandvaultError.self) { try shared.write(Data("x".utf8), to: "user/.zshrc") }
        #expect(throws: SandvaultError.self) { try shared.read("user/.zshrc") }
        #expect(try String(contentsOf: outside.appendingPathComponent(".zshrc"), encoding: .utf8) == "host secret")
    }

    @Test func rejectsEscapingPaths() {
        defer { cleanup() }
        for path in ["", "/etc/passwd", "../x", "a/../b", "a//b", "./a", "a/"] {
            #expect(throws: SandvaultError.self, "\(path)") { try shared.write(Data(), to: path) }
        }
        #expect(shared.relativePath(for: shared.root + "/repos/app/README.md") == "repos/app/README.md")
        #expect(shared.relativePath(for: shared.root + "/../x") == nil)
        #expect(shared.relativePath(for: "/etc/passwd") == nil)
    }

    @Test func removeDeletesTheLinkNotTheTarget() throws {
        defer { cleanup() }
        try FileManager.default.createSymbolicLink(atPath: shared.root + "/link", withDestinationPath: outside.appendingPathComponent(".zshrc").path)
        try shared.remove("link")
        try shared.remove("link")
        #expect(FileManager.default.fileExists(atPath: outside.appendingPathComponent(".zshrc").path))
    }

    @Test func readEnforcesSizeLimit() throws {
        defer { cleanup() }
        try shared.write(Data(repeating: 0x41, count: 100), to: "big")
        #expect(throws: SandvaultError.self) { try shared.read("big", maxBytes: 10) }
        #expect(try shared.read("big", maxBytes: 100)?.count == 100)
    }
}
