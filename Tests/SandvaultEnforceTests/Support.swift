import Foundation
import Testing
@testable import SandvaultCore
@testable import SandvaultEnforce

enum Fixture {
    static func url(_ name: String) throws -> URL {
        let base = try #require(Bundle.module.url(forResource: "Fixtures", withExtension: nil))
        return base.appendingPathComponent(name)
    }

    static func text(_ name: String) throws -> String {
        try String(contentsOf: url(name), encoding: .utf8)
    }

    /// Compares with `Fixtures/golden/<name>`. `SV_UPDATE_GOLDEN=1 swift test` rewrites the file in the source tree.
    static func expectGolden(_ actual: String, _ name: String, filePath: String = #filePath, sourceLocation: SourceLocation = #_sourceLocation) throws {
        if ProcessInfo.processInfo.environment["SV_UPDATE_GOLDEN"] == "1" {
            let target = URL(fileURLWithPath: filePath).deletingLastPathComponent().appendingPathComponent("Fixtures/golden/\(name)")
            try actual.write(to: target, atomically: true, encoding: .utf8)
            return
        }
        let expected = try text("golden/\(name)")
        #expect(actual == expected, "golden \(name) differs; rerun with SV_UPDATE_GOLDEN=1 and review the diff", sourceLocation: sourceLocation)
    }
}

/// Fixed ids keep golden files stable.
func fixedID(_ n: Int) -> UUID {
    UUID(uuidString: String(format: "00000000-0000-4000-8000-%012d", n))!
}

/// A temporary root with the directories macOS has, sv's profile and sudoers file for `alice`.
struct TempRoot {
    let path: String
    let alice = SandvaultEnvironment(hostUser: "alice", hostHome: "/Users/alice")

    init() throws {
        path = FileManager.default.temporaryDirectory.appendingPathComponent("svctl-enforce-\(UUID().uuidString)").path
        for directory in ["var/sandvault", "etc/sudoers.d", "Library/Application Support", "Library/LaunchDaemons"] {
            try FileManager.default.createDirectory(atPath: "\(path)/\(directory)", withIntermediateDirectories: true)
        }
        try write(Fixture.text("sandbox-sandvault-alice.sb"), to: alice.sandboxProfilePath, mode: 0o444)
        try write("alice ALL=(sandvault-alice) NOPASSWD: /usr/bin/env\n", to: alice.sudoersFile, mode: 0o444)
    }

    func write(_ text: String, to rootPath: String, mode: Int = 0o644) throws {
        let full = path + rootPath
        if FileManager.default.fileExists(atPath: full) { try FileManager.default.removeItem(atPath: full) }
        try Data(text.utf8).write(to: URL(fileURLWithPath: full))
        try FileManager.default.setAttributes([.posixPermissions: mode], ofItemAtPath: full)
    }

    func read(_ rootPath: String) -> String? {
        FileManager.default.contents(atPath: path + rootPath).map { String(decoding: $0, as: UTF8.self) }
    }

    func mode(_ rootPath: String) -> Int? {
        (try? FileManager.default.attributesOfItem(atPath: path + rootPath))?[.posixPermissions].flatMap { ($0 as? NSNumber)?.intValue }
    }

    func exists(_ rootPath: String) -> Bool {
        FileManager.default.fileExists(atPath: path + rootPath)
    }

    /// Files a failed write might leave behind.
    func stagedLeftovers(in rootDirectory: String) -> [String] {
        ((try? FileManager.default.contentsOfDirectory(atPath: path + rootDirectory)) ?? []).filter { $0.hasSuffix(".tmp") }
    }

    func cleanup() {
        try? FileManager.default.removeItem(atPath: path)
    }
}
