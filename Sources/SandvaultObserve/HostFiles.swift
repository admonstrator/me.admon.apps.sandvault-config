import Foundation
import SandvaultCore

/// Read-only access to host files this module inspects: sv's root-owned files (sudoers, profile), the
/// host-only state directory (helper logs, install marker) and Homebrew. None of them is sandbox-writable;
/// the shared workspace is only ever inspected through `ls`. Injectable so tests need no real files.
public struct HostFiles: Sendable {
    /// Contents of a regular file (at most `maxBytes`), or `nil` when missing or unreadable.
    public var read: @Sendable (_ path: String, _ maxBytes: Int) -> String?
    public var exists: @Sendable (_ path: String) -> Bool
    public var isExecutable: @Sendable (_ path: String) -> Bool
    /// POSIX permission bits, or `nil` when missing.
    public var permissions: @Sendable (_ path: String) -> Int?

    public init(
        read: @escaping @Sendable (String, Int) -> String?,
        exists: @escaping @Sendable (String) -> Bool,
        isExecutable: @escaping @Sendable (String) -> Bool,
        permissions: @escaping @Sendable (String) -> Int?
    ) {
        self.read = read
        self.exists = exists
        self.isExecutable = isExecutable
        self.permissions = permissions
    }

    public static let live = HostFiles(
        read: { path, maxBytes in
            guard let handle = FileHandle(forReadingAtPath: path) else { return nil }
            defer { try? handle.close() }
            do {
                return String(decoding: try handle.read(upToCount: maxBytes) ?? Data(), as: UTF8.self)
            } catch {
                return nil
            }
        },
        exists: { FileManager.default.fileExists(atPath: $0) },
        isExecutable: { FileManager.default.isExecutableFile(atPath: $0) },
        permissions: { path in
            (try? FileManager.default.attributesOfItem(atPath: path))?[.posixPermissions] as? Int
        }
    )

    /// An in-memory file system for tests: path -> contents, plus executables and permissions.
    public static func fixed(
        files: [String: String] = [:], executables: Set<String> = [], permissions: [String: Int] = [:]
    ) -> HostFiles {
        HostFiles(
            read: { path, _ in files[path] },
            exists: { files[$0] != nil || executables.contains($0) || permissions[$0] != nil },
            isExecutable: { executables.contains($0) },
            permissions: { permissions[$0] }
        )
    }
}
