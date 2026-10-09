import Foundation
#if canImport(Darwin)
import Darwin
#elseif canImport(Glibc)
import Glibc
#endif

/// Reads and writes inside a tree the sandbox can modify (the shared workspace).
///
/// The sandbox can replace any file or directory there with a symlink to a host file. A plain write as the
/// host user would then overwrite that host file, and a plain read would copy its content into the sandbox.
/// Every operation here walks the path with `openat(..., O_NOFOLLOW)` from `root`, creates files with
/// `O_EXCL | O_NOFOLLOW` and replaces them with `renameat`, so a planted symlink is never followed.
/// `root` itself must be trustworthy (`/Users/Shared/sv-$USER` is owned by the host user in a sticky directory).
public struct SharedFiles: Sendable {
    public let root: String

    public init(root: String) {
        self.root = root
    }

    public init(environment: SandvaultEnvironment) {
        self.init(root: environment.sharedWorkspace)
    }

    /// `absolutePath` relative to `root`, or `nil` when it lies outside or contains `.`/`..` components.
    public func relativePath(for absolutePath: String) -> String? {
        let prefix = root.hasSuffix("/") ? root : root + "/"
        guard absolutePath.hasPrefix(prefix) else { return nil }
        let relative = String(absolutePath.dropFirst(prefix.count))
        return (try? components(relative)) != nil ? relative : nil
    }

    /// Atomically writes `data`. Missing directories are created with `directoryPermissions`.
    public func write(_ data: Data, to relativePath: String, permissions: Int = 0o660, directoryPermissions: Int = 0o770) throws {
        let parts = try components(relativePath)
        let directory = try openDirectory(Array(parts.dropLast()), create: true, permissions: directoryPermissions)
        defer { close(directory) }
        let name = parts[parts.count - 1]
        let temporary = ".\(name).\(UUID().uuidString).tmp"

        let fd = openat(directory, temporary, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, mode_t(permissions))
        guard fd >= 0 else { throw posixError("create \(relativePath)") }
        var failure: SandvaultError?
        data.withUnsafeBytes { buffer in
            var offset = 0
            while offset < buffer.count {
                let written = Foundation.write(fd, buffer.baseAddress! + offset, buffer.count - offset)
                if written < 0 {
                    if errno == EINTR { continue }
                    failure = posixError("write \(relativePath)")
                    return
                }
                offset += written
            }
        }
        if failure == nil, fchmod(fd, mode_t(permissions)) != 0 { failure = posixError("chmod \(relativePath)") }
        close(fd)
        if failure == nil, renameat(directory, temporary, directory, name) != 0 { failure = posixError("rename \(relativePath)") }
        if let failure {
            unlinkat(directory, temporary, 0)
            throw failure
        }
    }

    /// Reads a regular file up to `maxBytes`; `nil` when it does not exist. Throws on symlinks and non-regular files.
    public func read(_ relativePath: String, maxBytes: Int = 1 << 20) throws -> Data? {
        let parts = try components(relativePath)
        let directory: Int32
        do {
            directory = try openDirectory(Array(parts.dropLast()), create: false, permissions: 0)
        } catch SandvaultError.io(let message) where message.hasSuffix("(errno \(ENOENT))") {
            return nil
        }
        defer { close(directory) }
        let fd = openat(directory, parts[parts.count - 1], O_RDONLY | O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK)
        if fd < 0 {
            if errno == ENOENT { return nil }
            throw posixError("open \(relativePath)")
        }
        defer { close(fd) }
        var info = stat()
        guard fstat(fd, &info) == 0 else { throw posixError("stat \(relativePath)") }
        guard (info.st_mode & S_IFMT) == S_IFREG else {
            throw SandvaultError.permissionDenied("\(relativePath) is not a regular file")
        }
        var result = Data()
        var buffer = [UInt8](repeating: 0, count: 64 * 1024)
        while result.count <= maxBytes {
            let count = Foundation.read(fd, &buffer, buffer.count)
            if count < 0 {
                if errno == EINTR { continue }
                throw posixError("read \(relativePath)")
            }
            if count == 0 { break }
            result.append(contentsOf: buffer[0..<count])
        }
        guard result.count <= maxBytes else { throw SandvaultError.io("\(relativePath) exceeds \(maxBytes) bytes") }
        return result
    }

    /// Removes a file (never follows a symlink; removes the link itself). Missing files are ignored.
    public func remove(_ relativePath: String) throws {
        let parts = try components(relativePath)
        let directory: Int32
        do {
            directory = try openDirectory(Array(parts.dropLast()), create: false, permissions: 0)
        } catch SandvaultError.io(let message) where message.hasSuffix("(errno \(ENOENT))") {
            return
        }
        defer { close(directory) }
        if unlinkat(directory, parts[parts.count - 1], 0) != 0, errno != ENOENT {
            throw posixError("remove \(relativePath)")
        }
    }

    // MARK: - Internals

    func components(_ relativePath: String) throws -> [String] {
        guard !relativePath.isEmpty, !relativePath.hasPrefix("/"), !relativePath.contains("\0") else {
            throw SandvaultError.invalidInput("bad shared path '\(relativePath)'")
        }
        let parts = relativePath.split(separator: "/", omittingEmptySubsequences: false).map(String.init)
        for part in parts where part.isEmpty || part == "." || part == ".." {
            throw SandvaultError.invalidInput("bad shared path '\(relativePath)'")
        }
        return parts
    }

    private func openDirectory(_ parts: [String], create: Bool, permissions: Int) throws -> Int32 {
        var fd = open(root, O_RDONLY | O_DIRECTORY | O_CLOEXEC)
        guard fd >= 0 else { throw posixError("open \(root)") }
        for part in parts {
            var next = openat(fd, part, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
            if next < 0, errno == ENOENT, create {
                if mkdirat(fd, part, mode_t(permissions)) != 0, errno != EEXIST {
                    let error = posixError("mkdir \(part)")
                    close(fd)
                    throw error
                }
                next = openat(fd, part, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
            }
            guard next >= 0 else {
                let error = posixError("open \(part)")
                close(fd)
                throw error
            }
            close(fd)
            fd = next
        }
        return fd
    }

    private func posixError(_ action: String) -> SandvaultError {
        let code = errno
        if code == ELOOP {
            return .permissionDenied("\(action): refusing to follow a symlink (errno \(code))")
        }
        if code == ENOTDIR {
            return .permissionDenied("\(action): not a directory (errno \(code))")
        }
        return .io("\(action) failed (errno \(code))")
    }
}
