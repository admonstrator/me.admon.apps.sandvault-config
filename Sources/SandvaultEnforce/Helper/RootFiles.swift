import Foundation
#if canImport(Darwin)
import Darwin
#elseif canImport(Glibc)
import Glibc
#endif
import SandvaultCore

/// File operations of the root helper. Writes go to a staged sibling (created with `O_EXCL | O_NOFOLLOW`), get
/// their owner and mode on the open descriptor, and are renamed into place; reads refuse symlinks.
struct RootFiles: Sendable {
    /// `chown 0:0` (root:wheel on macOS) on everything written; tests that do not run as root turn it off.
    var setsRootOwnership: Bool

    func read(_ path: String, maxBytes: Int = 16 << 20) throws -> Data? {
        let fd = open(path, O_RDONLY | O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK)
        if fd < 0 {
            if errno == ENOENT { return nil }
            throw posixError("open \(path)")
        }
        defer { close(fd) }
        var info = stat()
        guard fstat(fd, &info) == 0 else { throw posixError("stat \(path)") }
        guard (info.st_mode & S_IFMT) == S_IFREG else { throw SandvaultError.permissionDenied("\(path) is not a regular file") }
        var result = Data()
        var buffer = [UInt8](repeating: 0, count: 64 * 1024)
        while true {
            let count = Foundation.read(fd, &buffer, buffer.count)
            if count < 0 {
                if errno == EINTR { continue }
                throw posixError("read \(path)")
            }
            if count == 0 { break }
            result.append(contentsOf: buffer[0..<count])
            guard result.count <= maxBytes else { throw SandvaultError.io("\(path) exceeds \(maxBytes) bytes") }
        }
        return result
    }

    func readText(_ path: String) throws -> String? {
        try read(path).map { String(decoding: $0, as: UTF8.self) }
    }

    /// Writes `data` to a new hidden sibling of `path` with the final owner and mode; returns its path.
    /// Hidden names contain a dot, so sudo's `#includedir` ignores a staged sudoers file.
    func stage(_ data: Data, beside path: String, mode: Int) throws -> String {
        let url = URL(fileURLWithPath: path)
        let staged = url.deletingLastPathComponent().appendingPathComponent(".\(url.lastPathComponent).\(UUID().uuidString).tmp").path
        let fd = open(staged, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0o600)
        guard fd >= 0 else { throw posixError("create \(staged)") }
        var failure: SandvaultError?
        data.withUnsafeBytes { buffer in
            var offset = 0
            while offset < buffer.count {
                let written = Foundation.write(fd, buffer.baseAddress! + offset, buffer.count - offset)
                if written < 0 {
                    if errno == EINTR { continue }
                    failure = posixError("write \(staged)")
                    return
                }
                offset += written
            }
        }
        if failure == nil, setsRootOwnership, fchown(fd, 0, 0) != 0 { failure = posixError("chown \(staged)") }
        if failure == nil, fchmod(fd, mode_t(mode)) != 0 { failure = posixError("chmod \(staged)") }
        if failure == nil, fsync(fd) != 0 { failure = posixError("fsync \(staged)") }
        close(fd)
        if let failure {
            unlink(staged)
            throw failure
        }
        return staged
    }

    func commit(_ staged: String, to path: String) throws {
        guard rename(staged, path) == 0 else {
            let error = posixError("rename \(staged) to \(path)")
            unlink(staged)
            throw error
        }
    }

    func discard(_ staged: String) {
        unlink(staged)
    }

    func write(_ data: Data, to path: String, mode: Int) throws {
        try commit(try stage(data, beside: path, mode: mode), to: path)
    }

    /// Creates one directory level when missing; an existing path must be a real directory.
    func makeDirectory(_ path: String, mode: Int) throws {
        var info = stat()
        if lstat(path, &info) == 0 {
            guard (info.st_mode & S_IFMT) == S_IFDIR else { throw SandvaultError.permissionDenied("\(path) exists and is not a directory") }
            return
        }
        guard mkdir(path, mode_t(mode)) == 0 else { throw posixError("mkdir \(path)") }
        if setsRootOwnership, chown(path, 0, 0) != 0 { throw posixError("chown \(path)") }
        guard chmod(path, mode_t(mode)) == 0 else { throw posixError("chmod \(path)") }
    }

    /// Removes a file or symlink; a missing path is fine.
    func remove(_ path: String) throws {
        if unlink(path) != 0, errno != ENOENT { throw posixError("remove \(path)") }
    }

    func removeTree(_ path: String) throws {
        guard FileManager.default.fileExists(atPath: path) else { return }
        do {
            try FileManager.default.removeItem(atPath: path)
        } catch {
            throw SandvaultError.io("cannot remove \(path): \(error)")
        }
    }

    private func posixError(_ action: String) -> SandvaultError {
        let code = errno
        if code == ELOOP { return .permissionDenied("\(action): refusing to follow a symlink") }
        if code == EACCES || code == EPERM { return .permissionDenied("\(action) (errno \(code))") }
        return .io("\(action) failed (errno \(code))")
    }
}
