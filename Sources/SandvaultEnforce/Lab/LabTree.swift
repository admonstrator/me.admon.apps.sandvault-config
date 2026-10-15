import Foundation
#if canImport(Darwin)
import Darwin
#elseif canImport(Glibc)
import Glibc
#endif
import SandvaultCore

/// File system work of lab mode, as root inside trees the sandbox can write (D52). Every step goes through a
/// directory descriptor opened with `O_NOFOLLOW` from a trusted parent, so a symlink the sandbox planted is
/// copied or moved as a link and never followed. The live trees are quiet while the helper writes into them:
/// a rewind terminates the sandbox's processes first.
enum LabTree {
    /// More entries than this in one session is refused rather than walked every minute.
    static let maxEntries = 2_000_000

    // MARK: Descriptors

    /// Opens an existing directory without following a symlink at the last component.
    static func openDirectory(_ path: String) throws -> Int32 {
        let fd = open(path, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
        guard fd >= 0 else { throw posixError("open \(path)") }
        return fd
    }

    static func openDirectory(at parent: Int32, _ name: String) throws -> Int32 {
        let fd = openat(parent, name, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
        guard fd >= 0 else { throw posixError("open \(name)") }
        return fd
    }

    /// Opens `relative` below `base` component by component; `nil` when something on the way is missing.
    static func openDirectory(_ base: Int32, relative components: [String]) throws -> Int32? {
        var current = dup(base)
        guard current >= 0 else { throw posixError("dup") }
        for component in components {
            let next = openat(current, component, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
            let code = errno
            close(current)
            if next < 0 {
                if code == ENOENT || code == ENOTDIR || code == ELOOP { return nil }
                errno = code
                throw posixError("open \(component)")
            }
            current = next
        }
        return current
    }

    static func entryNames(_ directory: Int32) throws -> [String] {
        let copy = dup(directory)
        guard copy >= 0, let stream = fdopendir(copy) else {
            if copy >= 0 { close(copy) }
            throw posixError("read directory")
        }
        defer { closedir(stream) }
        rewinddir(stream)
        var names: [String] = []
        while let entry = readdir(stream) {
            let name = withUnsafePointer(to: entry.pointee.d_name) {
                $0.withMemoryRebound(to: CChar.self, capacity: MemoryLayout.size(ofValue: entry.pointee.d_name)) { String(cString: $0) }
            }
            if name != ".", name != ".." { names.append(name) }
        }
        return names.sorted()
    }

    static func lstatAt(_ directory: Int32, _ name: String) -> stat? {
        var info = stat()
        return fstatat(directory, name, &info, AT_SYMLINK_NOFOLLOW) == 0 ? info : nil
    }

    static func entry(_ info: stat, directory: Int32, name: String) -> LabEntry {
        let type = info.st_mode & S_IFMT
        let kind: LabEntry.Kind = switch type {
        case S_IFREG: .file
        case S_IFDIR: .directory
        case S_IFLNK: .symlink
        default: .other
        }
        #if canImport(Darwin)
        let mtime = Int64(info.st_mtimespec.tv_sec) * 1_000_000_000 + Int64(info.st_mtimespec.tv_nsec)
        #else
        let mtime = Int64(info.st_mtim.tv_sec) * 1_000_000_000 + Int64(info.st_mtim.tv_nsec)
        #endif
        var target: String?
        if kind == .symlink {
            var buffer = [CChar](repeating: 0, count: 4096)
            let count = readlinkat(directory, name, &buffer, buffer.count - 1)
            if count >= 0 { target = String(decoding: buffer[0..<count].map { UInt8(bitPattern: $0) }, as: UTF8.self) }
        }
        return LabEntry(
            kind: kind, size: kind == .file ? Int64(info.st_size) : 0, mode: UInt16(info.st_mode & 0o7777), uid: UInt32(info.st_uid),
            mtime: kind == .directory ? 0 : mtime, target: target
        )
    }

    // MARK: Walk

    /// Every entry below `rootPath` (not the root itself), keyed by `LabPath.key`, leaving out `excludes`
    /// (paths relative to the root).
    static func walk(_ rootPath: String, root: LabRoot, excludes: Set<String>, into manifest: inout LabManifest) throws {
        let fd = try openDirectory(rootPath)
        defer { close(fd) }
        try walk(fd, prefix: "", root: root, excludes: excludes, into: &manifest)
    }

    private static func walk(_ directory: Int32, prefix: String, root: LabRoot, excludes: Set<String>, into manifest: inout LabManifest) throws {
        for name in try entryNames(directory) {
            let relative = prefix + name
            guard !excludes.contains(relative), let info = lstatAt(directory, name) else { continue }
            let entry = entry(info, directory: directory, name: name)
            manifest[LabPath(root: root, path: relative).key] = entry
            guard manifest.count <= maxEntries else {
                throw SandvaultError.io("more than \(maxEntries) files below \(root.displayName); add excludes for large folders")
            }
            if entry.kind == .directory {
                // A directory that turned into something else between lstat and open is skipped.
                guard let child = try? openDirectory(at: directory, name) else { continue }
                defer { close(child) }
                try walk(child, prefix: relative + "/", root: root, excludes: excludes, into: &manifest)
            }
        }
    }

    // MARK: Clone

    /// Copies `name` from `source` to `destinationName` in `destination` as an APFS clone. With `excludes`
    /// (relative to `name`) directories on the way are recreated and only the rest is cloned.
    static func clone(_ source: Int32, _ name: String, to destination: Int32, as destinationName: String, excludes: [String]) throws {
        guard !excludes.isEmpty else { return try cloneWhole(source, name, to: destination, as: destinationName) }
        guard let info = lstatAt(source, name) else { return }
        guard info.st_mode & S_IFMT == S_IFDIR else { return try cloneWhole(source, name, to: destination, as: destinationName) }
        try makeDirectory(destination, destinationName, like: info)
        let from = try openDirectory(at: source, name)
        defer { close(from) }
        let to = try openDirectory(at: destination, destinationName)
        defer { close(to) }
        for child in try entryNames(from) {
            let below = subExcludes(excludes, child)
            if below == nil { continue }
            try clone(from, child, to: to, as: child, excludes: below ?? [])
        }
    }

    /// `nil` when `child` itself is excluded, else the excludes below it (relative to it).
    static func subExcludes(_ excludes: [String], _ child: String) -> [String]? {
        var result: [String] = []
        for exclude in excludes {
            if exclude == child { return nil }
            if exclude.hasPrefix(child + "/") { result.append(String(exclude.dropFirst(child.count + 1))) }
        }
        return result
    }

    static func cloneWhole(_ source: Int32, _ name: String, to destination: Int32, as destinationName: String) throws {
        #if os(macOS)
        let noFollow: UInt32 = 0x0001 // CLONE_NOFOLLOW
        guard clonefileat(source, name, destination, destinationName, noFollow) == 0 else {
            let code = errno
            if code == ENOENT { return }
            if code == EXDEV || code == ENOTSUP {
                throw SandvaultError.io("cannot clone \(name): the checkpoints are not on the same APFS volume as the sandbox (errno \(code))")
            }
            errno = code
            throw posixError("clone \(name)")
        }
        #else
        try copyTree(source, name, to: destination, as: destinationName)
        #endif
    }

    /// The portable stand-in for `clonefileat` (Linux tests): a plain recursive copy that keeps modes, times
    /// and, as root, owners.
    static func copyTree(_ source: Int32, _ name: String, to destination: Int32, as destinationName: String) throws {
        guard let info = lstatAt(source, name) else { return }
        switch info.st_mode & S_IFMT {
        case S_IFDIR:
            try makeDirectory(destination, destinationName, like: info)
            let from = try openDirectory(at: source, name)
            defer { close(from) }
            let to = try openDirectory(at: destination, destinationName)
            defer { close(to) }
            for child in try entryNames(from) { try copyTree(from, child, to: to, as: child) }
        case S_IFLNK:
            guard let target = entry(info, directory: source, name: name).target else { throw posixError("readlink \(name)") }
            guard symlinkat(target, destination, destinationName) == 0 else { throw posixError("symlink \(destinationName)") }
        case S_IFREG:
            let input = openat(source, name, O_RDONLY | O_NOFOLLOW | O_CLOEXEC)
            guard input >= 0 else { throw posixError("open \(name)") }
            defer { close(input) }
            let output = openat(destination, destinationName, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0o600)
            guard output >= 0 else { throw posixError("create \(destinationName)") }
            defer { close(output) }
            var buffer = [UInt8](repeating: 0, count: 64 * 1024)
            while true {
                let count = read(input, &buffer, buffer.count)
                if count < 0 { if errno == EINTR { continue }; throw posixError("read \(name)") }
                if count == 0 { break }
                var offset = 0
                while offset < count {
                    let written = buffer.withUnsafeBytes { write(output, $0.baseAddress! + offset, count - offset) }
                    if written < 0 { if errno == EINTR { continue }; throw posixError("write \(destinationName)") }
                    offset += written
                }
            }
            if geteuid() == 0 { _ = fchown(output, info.st_uid, info.st_gid) }
            fchmod(output, info.st_mode & 0o7777)
            var times = [timespecMTime(info), timespecMTime(info)]
            futimens(output, &times)
        default:
            return // sockets, fifos and devices are not copied
        }
    }

    static func timespecMTime(_ info: stat) -> timespec {
        #if canImport(Darwin)
        info.st_mtimespec
        #else
        info.st_mtim
        #endif
    }

    /// macOS changes a symlink itself with this flag; Linux has no mode on links and refuses it, and only real
    /// directories reach `fchmodat` here.
    #if canImport(Darwin)
    static let chmodNoFollow = AT_SYMLINK_NOFOLLOW
    #else
    static let chmodNoFollow: Int32 = 0
    #endif

    /// Creates a directory with the owner and mode of `info` (owner only as root).
    static func makeDirectory(_ parent: Int32, _ name: String, like info: stat) throws {
        guard mkdirat(parent, name, 0o700) == 0 || errno == EEXIST else { throw posixError("mkdir \(name)") }
        guard let made = lstatAt(parent, name), made.st_mode & S_IFMT == S_IFDIR else {
            throw SandvaultError.permissionDenied("\(name) exists and is not a directory")
        }
        if geteuid() == 0 { _ = fchownat(parent, name, info.st_uid, info.st_gid, AT_SYMLINK_NOFOLLOW) }
        _ = fchmodat(parent, name, info.st_mode & 0o7777, chmodNoFollow)
    }

    // MARK: Restore

    /// Makes the live directory `live` hold what `checkpoint` holds (`nil`: nothing), leaving `excludes` as they
    /// are. Replaced entries are moved into `trash` (a root-only directory on the same volume) first.
    static func restore(from checkpoint: Int32?, into live: Int32, excludes: [String], trash: Int32) throws {
        var names = Set(try entryNames(live))
        if let checkpoint { names.formUnion(try entryNames(checkpoint)) }
        for name in names.sorted() {
            guard let below = subExcludes(excludes, name) else { continue }
            let saved = checkpoint.flatMap { lstatAt($0, name) }
            if below.isEmpty {
                if lstatAt(live, name) != nil { try moveToTrash(live, name, trash) }
                if let checkpoint, saved != nil { try cloneWhole(checkpoint, name, to: live, as: name) }
                continue
            }
            // Something below is excluded: keep this directory and work inside it.
            let current = lstatAt(live, name)
            if let current, current.st_mode & S_IFMT != S_IFDIR { try moveToTrash(live, name, trash) }
            let savedDirectory = saved.flatMap { $0.st_mode & S_IFMT == S_IFDIR ? $0 : nil }
            if current == nil || current!.st_mode & S_IFMT != S_IFDIR {
                // Recreated only to hold excluded content; there is none when it was missing.
                guard let savedDirectory else {
                    if let checkpoint, saved != nil { try cloneWhole(checkpoint, name, to: live, as: name) }
                    continue
                }
                try makeDirectory(live, name, like: savedDirectory)
            } else if let savedDirectory {
                if geteuid() == 0 { _ = fchownat(live, name, savedDirectory.st_uid, savedDirectory.st_gid, AT_SYMLINK_NOFOLLOW) }
                _ = fchmodat(live, name, savedDirectory.st_mode & 0o7777, chmodNoFollow)
            }
            let liveChild = try openDirectory(at: live, name)
            defer { close(liveChild) }
            let savedChild = savedDirectory == nil ? nil : try checkpoint.map { try openDirectory(at: $0, name) }
            defer { if let savedChild { close(savedChild) } }
            try restore(from: savedChild, into: liveChild, excludes: below, trash: trash)
        }
    }

    static func moveToTrash(_ directory: Int32, _ name: String, _ trash: Int32) throws {
        guard renameat(directory, name, trash, UUID().uuidString) == 0 else { throw posixError("move \(name) aside") }
    }

    // MARK: Files

    /// A regular file below `base` by relative path, never through a symlink; `nil` when missing or not a
    /// regular file. At most `maxBytes` are read.
    static func readFile(_ base: Int32, relative path: String, maxBytes: Int) throws -> (data: Data, size: Int64)? {
        let parts = path.split(separator: "/").map(String.init)
        guard let last = parts.last, let directory = try openDirectory(base, relative: Array(parts.dropLast())) else { return nil }
        defer { close(directory) }
        let fd = openat(directory, last, O_RDONLY | O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK)
        guard fd >= 0 else { return nil }
        defer { close(fd) }
        var info = stat()
        guard fstat(fd, &info) == 0, info.st_mode & S_IFMT == S_IFREG else { return nil }
        var data = Data()
        var buffer = [UInt8](repeating: 0, count: 64 * 1024)
        while data.count < maxBytes {
            let count = read(fd, &buffer, min(buffer.count, maxBytes - data.count))
            if count < 0 { if errno == EINTR { continue }; throw posixError("read \(path)") }
            if count == 0 { break }
            data.append(contentsOf: buffer[0..<count])
        }
        return (data, Int64(info.st_size))
    }

    static func freeBytes(_ path: String) -> Int64? {
        var info = statvfs()
        guard statvfs(path, &info) == 0 else { return nil }
        return Int64(info.f_bavail) * Int64(info.f_frsize)
    }

    static func device(_ path: String) -> UInt64? {
        var info = stat()
        guard lstat(path, &info) == 0 else { return nil }
        return UInt64(info.st_dev)
    }

    static func posixError(_ action: String) -> SandvaultError {
        let code = errno
        if code == ELOOP { return .permissionDenied("\(action): refusing to follow a symlink") }
        if code == EACCES || code == EPERM { return .permissionDenied("\(action) (errno \(code))") }
        return .io("\(action) failed (errno \(code))")
    }
}
