import Foundation
import SandvaultCore

/// Turns `eslogger --format json` lines into `FileActivityEvent`s (D44). Lives in Enforce because the root helper
/// parses and filters before anything leaves root. Unknown events and malformed lines yield `nil`, never an error.
public enum ESLoggerParser {
    /// The event names `activity-record` subscribes to.
    public static let events = ["exec", "open", "close", "create", "write", "rename", "unlink"]

    /// Kernel `FWRITE` in `open.fflag` (eslogger reports fflags, not `O_*` flags).
    static let fwrite = 0x2
    /// `CS_VALID` and `CS_ADHOC` in `codesigning_flags` (`<kern/cs_blobs.h>`).
    static let csValid: UInt32 = 0x1
    static let csAdhoc: UInt32 = 0x2

    /// One event for `uid`: kept when the acting process's effective or real uid matches, else `nil`.
    public static func event(fromLine line: String, uid: UInt32) -> FileActivityEvent? {
        // Cheap pre-check: a line without the uid's digits cannot match, and most system-wide lines do not.
        guard line.hasPrefix("{"), line.contains(String(uid)) else { return nil }
        guard let message = try? JSONDecoder().decode(Message.self, from: Data(line.utf8)) else { return nil }
        let token = message.process.auditToken
        guard token.euid == uid || token.ruid == uid else { return nil }
        return event(from: message)
    }

    static func event(from message: Message) -> FileActivityEvent? {
        guard let timestamp = parseTime(message.time), let pid = message.process.auditToken.pid else { return nil }
        let actor = message.process
        let executable = actor.executable?.path
        let process = executable.map { ($0 as NSString).lastPathComponent } ?? "pid \(pid)"
        func make(_ kind: FileActivityEvent.Kind, _ path: String?, destination: String? = nil, forWriting: Bool = false,
                  modified: Bool = false, arguments: [String] = [], image: Process? = nil, cwd: String? = nil) -> FileActivityEvent? {
            guard let path, !path.isEmpty else { return nil }
            // exec keeps the pid; the signature is the new image's.
            let signed = image ?? actor
            return FileActivityEvent(
                timestamp: timestamp, kind: kind, path: path, destination: destination, pid: pid, process: process,
                executable: executable, forWriting: forWriting, modified: modified, arguments: arguments,
                ppid: actor.originalPPID.flatMap { $0 > 0 ? $0 : nil } ?? actor.ppid, processStart: parseTime(actor.startTime),
                signature: signed.signature, signingID: signed.signingID, cwd: cwd
            )
        }

        let body = message.event
        if let exec = body.exec {
            return make(.exec, exec.target?.executable?.path, arguments: exec.args ?? [], image: exec.target, cwd: exec.cwd?.path)
        }
        if let open = body.open {
            return make(.open, open.file?.path, forWriting: (open.fflag ?? 0) & fwrite != 0)
        }
        if let close = body.close {
            return make(.close, close.target?.path, modified: close.modified ?? false)
        }
        if let create = body.create {
            return make(.create, create.destination?.path)
        }
        if let write = body.write {
            return make(.write, write.target?.path)
        }
        if let rename = body.rename {
            return make(.rename, rename.source?.path, destination: rename.destination?.path)
        }
        if let unlink = body.unlink {
            return make(.delete, unlink.target?.path)
        }
        return nil
    }

    /// `2026-10-10T08:15:02.123456789Z` (nanoseconds; also without fraction or with `+02:00`).
    public static func parseTime(_ text: String?) -> Date? {
        guard let text else { return nil }
        let halves = text.split(separator: "T", maxSplits: 1)
        guard halves.count == 2 else { return nil }
        let date = halves[0].split(separator: "-").compactMap { Int($0) }
        guard date.count == 3 else { return nil }

        var time = halves[1]
        var offset = 0
        if time.hasSuffix("Z") {
            time = time.dropLast()
        } else if let sign = time.lastIndex(where: { $0 == "+" || $0 == "-" }) {
            let zone = time[time.index(after: sign)...].filter { $0 != ":" }
            guard zone.count == 4, let hours = Int(zone.prefix(2)), let minutes = Int(zone.suffix(2)) else { return nil }
            offset = (hours * 3600 + minutes * 60) * (time[sign] == "-" ? -1 : 1)
            time = time[..<sign]
        } else {
            return nil
        }
        let clock = time.split(separator: ":")
        guard clock.count == 3, let hour = Int(clock[0]), let minute = Int(clock[1]), let seconds = Double(clock[2]) else { return nil }
        let days = daysFromCivil(year: date[0], month: date[1], day: date[2])
        return Date(timeIntervalSince1970: Double(days * 86_400 + hour * 3600 + minute * 60 - offset) + seconds)
    }

    /// Days since 1970-01-01 for a proleptic Gregorian date (H. Hinnant's algorithm).
    static func daysFromCivil(year: Int, month: Int, day: Int) -> Int {
        let y = month <= 2 ? year - 1 : year
        let era = (y >= 0 ? y : y - 399) / 400
        let yearOfEra = y - era * 400
        let dayOfYear = (153 * (month > 2 ? month - 3 : month + 9) + 2) / 5 + day - 1
        let dayOfEra = yearOfEra * 365 + yearOfEra / 4 - yearOfEra / 100 + dayOfYear
        return era * 146_097 + dayOfEra - 719_468
    }

    // MARK: - eslogger's JSON (only the fields we read)

    struct Message: Decodable {
        var time: String?
        var process: Process
        var event: Body
    }

    struct Process: Decodable {
        var auditToken: AuditToken
        var executable: File?
        var ppid: Int32?
        var originalPPID: Int32?
        var startTime: String?
        var signingID: String?
        var teamID: String?
        var platformBinary: Bool?
        var codesigningFlags: UInt32?

        enum CodingKeys: String, CodingKey {
            case auditToken = "audit_token", executable, ppid, originalPPID = "original_ppid", startTime = "start_time"
            case signingID = "signing_id", teamID = "team_id", platformBinary = "is_platform_binary"
            case codesigningFlags = "codesigning_flags"
        }

        /// Every field is optional: these are reconstructed from Apple's `es_process_t` serialisation, not from a
        /// capture of this macOS version, and a missing or renamed one must not cost the event.
        init(from decoder: Decoder) throws {
            let c = try decoder.container(keyedBy: CodingKeys.self)
            auditToken = try c.decode(AuditToken.self, forKey: .auditToken)
            executable = try? c.decodeIfPresent(File.self, forKey: .executable)
            ppid = try? c.decodeIfPresent(Int32.self, forKey: .ppid)
            originalPPID = try? c.decodeIfPresent(Int32.self, forKey: .originalPPID)
            startTime = try? c.decodeIfPresent(String.self, forKey: .startTime)
            signingID = try? c.decodeIfPresent(String.self, forKey: .signingID)
            teamID = try? c.decodeIfPresent(String.self, forKey: .teamID)
            platformBinary = try? c.decodeIfPresent(Bool.self, forKey: .platformBinary)
            codesigningFlags = try? c.decodeIfPresent(UInt32.self, forKey: .codesigningFlags)
        }

        /// Apple for platform binaries, then ad hoc, a developer team, unsigned; `nil` without any of the fields.
        var signature: AskProgram.Signature? {
            if platformBinary == true { return .apple }
            if let flags = codesigningFlags {
                if flags & ESLoggerParser.csAdhoc != 0 { return .adHoc }
                if flags & ESLoggerParser.csValid == 0 { return .unsigned }
            }
            if let team = teamID, !team.isEmpty { return .developer(team: team) }
            if codesigningFlags != nil || signingID != nil { return .developer(team: nil) }
            return nil
        }
    }

    struct AuditToken: Decodable {
        var euid: UInt32?
        var ruid: UInt32?
        var pid: Int32?
    }

    struct File: Decodable {
        var path: String?
    }

    struct Body: Decodable {
        var exec: Exec?
        var open: Open?
        var close: Close?
        var create: Create?
        var write: Target?
        var rename: Rename?
        var unlink: Target?
    }

    struct Exec: Decodable {
        var target: Process?
        var args: [String]?
        var cwd: File?
    }

    struct Open: Decodable {
        var fflag: Int?
        var file: File?
    }

    struct Close: Decodable {
        var modified: Bool?
        var target: File?
    }

    struct Target: Decodable {
        var target: File?
    }

    struct Create: Decodable {
        var destination: Destination?
    }

    struct Rename: Decodable {
        var source: File?
        var destination: Destination?
    }

    /// `{"existing_file": {...}}` or `{"new_path": {"dir": {...}, "filename": "..."}}`.
    struct Destination: Decodable {
        var existingFile: File?
        var newPath: NewPath?

        enum CodingKeys: String, CodingKey {
            case existingFile = "existing_file", newPath = "new_path"
        }

        var path: String? {
            if let path = existingFile?.path { return path }
            guard let directory = newPath?.dir?.path, let name = newPath?.filename else { return nil }
            return directory.hasSuffix("/") ? directory + name : directory + "/" + name
        }
    }

    struct NewPath: Decodable {
        var dir: File?
        var filename: String?
    }
}
