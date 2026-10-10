import Foundation
import SandvaultCore

/// Paths as people read them: the host user's home as `~`, the sandbox user's as `~sandvault-<name>`.
public enum PathDisplay {
    public static func short(_ path: String, _ environment: SandvaultEnvironment) -> String {
        if let rest = below(environment.hostHome, path) { return "~" + rest }
        if let rest = below(environment.sandvaultHome, path) { return "~\(environment.sandvaultUser)" + rest }
        return path
    }

    /// `""` for `base` itself, `/x/y` for a path below it, `nil` otherwise.
    static func below(_ base: String, _ path: String) -> String? {
        guard !base.isEmpty, path.hasPrefix(base) else { return nil }
        let rest = String(path.dropFirst(base.count))
        return rest.isEmpty || rest.hasPrefix("/") ? rest : nil
    }

    static func name(_ path: String) -> String {
        path.split(separator: "/").last.map(String.init) ?? path
    }

    static func parent(_ path: String) -> String {
        guard let slash = path.lastIndex(of: "/"), slash != path.startIndex else { return "/" }
        return String(path[..<slash])
    }
}

/// A place whose files deserve attention (D45): keys, logins, keychains, browser profiles, other people's files.
public struct SensitivePlace: Sendable, Equatable, Hashable {
    public enum Kind: String, Sendable, CaseIterable {
        case ssh, keychain, cloudCredentials, gnupg, browserProfile, envFile
        /// A home folder other than the sandbox user's (the host user's included: the sandbox should not be there).
        case otherHome
    }

    public var kind: Kind
    /// `your SSH keys and settings`; fits after "Read".
    public var title: String
    /// One sentence on why it matters.
    public var explanation: String

    public init(_ kind: Kind, _ title: String, _ explanation: String) {
        self.kind = kind
        self.title = title
        self.explanation = explanation
    }

    /// Credential files by their place relative to a home folder.
    static let credentials: [(suffix: [String], title: String, explanation: String)] = [
        ([".aws"], "your AWS credentials", "Whoever has them can use your AWS account."),
        ([".config", "gcloud"], "your Google Cloud credentials", "Whoever has them can use your Google Cloud account."),
        ([".azure"], "your Azure credentials", "Whoever has them can use your Azure account."),
        ([".kube"], "your Kubernetes credentials", "Whoever has them can reach your clusters."),
        ([".docker", "config.json"], "your Docker logins", "Logins for container registries."),
        ([".config", "gh"], "your GitHub CLI login", "Whoever has it can act on GitHub as you."),
        ([".netrc"], "your saved logins (.netrc)", "Passwords for servers, in plain text."),
        ([".git-credentials"], "your saved Git passwords", "Passwords for Git servers, in plain text."),
        ([".npmrc"], "your npm settings", "May hold a login token for the registry."),
        ([".pypirc"], "your PyPI settings", "May hold a login token for the registry."),
    ]

    static let browsers: [[String]] = [
        ["Library", "Application Support", "Google", "Chrome"],
        ["Library", "Application Support", "Chromium"],
        ["Library", "Application Support", "BraveSoftware"],
        ["Library", "Application Support", "Microsoft Edge"],
        ["Library", "Application Support", "Arc"],
        ["Library", "Application Support", "Vivaldi"],
        ["Library", "Application Support", "Firefox"],
        ["Library", "Safari"],
        ["Library", "Cookies"],
    ]

    /// `includeHostHome`: the host user's home counts as another home (file activity); learn mode leaves it out,
    /// because the sandbox asks for folders there all the time.
    public static func classify(_ path: String, environment: SandvaultEnvironment, includeHostHome: Bool = true) -> SensitivePlace? {
        let parts = path.split(separator: "/").map(String.init)
        if parts.contains(".ssh") {
            return SensitivePlace(.ssh, "your SSH keys and settings", "Anyone with these files can log in to your servers as you.")
        }
        if parts.contains(".gnupg") {
            return SensitivePlace(.gnupg, "your GnuPG keys", "Whoever has them can sign and decrypt as you.")
        }
        if contains(parts, ["Library", "Keychains"]) {
            return SensitivePlace(.keychain, "a keychain", "Holds passwords, keys and certificates.")
        }
        for entry in credentials where contains(parts, entry.suffix) {
            return SensitivePlace(.cloudCredentials, entry.title, entry.explanation)
        }
        if browsers.contains(where: { contains(parts, $0) }) {
            return SensitivePlace(.browserProfile, "a browser profile", "Holds cookies, saved passwords and history.")
        }
        if let name = parts.last, isEnvFile(name) {
            return SensitivePlace(.envFile, "a .env file", "Often holds passwords and API keys.")
        }
        if parts.count >= 2, parts[0] == "Users" {
            let user = parts[1]
            if user == environment.hostUser, includeHostHome {
                return SensitivePlace(.otherHome, "your home folder", "Outside the sandbox; the sandbox should not see it.")
            }
            if user != environment.hostUser, user != environment.sandvaultUser, user != "Shared" {
                return SensitivePlace(.otherHome, "the home folder of \(user)", "Another user's files.")
            }
        }
        return nil
    }

    static func isEnvFile(_ name: String) -> Bool {
        guard name == ".env" || name.hasPrefix(".env.") else { return false }
        return !["example", "sample", "template", "dist"].contains { name.hasSuffix(".\($0)") }
    }

    static func contains(_ parts: [String], _ run: [String]) -> Bool {
        guard run.count <= parts.count else { return false }
        return (0...(parts.count - run.count)).contains { Array(parts[$0..<($0 + run.count)]) == run }
    }
}

// MARK: - Summaries

/// What a summary line says the program did.
public enum ActivityAction: String, Sendable, CaseIterable {
    case read, change, create, delete, move, run

    public var verb: String {
        switch self {
        case .read: "Read"
        case .change: "Changed"
        case .create: "Created"
        case .delete: "Deleted"
        case .move: "Moved"
        case .run: "Started"
        }
    }

    public var symbolName: String {
        switch self {
        case .read: "eye"
        case .change: "pencil"
        case .create: "plus"
        case .delete: "trash"
        case .move: "arrow.right"
        case .run: "play.fill"
        }
    }
}

/// The five tiles above the list.
public struct ActivityTiles: Sendable, Equatable {
    public var read = 0
    public var changed = 0
    public var created = 0
    public var deleted = 0
    public var programs = 0

    public init(read: Int = 0, changed: Int = 0, created: Int = 0, deleted: Int = 0, programs: Int = 0) {
        self.read = read
        self.changed = changed
        self.created = created
        self.deleted = deleted
        self.programs = programs
    }
}

/// One sentence of Changes: `Created 2,341 files in node_modules`.
public struct ActivityLine: Identifiable, Sendable, Equatable {
    public var id: String
    public var action: ActivityAction
    /// `Created`.
    public var verb: String
    /// `2,341 files`, `cart.ts`, `your SSH keys and settings`, `git 6 times, node twice`; shown in bold.
    public var object: String
    /// `node_modules`, the last part of the folder; `nil` for one file and for programs.
    public var place: String?
    /// The second line: the path, a few names, or the folder when folded.
    public var detail: String
    /// The folder the files are in (absolute), for Show in Finder.
    public var folder: String?
    public var count: Int
    /// The files behind a folded line, at most `ActivityReport.filesPerLine`.
    public var files: [String]
    public var folded: Bool
    public var sensitive: SensitivePlace?
    public var lastSeen: Date

    public var sentence: String { [verb, object].joined(separator: " ") + (place.map { " in \($0)" } ?? "") }

    /// The files below `folder`, relative to it, for the folded list.
    public var fileNames: [String] {
        guard let folder else { return files }
        return files.map { ActivityReport.relative($0, to: folder) }
    }
}

/// Everything one program did, as Changes shows it.
public struct ProcessActivity: Identifiable, Sendable, Equatable {
    public var process: String
    public var firstSeen: Date
    public var lastSeen: Date
    public var eventCount: Int
    public var lines: [ActivityLine]
    /// The folder with the most files, for Show in Finder.
    public var folder: String?

    public var id: String { process }
    public var sensitive: Bool { lines.contains { $0.sensitive != nil } }
}

/// Changes and the tiles, computed from the stored events (D45).
public struct ActivityReport: Sendable, Equatable {
    public var tiles: ActivityTiles
    public var groups: [ProcessActivity]

    /// More files than this in one line are folded into the folder.
    public static let foldAbove = 12
    public static let filesPerLine = 200
    /// Folders whose contents are written in bulk; files below them are counted at the folder.
    public static let bulkFolders: Set<String> = [
        "node_modules", ".git", ".build", "DerivedData", "__pycache__", ".venv", "venv", "site-packages", "target", ".next",
        ".cache", "Pods", ".gradle", ".npm", ".pnpm-store", ".cargo",
    ]

    public init(tiles: ActivityTiles = ActivityTiles(), groups: [ProcessActivity] = []) {
        self.tiles = tiles
        self.groups = groups
    }

    public static func make(_ events: [FileActivityEvent], environment: SandvaultEnvironment) -> ActivityReport {
        var tiles = Sets()
        var byProcess: [String: [FileActivityEvent]] = [:]
        for event in events {
            byProcess[event.process, default: []].append(event)
            tiles.add(event)
        }
        let groups = byProcess.map { process, events in group(process, events, environment) }
            .sorted { ($0.sensitive ? 1 : 0, $0.lastSeen, $1.process) > ($1.sensitive ? 1 : 0, $1.lastSeen, $0.process) }
        return ActivityReport(tiles: tiles.tiles, groups: groups)
    }

    /// Distinct paths per tile; a file created and then written counts as created only.
    struct Sets {
        var read: Set<String> = []
        var changed: Set<String> = []
        var created: Set<String> = []
        var deleted: Set<String> = []
        var programs: Set<String> = []

        mutating func add(_ event: FileActivityEvent) {
            guard let action = ActivityReport.action(event) else { return }
            switch action {
            case .read: read.insert(event.path)
            case .change, .move: changed.insert(event.path)
            case .create: created.insert(event.path)
            case .delete: deleted.insert(event.path)
            case .run: programs.insert(event.path)
            }
        }

        var tiles: ActivityTiles {
            ActivityTiles(read: read.count, changed: changed.subtracting(created).count, created: created.count, deleted: deleted.count, programs: programs.count)
        }
    }

    /// What an event counts as; `nil` for opens for writing and closes without changes.
    public static func action(_ event: FileActivityEvent) -> ActivityAction? {
        switch event.kind {
        case .exec: .run
        case .open: event.forWriting ? nil : .read
        case .close: event.modified ? .change : nil
        case .write: .change
        case .create: .create
        case .rename: .move
        case .delete: .delete
        }
    }

    /// The folder a file is counted at: below a bulk folder the bulk folder, else its own folder.
    public static func anchor(of path: String) -> String {
        let parts = path.split(separator: "/").map(String.init)
        if let index = parts.firstIndex(where: bulkFolders.contains), index < parts.count - 1 {
            return "/" + parts[...index].joined(separator: "/")
        }
        return PathDisplay.parent(path)
    }

    struct Bucket {
        var action: ActivityAction
        var anchor: String
        var sensitive: SensitivePlace?
        var paths: [String] = []
        var seen: Set<String> = []
        var lastSeen: Date
    }

    static func group(_ process: String, _ events: [FileActivityEvent], _ environment: SandvaultEnvironment) -> ProcessActivity {
        var buckets: [String: Bucket] = [:]
        var runs: [FileActivityEvent] = []
        let created = Set(events.filter { $0.kind == .create }.map(\.path))
        for event in events {
            guard let action = action(event) else { continue }
            if action == .run {
                runs.append(event)
                continue
            }
            if action == .change, created.contains(event.path) { continue }
            let sensitive = SensitivePlace.classify(event.path, environment: environment)
            let anchor = anchor(of: event.path)
            let key = "\(action.rawValue) \(sensitive?.kind.rawValue ?? "") \(anchor)"
            var bucket = buckets[key] ?? Bucket(action: action, anchor: anchor, sensitive: sensitive, lastSeen: event.timestamp)
            if bucket.seen.insert(event.path).inserted { bucket.paths.append(event.path) }
            bucket.lastSeen = max(bucket.lastSeen, event.timestamp)
            buckets[key] = bucket
        }
        var lines = buckets.map { key, bucket in line(key, bucket, environment) }
        if let run = runLine(runs) { lines.append(run) }
        lines.sort { ($0.sensitive == nil ? 0 : 1, $0.lastSeen, $1.id) > ($1.sensitive == nil ? 0 : 1, $1.lastSeen, $0.id) }
        let folder = lines.filter { $0.action != .run }.max { ($0.count, $1.id) < ($1.count, $0.id) }?.folder
        return ProcessActivity(
            process: process, firstSeen: events.map(\.timestamp).min() ?? Date(timeIntervalSince1970: 0),
            lastSeen: events.map(\.timestamp).max() ?? Date(timeIntervalSince1970: 0), eventCount: events.count, lines: lines, folder: folder
        )
    }

    static func line(_ key: String, _ bucket: Bucket, _ environment: SandvaultEnvironment) -> ActivityLine {
        let count = bucket.paths.count
        let folded = count > foldAbove
        let object: String
        let place: String?
        if let sensitive = bucket.sensitive {
            object = sensitive.title
            place = nil
        } else if count == 1 {
            object = PathDisplay.name(bucket.paths[0])
            place = nil
        } else {
            object = "\(Format.grouped(count)) files"
            place = PathDisplay.name(bucket.anchor)
        }
        let detail: String
        if count == 1 {
            detail = PathDisplay.short(bucket.paths[0], environment)
        } else if folded {
            detail = PathDisplay.short(bucket.anchor, environment)
        } else {
            detail = names(bucket.paths.map { relative($0, to: bucket.anchor) })
        }
        return ActivityLine(
            id: key, action: bucket.action, verb: bucket.action.verb, object: object, place: place, detail: detail, folder: bucket.anchor,
            count: count, files: Array(bucket.paths.prefix(filesPerLine)), folded: folded, sensitive: bucket.sensitive, lastSeen: bucket.lastSeen
        )
    }

    /// `Started git 6 times, node twice` with the command lines below.
    static func runLine(_ runs: [FileActivityEvent]) -> ActivityLine? {
        guard let last = runs.map(\.timestamp).max() else { return nil }
        var counts: [String: Int] = [:]
        var order: [String] = []
        var commands: [String] = []
        for run in runs {
            let name = PathDisplay.name(run.path)
            if counts[name] == nil { order.append(name) }
            counts[name, default: 0] += 1
            let command = commandLine(run)
            if !commands.contains(command) { commands.append(command) }
        }
        let programs = order.sorted { (counts[$0]!, $1) > (counts[$1]!, $0) }.map { name in
            switch counts[name]! {
            case 1: name
            case 2: "\(name) twice"
            case let n: "\(name) \(n) times"
            }
        }
        return ActivityLine(
            id: "run", action: .run, verb: ActivityAction.run.verb, object: list(programs), place: nil, detail: names(commands),
            folder: nil, count: runs.count, files: [], folded: false, sensitive: nil, lastSeen: last
        )
    }

    /// `git status`: the program name and its first two arguments.
    static func commandLine(_ event: FileActivityEvent) -> String {
        let name = PathDisplay.name(event.path)
        let arguments = event.arguments.dropFirst().prefix(2)
        return ([name] + arguments).joined(separator: " ")
    }

    static func relative(_ path: String, to folder: String) -> String {
        PathDisplay.below(folder, path).map { String($0.dropFirst()) } ?? path
    }

    /// `a, b, c, d` or `a, b, c and 60 more`.
    static func names(_ items: [String]) -> String {
        guard items.count > 4 else { return items.joined(separator: ", ") }
        return items.prefix(3).joined(separator: ", ") + " and \(Format.grouped(items.count - 3)) more"
    }

    /// `a`, `a and b`, `a, b and c`.
    static func list(_ items: [String]) -> String {
        guard items.count > 1 else { return items.first ?? "" }
        return items.dropLast().joined(separator: ", ") + " and " + items.last!
    }
}

/// One row of Everything: the raw event in plain words.
public struct ActivityEventLine: Identifiable, Sendable, Equatable {
    public var id: UUID
    public var time: Date
    public var process: String
    /// `Opened for writing`, `Closed, changed`.
    public var text: String
    public var path: String
    public var action: ActivityAction?
    public var sensitive: Bool

    public init(_ event: FileActivityEvent, environment: SandvaultEnvironment) {
        id = event.id
        time = event.timestamp
        process = event.process
        text = Self.describe(event)
        action = ActivityReport.action(event)
        sensitive = SensitivePlace.classify(event.path, environment: environment) != nil
        switch event.kind {
        case .exec:
            path = event.arguments.isEmpty ? PathDisplay.short(event.path, environment) : event.arguments.joined(separator: " ")
        case .rename:
            path = PathDisplay.short(event.path, environment) + (event.destination.map { " → " + PathDisplay.short($0, environment) } ?? "")
        default:
            path = PathDisplay.short(event.path, environment)
        }
    }

    public static func describe(_ event: FileActivityEvent) -> String {
        switch event.kind {
        case .exec: "Started"
        case .open: event.forWriting ? "Opened for writing" : "Opened for reading"
        case .close: event.modified ? "Closed, changed" : "Closed"
        case .create: "Created"
        case .write: "Wrote to"
        case .rename:
            if let destination = event.destination, PathDisplay.parent(destination) == PathDisplay.parent(event.path) { "Renamed" } else { "Moved" }
        case .delete: "Deleted"
        }
    }
}
