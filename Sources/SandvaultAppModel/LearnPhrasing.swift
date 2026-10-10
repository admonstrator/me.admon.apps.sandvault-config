import Foundation
import SandvaultCore

/// One learn mode suggestion in plain words (D46): who wanted what where, why it matters, at most two ways to
/// allow it, and the raw lines for Details.
public struct LearnCard: Identifiable, Sendable, Equatable {
    public enum Kind: String, Sendable {
        case folder, file, sensitive, program, service
    }

    public var id: String { suggestion.id }
    public var suggestion: RuleSuggestion
    public var kind: Kind
    /// `claude wanted to create and change files in`; the sentence up to the place.
    public var lead: String
    /// `~/Documents/Notes`, `brew`; shown as code. `nil` for named services.
    public var place: String?
    /// `7 times, most recently 10:21:04. The folder is outside the sandbox.`
    public var reason: String
    /// A sensitive place or service: the reason is shown in red and Keep Blocked is the default.
    public var warning: Bool
    public var choices: [LearnChoice]
    /// The raw `operation target` lines and the rule note.
    public var details: [String]

    public var sentence: String { place.map { "\(lead) \($0)" } ?? lead }

    public static func make(_ suggestion: RuleSuggestion, environment: SandvaultEnvironment) -> LearnCard {
        let actor = actor(suggestion.processes)
        let when = "\(times(suggestion.occurrences)), most recently \(Format.time(suggestion.lastSeen))."
        var details = suggestion.examples
        if let note = suggestion.note { details.append(note) }
        switch suggestion.proposal {
        case .file(let rule):
            let sensitive = SensitivePlace.classify(rule.path, environment: environment, includeHostHome: false)
            let verbs = list(fileVerbs(rule.access, examples: suggestion.examples))
            let folder = rule.match != .literal
            let what = sensitive?.title ?? (folder ? "files" : "the file")
            let lead = "\(actor) wanted to \(verbs) \(what)\(folder ? " in" : sensitive != nil ? ":" : "")"
            let about = sensitive?.explanation ?? placeDescription(rule.path, folder: folder, environment: environment)
            return LearnCard(
                suggestion: suggestion, kind: sensitive != nil ? .sensitive : folder ? .folder : .file, lead: lead,
                place: PathDisplay.short(rule.path, environment), reason: [when, about].compactMap { $0 }.joined(separator: " "),
                warning: sensitive != nil, choices: fileChoices(rule, sensitive: sensitive != nil, environment: environment), details: details
            )
        case .exec(let rule):
            let about = programDescription(rule.path, environment: environment)
            return LearnCard(
                suggestion: suggestion, kind: .program, lead: "\(actor) wanted to start the program", place: PathDisplay.name(rule.path),
                reason: [when, about].joined(separator: " "), warning: false,
                choices: [LearnChoice(title: "Allow This Program", proposal: .exec(rule))], details: details
            )
        case .mach(let rule):
            guard let service = MachService.known(rule.name) else {
                return LearnCard(
                    suggestion: suggestion, kind: .service, lead: "\(actor) wanted to talk to the system service", place: rule.name,
                    reason: "\(when) A service without a known name.", warning: false,
                    choices: [LearnChoice(title: "Allow", proposal: .mach(rule))], details: details
                )
            }
            return LearnCard(
                suggestion: suggestion, kind: service.sensitive ? .sensitive : .service, lead: "\(actor) wanted to \(service.action)",
                place: nil, reason: "\(when) \(service.explanation)", warning: service.sensitive,
                choices: [LearnChoice(title: service.sensitive ? "Allow Anyway" : "Allow", proposal: .mach(rule))], details: details
            )
        }
    }

    /// `claude`, `claude and node`, `claude and 2 others`.
    static func actor(_ processes: [String]) -> String {
        switch processes.count {
        case 0: "A program"
        case 1: processes[0]
        case 2: "\(processes[0]) and \(processes[1])"
        default: "\(processes[0]) and \(processes.count - 1) others"
        }
    }

    static func times(_ count: Int) -> String {
        switch count {
        case ...1: "Once"
        case 2: "Twice"
        default: "\(Format.grouped(count)) times"
        }
    }

    /// `read`, `create`, `change`, `delete` from the denied operations, in that order.
    static func fileVerbs(_ access: FileAccess, examples: [String]) -> [String] {
        let operations = examples.compactMap { $0.split(separator: " ").first.map(String.init) }
        var verbs: [String] = []
        if access != .write || operations.contains(where: { $0.hasPrefix("file-read") }) { verbs.append("read") }
        let writes = operations.filter { $0.hasPrefix("file-write") }
        if writes.contains(where: { $0.hasPrefix("file-write-create") }) { verbs.append("create") }
        if writes.contains(where: { !$0.hasPrefix("file-write-create") && !$0.hasPrefix("file-write-unlink") }) || (access != .read && writes.isEmpty) {
            verbs.append("change")
        }
        if writes.contains(where: { $0.hasPrefix("file-write-unlink") }) { verbs.append("delete") }
        return verbs
    }

    static func list(_ items: [String]) -> String {
        guard items.count > 1 else { return items.first ?? "" }
        return items.dropLast().joined(separator: ", ") + " and " + items.last!
    }

    /// What the place is, for the reason line.
    static func placeDescription(_ path: String, folder: Bool, environment: SandvaultEnvironment) -> String? {
        let noun = folder ? "The folder" : "The file"
        if PathDisplay.below(environment.hostHome, path) != nil { return "\(noun) is in your home folder, outside the sandbox." }
        if PathDisplay.below(environment.sandvaultHome, path) != nil { return "\(noun) is in the sandbox's own home folder." }
        if PathDisplay.below(environment.sharedWorkspace, path) != nil { return "\(noun) is in the shared workspace." }
        if ["/private/tmp", "/private/var/folders", "/tmp"].contains(where: { PathDisplay.below($0, path) != nil }) {
            return "\(noun) is in a temporary folder."
        }
        if ["/System", "/Library", "/usr", "/bin", "/sbin", "/private/etc", "/private/var/db"].contains(where: { PathDisplay.below($0, path) != nil }) {
            return "\(noun) belongs to macOS."
        }
        return nil
    }

    static func programDescription(_ path: String, environment: SandvaultEnvironment) -> String {
        if PathDisplay.below("/opt/homebrew", path) != nil || PathDisplay.below("/usr/local/Cellar", path) != nil {
            return "Installed with Homebrew, in \(PathDisplay.parent(path))."
        }
        if ["/bin", "/sbin", "/usr/bin", "/usr/sbin", "/usr/libexec", "/System"].contains(where: { PathDisplay.below($0, path) != nil }) {
            return "Part of macOS, in \(PathDisplay.parent(path))."
        }
        if PathDisplay.below(environment.hostHome, path) != nil { return "In your home folder, outside the sandbox." }
        return "In \(PathDisplay.short(PathDisplay.parent(path), environment))."
    }

    /// This file or this folder, read only or read and write; a sensitive place gets one choice only.
    static func fileChoices(_ rule: FileRule, sensitive: Bool, environment: SandvaultEnvironment) -> [LearnChoice] {
        if sensitive { return [LearnChoice(title: "Allow Anyway", proposal: .file(rule))] }
        let folder = rule.match != .literal
        var choices = [LearnChoice(title: folder ? "Allow This Folder" : "Allow This File", proposal: .file(rule))]
        if rule.access != .read {
            var readOnly = rule
            readOnly.access = .read
            choices.append(LearnChoice(title: "Allow Reading Only", proposal: .file(readOnly)))
        } else if !folder {
            let parent = PathDisplay.parent(rule.path)
            let isHome = parent == environment.hostHome || parent == environment.sandvaultHome
            if parent.split(separator: "/").count >= 3, !isHome,
               SensitivePlace.classify(parent, environment: environment, includeHostHome: false) == nil {
                var whole = rule
                whole.path = parent
                whole.match = .subpath
                choices.append(LearnChoice(title: "Allow This Folder", proposal: .file(whole)))
            }
        }
        return choices
    }
}

/// One way to allow a suggestion: a button title and the rule it adds.
public struct LearnChoice: Identifiable, Sendable, Equatable {
    public var title: String
    public var proposal: RuleSuggestion.Proposal

    public var id: String { title }

    public init(title: String, proposal: RuleSuggestion.Proposal) {
        self.title = title
        self.proposal = proposal
    }
}

/// System services the sandbox commonly asks for, by their mach names.
public struct MachService: Sendable, Equatable {
    /// `show a notification`; fits after "wanted to".
    public var action: String
    public var explanation: String
    public var sensitive: Bool

    /// Exact names and name prefixes (a trailing `.` or `@` marks a prefix).
    static let table: [(names: [String], service: MachService)] = [
        (["com.apple.SecurityServer", "com.apple.securityd", "com.apple.securityd.xpc", "com.apple.security.agent", "com.apple.security.keychainsyncingoveridsproxy"],
         MachService(action: "use the Keychain", explanation: "The Keychain holds your passwords, keys and certificates.", sensitive: true)),
        (["com.apple.trustd", "com.apple.trustd.agent"],
         MachService(action: "check certificates", explanation: "Many programs need this to verify secure connections.", sensitive: false)),
        (["com.apple.usernoted.client", "com.apple.usernoted.daemon_client", "com.apple.usernotifications."],
         MachService(action: "show a notification", explanation: "Talks to the macOS notification service.", sensitive: false)),
        (["com.apple.pasteboard."],
         MachService(action: "use the clipboard", explanation: "It could read what you copied, passwords included.", sensitive: true)),
        (["com.apple.locationd.", "com.apple.CoreLocation."],
         MachService(action: "find out where this Mac is", explanation: "Location services.", sensitive: true)),
        (["com.apple.coreservices.launchservicesd", "com.apple.lsd."],
         MachService(action: "open apps, files or links", explanation: "LaunchServices opens them outside the sandbox.", sensitive: false)),
        (["com.apple.coreservices.appleevents", "com.apple.ae."],
         MachService(action: "control other apps", explanation: "Apple Events can remote-control apps such as Finder or Terminal.", sensitive: true)),
        (["com.apple.windowserver.active", "com.apple.windowserver."],
         MachService(action: "use the screen", explanation: "The window server draws windows and can read the screen.", sensitive: false)),
        (["com.apple.replayd", "com.apple.screencapture."],
         MachService(action: "record the screen", explanation: "Screen recording.", sensitive: true)),
        (["com.apple.tccd", "com.apple.tccd.system"],
         MachService(action: "check privacy permissions", explanation: "Asks macOS whether access to files, camera or contacts is allowed.", sensitive: false)),
        (["com.apple.audio.coreaudiod", "com.apple.audio.audiohald", "com.apple.audio."],
         MachService(action: "play or record sound", explanation: "The sound system.", sensitive: false)),
        (["com.apple.FSEvents"],
         MachService(action: "watch folders for changes", explanation: "File change notifications.", sensitive: false)),
        (["com.apple.distributed_notifications@", "com.apple.distributed_notifications."],
         MachService(action: "send messages to other apps", explanation: "System-wide app notifications.", sensitive: false)),
        (["com.apple.SystemConfiguration.configd", "com.apple.SystemConfiguration."],
         MachService(action: "read the network settings", explanation: "Network configuration.", sensitive: false)),
        (["com.apple.cfprefsd.daemon", "com.apple.cfprefsd.agent"],
         MachService(action: "read app preferences", explanation: "The preferences service.", sensitive: false)),
        (["com.apple.accountsd.accountmanager", "com.apple.accountsd."],
         MachService(action: "use your accounts", explanation: "The internet accounts set up on this Mac.", sensitive: true)),
        (["com.apple.dock.server", "com.apple.dock."],
         MachService(action: "talk to the Dock", explanation: "The Dock and Mission Control.", sensitive: false)),
        (["com.apple.diskarbitrationd", "com.apple.DiskArbitration."],
         MachService(action: "work with disks", explanation: "Mounting and ejecting disks.", sensitive: false)),
        (["com.apple.bluetoothd", "com.apple.bluetooth."],
         MachService(action: "use Bluetooth", explanation: "Bluetooth devices.", sensitive: false)),
        (["com.apple.speech.", "com.apple.SpeechRecognitionCore."],
         MachService(action: "use speech", explanation: "Speech synthesis and recognition.", sensitive: false)),
    ]

    public static func known(_ name: String) -> MachService? {
        table.first { entry in
            entry.names.contains { $0.hasSuffix(".") || $0.hasSuffix("@") ? name.hasPrefix($0) : name == $0 }
        }?.service
    }
}
