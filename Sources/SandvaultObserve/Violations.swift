import Foundation
import SandvaultCore

/// Parses the unified log (`log show|stream --style ndjson`) into sandbox violations.
public enum ViolationParser {
    /// The `Sandbox: <process>(<pid>) deny(<n>) <operation> [<target>]` part of a message.
    public struct Message: Sendable, Equatable {
        public var process: String
        public var pid: Int32
        public var operation: String
        public var target: String?
        /// N for `N duplicate report(s) for Sandbox: ...`, else 1.
        public var occurrences: Int
    }

    /// One ndjson line. `nil` for non-JSON lines (`Filtering the log data using ...`) and for messages that are
    /// not sandbox denials. `attributedToSandbox` is left `false`; attribution is the caller's job.
    public static func parse(line: String) -> SandboxViolation? {
        guard line.hasPrefix("{"), let entry = try? JSONDecoder().decode(LogEntry.self, from: Data(line.utf8)),
              let text = entry.eventMessage, let timestamp = entry.timestamp.flatMap(parseTimestamp)
        else { return nil }
        let first = String(text.split(separator: "\n", maxSplits: 1, omittingEmptySubsequences: true).first ?? "")
        guard let message = parseMessage(first) else { return nil }
        return SandboxViolation(
            timestamp: timestamp, process: message.process, pid: message.pid, operation: message.operation,
            target: message.target, attributedToSandbox: false, raw: first
        )
    }

    public static func parseMessage(_ text: String) -> Message? {
        var occurrences = 1
        var body = Substring(text.trimmingCharacters(in: .whitespaces))
        if let range = body.range(of: " for Sandbox: "), body[..<range.lowerBound].hasSuffix(" duplicate report") || body[..<range.lowerBound].hasSuffix(" duplicate reports") {
            guard let count = Int(body.prefix(while: \.isNumber)), count > 0 else { return nil }
            occurrences = count
            body = body[body.index(range.lowerBound, offsetBy: 5)...]
        }
        guard body.hasPrefix("Sandbox: ") else { return nil }
        body = body.dropFirst("Sandbox: ".count)

        // `name(pid) deny(1) op target`; the name itself may contain spaces and parentheses.
        guard let verdict = body.range(of: ") deny(") else { return nil }
        let head = body[..<verdict.lowerBound]
        guard let open = head.lastIndex(of: "("), let pid = Int32(head[head.index(after: open)...]) else { return nil }
        let process = String(head[..<open])
        var rest = body[verdict.upperBound...]
        guard let close = rest.firstIndex(of: ")") else { return nil }
        rest = rest[rest.index(after: close)...].drop(while: { $0 == " " })
        let operation = rest.prefix { $0 != " " }
        guard !operation.isEmpty, !process.isEmpty else { return nil }
        let target = rest.dropFirst(operation.count).trimmingCharacters(in: .whitespaces)
        return Message(process: process, pid: pid, operation: String(operation), target: target.isEmpty ? nil : target, occurrences: occurrences)
    }

    /// `2026-10-09 12:00:01.123456+0200` (also `+02:00`, without fraction).
    public static func parseTimestamp(_ text: String) -> Date? {
        let parts = text.split(separator: " ")
        guard parts.count == 2 else { return nil }
        let date = parts[0].split(separator: "-").compactMap { Int($0) }
        guard date.count == 3 else { return nil }

        var time = parts[1]
        var offset = 0
        if let sign = time.lastIndex(where: { $0 == "+" || $0 == "-" }) {
            let zone = time[time.index(after: sign)...].filter { $0 != ":" }
            guard zone.count == 4, let hours = Int(zone.prefix(2)), let minutes = Int(zone.suffix(2)) else { return nil }
            offset = (hours * 3600 + minutes * 60) * (time[sign] == "-" ? -1 : 1)
            time = time[..<sign]
        }
        let clock = time.split(separator: ":")
        guard clock.count == 3, let hour = Int(clock[0]), let minute = Int(clock[1]), let seconds = Double(clock[2]) else { return nil }
        let days = daysFromCivil(year: date[0], month: date[1], day: date[2])
        let epoch = Double(days * 86_400 + hour * 3600 + minute * 60 - offset) + seconds
        return Date(timeIntervalSince1970: epoch)
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

    struct LogEntry: Decodable {
        var timestamp: String?
        var eventMessage: String?
    }
}

extension SandboxViolation {
    /// How many denials this entry stands for: N for `N duplicate reports for Sandbox: ...`, else 1.
    public var occurrences: Int {
        ViolationParser.parseMessage(raw)?.occurrences ?? 1
    }
}

/// Follows sandbox violations in the unified log and attributes them to the sandbox user.
/// Live only: macOS 27 does not store the kernel's sandbox reports, so `log show` would find none.
/// `log` needs an administrator account; the kernel reports the violating pid, not the user,
/// so attribution goes through a cache of the sandbox user's pids.
public struct ViolationMonitor: Sendable {
    public var environment: SandvaultEnvironment
    public var runner: CommandRunner

    public init(environment: SandvaultEnvironment, runner: CommandRunner) {
        self.environment = environment
        self.runner = runner
    }

    /// Live violations until the consumer stops iterating (which terminates `log stream`).
    public func stream() -> AsyncThrowingStream<SandboxViolation, Error> {
        let runner = runner
        let pids = SandboxPIDCache(monitor: ProcessMonitor(environment: environment, runner: runner))
        return AsyncThrowingStream { continuation in
            let task = Task {
                await pids.refresh()
                var deduplicator = Deduplicator()
                do {
                    for try await line in runner.lines(Invocations.logStream) {
                        guard var violation = ViolationParser.parse(line: line), deduplicator.isNew(violation) else { continue }
                        violation.attributedToSandbox = await pids.contains(violation.pid)
                        continuation.yield(violation)
                    }
                    continuation.finish()
                } catch SandvaultError.commandFailed(_, let code, let stderr) {
                    // The streaming runner does not capture stderr; the usual cause is a non-admin account.
                    let detail = stderr.isEmpty ? "`log stream` requires an administrator account" : stderr
                    continuation.finish(throwing: Self.logError(Invocations.logStream, code, detail))
                } catch {
                    continuation.finish(throwing: error)
                }
            }
            continuation.onTermination = { _ in task.cancel() }
        }
    }

    /// Violations of the next `duration`, each handed to `onEach` as it arrives. Ends early if the stream does.
    public func collect(
        for duration: Duration, onEach: @escaping @Sendable (SandboxViolation) -> Void = { _ in }
    ) async throws -> [SandboxViolation] {
        let stream = stream()
        return try await withThrowingTaskGroup(of: [SandboxViolation]?.self) { group in
            group.addTask {
                var seen: [SandboxViolation] = []
                for try await violation in stream {
                    onEach(violation)
                    seen.append(violation)
                }
                return seen
            }
            group.addTask {
                try? await Task.sleep(for: duration)
                return nil
            }
            // Whichever ends first cancels the other; cancelling the consumer ends the stream with what it has.
            var collected: [SandboxViolation] = []
            while let result = try await group.next() {
                if let seen = result { collected = seen }
                group.cancelAll()
            }
            return collected
        }
    }

    /// `30s`, `5m` or `1h`.
    public static func duration(_ text: String) throws -> Duration {
        let factors: [Character: Int] = ["s": 1, "m": 60, "h": 3600]
        guard let unit = text.last, let factor = factors[unit], text.count > 1,
              text.dropLast().allSatisfy({ $0.isASCII && $0.isNumber }), let value = Int(text.dropLast()), value > 0
        else { throw SandvaultError.invalidInput("duration '\(text)' must look like 30s, 5m or 1h") }
        return .seconds(value * factor)
    }

    static func logError(_ invocation: CommandInvocation, _ code: Int32, _ stderr: String) -> SandvaultError {
        if stderr.localizedCaseInsensitiveContains("admin") {
            return .permissionDenied("reading the unified log: \(stderr.trimmingCharacters(in: .whitespacesAndNewlines))")
        }
        return .commandFailed(invocation.description, code, stderr)
    }

    /// Drops an identical message for the same pid within one second (kernel and reporting subsystem
    /// may both report the same denial).
    struct Deduplicator {
        private var recent: [String: Date] = [:]

        mutating func isNew(_ violation: SandboxViolation) -> Bool {
            let key = "\(violation.pid) \(violation.raw)"
            recent = recent.filter { abs($0.value.timeIntervalSince(violation.timestamp)) < 1 }
            if recent[key] != nil { return false }
            recent[key] = violation.timestamp
            return true
        }
    }
}

/// Pids that belonged to the sandbox user at some point while watching. Unknown pids trigger a refresh,
/// at most once per `minInterval`, so a burst of violations costs one `ps`.
actor SandboxPIDCache {
    let monitor: ProcessMonitor
    let minInterval: Duration
    private let clock = ContinuousClock()
    private var known: Set<Int32> = []
    private var lastRefresh: ContinuousClock.Instant?

    init(monitor: ProcessMonitor, minInterval: Duration = .seconds(1)) {
        self.monitor = monitor
        self.minInterval = minInterval
    }

    func contains(_ pid: Int32) async -> Bool {
        if known.contains(pid) { return true }
        if lastRefresh.map({ clock.now - $0 >= minInterval }) ?? true { await refresh() }
        return known.contains(pid)
    }

    func refresh() async {
        lastRefresh = clock.now
        if let processes = try? await monitor.sandboxProcesses() { known.formUnion(processes.map(\.pid)) }
    }
}
