import Foundation
import SandvaultCore
import Testing
@testable import SandvaultAppModel

/// A lab helper in memory: answers from a script and records what was asked.
final class FakeLab: LabService, @unchecked Sendable {
    let requests = Locked<[LabRequest]>([])
    let session = Locked<LabSession?>(nil)
    let comparison = Locked(LabComparison(from: 0, to: nil, changes: []))
    let files = Locked<[Int?: String]>([:])
    let records = Locked<[ConnectionRecord]>([])

    func send(_ request: LabRequest) async throws -> LabResponse {
        requests.mutate { $0.append(request) }
        switch request {
        case .status: return LabResponse(ok: true, message: "", session: session.get(), freeBytes: 50 << 30)
        case .start(let settings):
            let start = LabCheckpoint(id: 0, parent: nil, takenAt: Date(timeIntervalSince1970: 1_800_000_000), reason: .start, label: "Start")
            session.set(LabSession(startedAt: start.takenAt, settings: settings, roots: [.home, .workspace], checkpoints: [start], nextID: 1))
            return LabResponse(ok: true, message: "", session: session.get(), checkpoint: start)
        case .checkpoint(let reason, let label, _):
            let taken: LabCheckpoint? = session.mutate { session in
                guard var current = session else { return nil }
                let checkpoint = LabCheckpoint(
                    id: current.nextID, parent: current.head, takenAt: Date(timeIntervalSince1970: 1_800_000_060), reason: reason,
                    label: label ?? "Automatic", created: 1
                )
                current.checkpoints.append(checkpoint)
                current.head = checkpoint.id
                current.nextID += 1
                session = current
                return checkpoint
            }
            return LabResponse(ok: true, message: "", session: session.get(), checkpoint: taken)
        case .compare(let from, let to):
            var result = comparison.get()
            result.from = from
            result.to = to
            return LabResponse(ok: true, message: "", session: session.get(), comparison: result)
        case .file(let path, let at):
            let text = files.get()[at]
            return LabResponse(ok: true, message: "", file: LabFileContent(path: path, at: at, exists: text != nil, size: Int64(text?.utf8.count ?? 0), text: text))
        case .rewind(let id):
            session.mutate { $0?.head = id }
            return LabResponse(ok: true, message: "", session: session.get())
        case .finish:
            session.set(nil)
            return LabResponse(ok: true, message: "")
        }
    }

    func connections(since date: Date) async -> [ConnectionRecord] {
        records.get().filter { $0.timestamp >= date }
    }
}

@MainActor @Suite struct LabModelTests {
    let world = TestWorld()
    let lab = FakeLab()

    func model() -> LabModel {
        let editor = ConfigEditor(store: world.store, netd: world.netd)
        editor.reload()
        return LabModel(service: lab, processes: world.processes, editor: editor, clock: world.clock.clock)
    }

    @Test func startUsesTheConfiguredSettingsAndWatches() async throws {
        defer { world.cleanUp() }
        let model = model()
        await model.refresh()
        #expect(!model.isRunning && !model.isWatching)
        #expect(model.statusLine.hasPrefix("No lab session"))
        await model.setInterval(30)
        await model.start()
        #expect(lab.requests.get().contains(.start(LabSettings(intervalSeconds: 30))))
        #expect(model.isRunning && model.isWatching)
        #expect(model.checkpoints.map(\.label) == ["Start"])
        model.shutDown()
    }

    @Test func findingsAndServersComeFromTheWholeSession() async throws {
        defer { world.cleanUp() }
        let model = model()
        await model.start()
        model.shutDown()
        lab.comparison.set(LabComparison(from: 0, to: nil, changes: [
            LabChange(path: LabPath(root: .home, path: ".zshrc"), kind: .changed, old: LabEntry(kind: .file, size: 1), new: LabEntry(kind: .file, size: 2)),
            LabChange(path: LabPath(root: .home, path: "x.txt"), kind: .created, old: nil, new: LabEntry(kind: .file, size: 2)),
        ]))
        lab.records.set([record("api.example", .allowed, at: Date(timeIntervalSince1970: 1_800_000_010))])
        await model.refresh()
        model.shutDown()
        #expect(model.findings.map(\.kind) == [.shellStartup])
        #expect(model.servers.map(\.host) == ["api.example"])
        #expect(model.statusLine.contains("2 changes since the start"))
    }

    @Test func markRewindAndFinish() async throws {
        defer { world.cleanUp() }
        let model = model()
        await model.start()
        model.shutDown()
        model.markLabel = "after npm install"
        await model.mark()
        #expect(model.checkpoints.first?.label == "after npm install" && model.markLabel.isEmpty)
        await model.rewind(to: 0)
        #expect(model.session?.head == 0 && model.message?.title == "Back at checkpoint 0")
        await model.finish(keep: false)
        #expect(!model.isRunning && !model.isWatching)
        #expect(lab.requests.get().contains(.finish(keep: false)))
    }

    @Test func diffComparesTextBeforeAndAfter() async throws {
        defer { world.cleanUp() }
        let model = model()
        await model.start()
        model.shutDown()
        lab.files.set([0: "a\nb\n", nil: "a\nc\n"])
        await model.compareWithNow(0)
        let change = LabChange(path: LabPath(root: .home, path: ".zshrc"), kind: .changed, old: LabEntry(kind: .file), new: LabEntry(kind: .file))
        await model.showDiff(change)
        let lines = try #require(model.diff?.lines)
        #expect(lines.map(\.kind) == [.context, .removed, .added])
    }

    @Test func automaticCheckpointsWaitForUserActions() async throws {
        defer { world.cleanUp() }
        let model = model()
        await model.start()
        model.shutDown()
        await model.autoCheckpoint(.checkpoint(reason: .interval, label: nil, onlyIfChanged: true))
        #expect(model.checkpoints.count == 2)
        #expect(model.summary(model.checkpoints[0]) == "1 new")
    }

    @Test func unavailableOffMacOS() async {
        defer { world.cleanUp() }
        let editor = ConfigEditor(store: world.store, netd: world.netd)
        let model = LabModel(service: UnavailableLab(), processes: world.processes, editor: editor, clock: world.clock.clock)
        await model.refresh()
        #expect(!model.availability.isAvailable)
    }
}
