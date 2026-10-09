import Foundation
import SandvaultCore
import SandvaultObserve
import Testing
@testable import SandvaultAppModel

@MainActor
@Suite struct ProcessesModelTests {
    static let sessionA = "6F1C8D2E-0000-4000-8000-00000000000A"

    static var snapshot: ProcessSnapshot {
        let processes = [
            process(100, ppid: 1, command: "-zsh", session: sessionA),
            process(101, ppid: 100, command: "node /opt/homebrew/bin/claude", session: sessionA),
            process(102, ppid: 101, command: "/bin/sleep 60", session: sessionA),
            process(200, ppid: 1, command: "/usr/bin/python3 server.py"),
        ]
        let session = SandboxSession(id: sessionA, rootPID: 100, processCount: 3, command: "claude", elapsedSeconds: 125)
        return ProcessSnapshot(processes: processes, sessions: [session], helpers: [], environmentReadable: true)
    }

    @Test func treeRowsAndSessionGroups() async {
        let world = TestWorld()
        defer { world.cleanUp() }
        world.processes.snapshotResult.set(.success(Self.snapshot))
        let model = ProcessesModel(source: world.processes, control: world.processes)
        await model.refresh()

        #expect(model.rows.map(\.pid) == [100, 101, 102, 200])
        #expect(model.rows.map(\.depth) == [0, 1, 2, 0])
        #expect(model.rows[1].name == "claude")
        #expect(model.rows[2].indentedName == "    sleep")
        #expect(model.rows[2].label == "    sleep")
        let ping = ProcessRow(SandboxProcess(pid: 7, ppid: 1, user: "root", realUser: "sandvault-alice", command: "ping x"), depth: 1)
        #expect(ping.label == "  ping (root)")
        #expect(model.processCount == 4)
        #expect(model.sessionCount == 1)

        let groups = model.sessionGroups
        #expect(groups.map(\.id) == [Self.sessionA, SessionGroup.unassignedID])
        #expect(groups[0].rows.map(\.pid) == [100, 101, 102])
        #expect(groups[0].title == "claude · 6f1c8d2e · 2m 05s")
        #expect(groups[1].rows.map(\.pid) == [200])
        #expect(groups[1].title == "Without session")
    }

    @Test func actionsReportAndRefresh() async {
        let world = TestWorld()
        defer { world.cleanUp() }
        world.processes.snapshotResult.set(.success(Self.snapshot))
        let model = ProcessesModel(source: world.processes, control: world.processes)

        await model.terminate(102)
        #expect(model.message == UserMessage(kind: .success, title: "Sent SIGTERM to pid 102", id: model.message!.id))
        await model.throttle(101, nice: 15, background: true)
        await model.terminateSession(Self.sessionA, force: true)
        await model.terminateAll()
        #expect(world.processes.actions.get() == [
            "terminate 102 force=false", "throttle 101 nice=15 background=true", "session \(Self.sessionA)", "all",
        ])
        #expect(model.message?.title == "Ended 3 sandbox processes")
        #expect(world.processes.snapshotCalls.get() == 4)
    }

    @Test func incompleteReportsBecomeErrors() async {
        let world = TestWorld()
        defer { world.cleanUp() }
        world.processes.report.set(ControlReport(
            action: "terminate-all", targets: [10, 11],
            steps: [ControlStep(command: "sudo -n /usr/bin/pkill -9 -u sandvault-alice", ok: false, detail: "a password is required")],
            remaining: [11]
        ))
        let model = ProcessesModel(source: world.processes, control: world.processes)
        await model.terminateAll()
        #expect(model.message?.kind == .error)
        #expect(model.message?.title == "Ended 2 sandbox processes (incomplete)")
        #expect(model.message?.detail == "sudo -n /usr/bin/pkill -9 -u sandvault-alice: a password is required\nstill running: 11")
    }

    @Test func aFailingSnapshotIsKeptAsRefreshError() async {
        let world = TestWorld()
        defer { world.cleanUp() }
        world.processes.snapshotResult.set(.failure(.commandNotRunnable("/bin/ps", "missing")))
        let model = ProcessesModel(source: world.processes, control: world.processes)
        await model.refresh()
        #expect(model.refreshError?.kind == .error)
        #expect(model.message == nil)
        #expect(model.rows.isEmpty)
    }
}
