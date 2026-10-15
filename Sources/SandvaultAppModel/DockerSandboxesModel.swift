import Foundation
import Observation
import SandvaultCore

/// Docker Sandboxes on the Sandbox page (D47): the VMs `sbx ls` reports, attach, stop and delete.
@MainActor @Observable
public final class DockerSandboxesModel {
    public private(set) var state = DockerSandboxesState.notInstalled
    public private(set) var isLoading = false
    public private(set) var busy: Set<String> = []
    public var message: UserMessage?

    @ObservationIgnored private let service: DockerSandboxService
    @ObservationIgnored private let editor: ConfigEditor

    public init(service: DockerSandboxService, editor: ConfigEditor) {
        self.service = service
        self.editor = editor
    }

    public var installed: Bool { state.installed }

    public func refresh() async {
        isLoading = true
        defer { isLoading = false }
        state = await service.state()
    }

    /// The repository a sandbox was handed off from, when this Mac did it.
    public func record(for sandbox: DockerSandbox) -> HandoffRecord? {
        editor.config.repos.last { $0.dockerSandbox == sandbox.name }
    }

    public func open(_ sandbox: DockerSandbox) async {
        let terminal = editor.config.handoff.terminal
        await run(sandbox, "Open \(sandbox.name)") {
            let launch = try await self.service.open(sandbox.name, terminal: terminal)
            return launch.launched
                ? .success("\(sandbox.name) opens in \(terminal.displayName)")
                : UserMessage(kind: .warning, title: "The terminal did not start", detail: launch.command)
        }
    }

    public func stop(_ sandbox: DockerSandbox) async {
        await run(sandbox, "Stop \(sandbox.name)") {
            try await self.service.stop(sandbox.name)
            return .success("Stopped \(sandbox.name)", detail: "Its files and installed packages stay until you delete it.")
        }
    }

    /// Deletes the VM and forgets its hand-off record (sbx removes the `sandbox-<name>` remote with it).
    public func remove(_ sandbox: DockerSandbox) async {
        await run(sandbox, "Delete \(sandbox.name)") {
            try await self.service.remove(sandbox.name)
            try await self.editor.edit(reloadNetd: false) { $0.repos.removeAll { $0.dockerSandbox == sandbox.name } }
            return .success("Deleted \(sandbox.name)")
        }
    }

    /// What deleting loses, for the confirmation.
    public func deleteExplanation(_ sandbox: DockerSandbox) -> String {
        let back = record(for: sandbox).map { " Fetch its commits into \($0.hostPath) first, or they are lost." } ?? ""
        return "The Linux VM, its files and installed packages are removed." + back
    }

    private func run(_ sandbox: DockerSandbox, _ action: String, _ body: @escaping () async throws -> UserMessage) async {
        busy.insert(sandbox.name)
        defer { busy.remove(sandbox.name) }
        do {
            message = try await body()
        } catch {
            message = UserMessage(error: error, action: action)
        }
        state = await service.state()
    }
}

extension DockerSandbox {
    /// `running · claude · ~/git/app`.
    public func summary(home: String) -> String {
        var parts = [status]
        if let agent { parts.append(agent) }
        if let folder = workspaces.first {
            parts.append(folder == home || folder.hasPrefix(home + "/") ? "~" + folder.dropFirst(home.count) : folder)
        }
        return parts.joined(separator: " · ")
    }
}
