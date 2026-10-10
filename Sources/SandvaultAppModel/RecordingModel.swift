import Foundation
import Observation
import SandvaultCore

/// Settings > Recording: what netd keeps of web traffic (D42, D43), whether the sandbox's files and programs are
/// recorded (D44, D45), how long recordings stay, the space they use, and Clear.
@MainActor @Observable
public final class RecordingModel {
    public private(set) var fileBytes: Int64 = 0
    public private(set) var isClearing = false
    /// Clear… was pressed; the section asks in place before anything is deleted.
    public var confirmingClear = false
    public var message: UserMessage?

    public static let retentionChoices = [1, 7, 30]

    @ObservationIgnored private let editor: ConfigEditor
    @ObservationIgnored private let netd: NetdLink
    @ObservationIgnored private let files: FileActivityModel
    @ObservationIgnored private let firewall: FirewallModel

    public init(editor: ConfigEditor, netd: NetdLink, files: FileActivityModel, firewall: FirewallModel) {
        self.editor = editor
        self.netd = netd
        self.files = files
        self.firewall = firewall
    }

    public var web: WebRecordingSettings { editor.config.network.recording }
    public var activity: ActivityRecordingSettings { editor.config.activity }
    public var inspectionEnabled: Bool { editor.config.network.inspection.enabled }
    public var isBusy: Bool { firewall.isBusy || isClearing }
    /// Why recording files and programs does not run although it is switched on; `nil` otherwise.
    public var recorderProblem: String? {
        switch files.state {
        case .off, .recording: nil
        case .needsFullDiskAccess, .needsHelper, .failed: "\(files.bannerTitle). See Activity > Files & programs."
        }
    }

    /// The web retention; both are set together, so it is the activity one as well.
    public var retentionDays: Int { web.retentionDays }

    /// `1 day`, `7 days`.
    public static func retentionTitle(_ days: Int) -> String {
        Format.count(days, "day")
    }

    // MARK: Web traffic (netd reloads)

    public func setRecordRequests(_ on: Bool) async {
        await editNetwork("Turn recording requests \(on ? "on" : "off")") { $0.requests = on }
    }

    public func setKeepContents(_ on: Bool) async {
        await editNetwork("Turn keeping contents \(on ? "on" : "off")") { $0.contents = on }
    }

    /// The existing inspection switch (CA, sandbox environment), as on Firewall & Proxy.
    public func setInspection(_ on: Bool) async {
        await firewall.setInspection(on)
        message = firewall.message
        firewall.message = nil
    }

    // MARK: Files & programs (the app records; netd is not involved)

    public func setRecordActivity(_ on: Bool) async {
        if on { await files.start() } else { await files.stop() }
        message = files.message
        files.message = nil
    }

    public func setOpenAndClose(_ on: Bool) async {
        await editActivity("Change opening and closing") { $0.openAndClose = on }
    }

    public func setHideSystemFiles(_ on: Bool) async {
        await editActivity("Change hiding system files") { $0.hideSystemFiles = on }
    }

    // MARK: Storage

    /// Sets the retention of web contents and of the activity log.
    public func setRetention(_ days: Int) async {
        do {
            let edit = try await editor.edit { config in
                config.network.recording.retentionDays = days
                config.activity.retentionDays = days
            }
            message = edit.netdReloaded == false ? .info("Saved", detail: netdReloadNote(false)) : nil
        } catch {
            message = UserMessage(error: error, action: "Change how long recordings are kept")
        }
    }

    /// Asks netd for its current size and the recorder for the activity log's.
    public func refreshStorage() async {
        await netd.refreshStatus()
        fileBytes = await files.storageBytes()
    }

    /// `Web 38.0 MB · Files 12.0 MB`.
    public var spaceText: String {
        let web = netd.status?.storedContentBytes.map(Format.bytes) ?? (netd.isConnected ? "unknown" : "unknown, netd is not running")
        return "Web \(web) · Files \(Format.bytes(fileBytes))"
    }

    /// Deletes the kept web contents and the recorded files and programs.
    public func clear() async {
        guard !isClearing else { return }
        isClearing = true
        defer { isClearing = false }
        confirmingClear = false
        var failures: [String] = []
        do {
            try await netd.clearContent()
        } catch {
            failures.append("Web contents: " + ActivityModel.contentError(error))
        }
        await files.clear()
        if let failed = files.message {
            failures.append("Files: " + (failed.detail ?? failed.title))
            files.message = nil
        }
        await refreshStorage()
        message = failures.isEmpty
            ? .success("Recordings cleared")
            : UserMessage(kind: .warning, title: "Clearing was incomplete", detail: failures.joined(separator: "\n"))
    }

    // MARK: -

    private func editNetwork(_ action: String, _ change: (inout WebRecordingSettings) -> Void) async {
        do {
            let edit = try await editor.edit { change(&$0.network.recording) }
            message = edit.netdReloaded == false ? .info("Saved", detail: netdReloadNote(false)) : nil
        } catch {
            message = UserMessage(error: error, action: action)
        }
    }

    private func editActivity(_ action: String, _ change: (inout ActivityRecordingSettings) -> Void) async {
        do {
            try await editor.edit(reloadNetd: false) { change(&$0.activity) }
            message = nil
            await files.settingsChanged()
        } catch {
            message = UserMessage(error: error, action: action)
        }
    }
}
