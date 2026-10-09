import AppKit

@MainActor
enum FolderPicker {
    /// An open panel for one folder; `nil` when cancelled.
    static func chooseRepository() -> String? {
        NSApplication.shared.activate()
        let panel = NSOpenPanel()
        panel.canChooseDirectories = true
        panel.canChooseFiles = false
        panel.allowsMultipleSelection = false
        panel.prompt = "Choose"
        panel.message = "Choose a repository to hand off to an agent in the sandbox."
        guard panel.runModal() == .OK else { return nil }
        return panel.url?.path
    }
}
