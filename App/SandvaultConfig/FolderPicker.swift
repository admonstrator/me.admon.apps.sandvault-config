import AppKit

@MainActor
enum FolderPicker {
    /// An open panel for one folder; `nil` when cancelled.
    static func chooseRepository() -> String? {
        chooseFolder(message: "Choose a repository to hand off to an agent in the sandbox.")
    }

    static func chooseFolder(message: String) -> String? {
        NSApplication.shared.activate()
        let panel = NSOpenPanel()
        panel.canChooseDirectories = true
        panel.canChooseFiles = false
        panel.allowsMultipleSelection = false
        panel.canCreateDirectories = true
        panel.prompt = "Choose"
        panel.message = message
        guard panel.runModal() == .OK else { return nil }
        return panel.url?.path
    }
}
