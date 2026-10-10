import AppKit
import SandvaultAppModel
import SandvaultCore
import SwiftUI

@main
struct SandvaultConfigApp: App {
    @NSApplicationDelegateAdaptor(AppDelegate.self) private var delegate

    var body: some Scene {
        MenuBarExtra {
            MenuBarView(model: AppRuntime.model)
        } label: {
            MenuBarLabel(model: AppRuntime.model)
                .background(WindowOpenerRegistration())
        }
        .menuBarExtraStyle(.window)

        Window(BundleIdentity.displayName, id: MainWindow.id) {
            MainWindow(model: AppRuntime.model)
        }
        .defaultSize(width: 1080, height: 720)
    }
}

/// The one model of the running app, shared by the scenes and the AppKit glue.
@MainActor
enum AppRuntime {
    static let model = AppModel(environment: .live(bundled: .inMainBundle()))
    /// Opens the main window; registered by a view, because only SwiftUI can open a `Window` scene.
    static var openMainWindow: (() -> Void)?
    /// The panels of the waiting asks; the app delegate creates them at launch.
    static var askPanels: AskPanelController?

    /// Brings every waiting ask's panel to the front (Review in the menu bar window).
    static func showAskPanels() {
        askPanels?.showAll()
    }

    static func showMainWindow(_ screen: Screen? = nil) {
        if let screen { model.select(screen) }
        if let openMainWindow {
            openMainWindow()
        } else {
            NSApplication.shared.windows.first { $0.title == BundleIdentity.displayName }?.makeKeyAndOrderFront(nil)
        }
        NSApplication.shared.activate()
    }
}

/// Hands SwiftUI's `openWindow` to the AppKit side (Dock icon click and Dock menu).
struct WindowOpenerRegistration: View {
    @Environment(\.openWindow) private var openWindow

    var body: some View {
        Color.clear
            .onAppear { AppRuntime.openMainWindow = { openWindow(id: MainWindow.id) } }
    }
}

/// Dock icon on or off; the bundle starts as an agent app (LSUIElement), so the menu bar item alone is the default
/// until this runs.
@MainActor
enum DockPresence {
    static func apply(_ show: Bool) {
        NSApplication.shared.setActivationPolicy(show ? .regular : .accessory)
        if show { NSApplication.shared.activate() }
    }
}

@MainActor
final class AppDelegate: NSObject, NSApplicationDelegate {
    func applicationDidFinishLaunching(_ notification: Notification) {
        let model = AppRuntime.model
        AppRuntime.askPanels = AskPanelController(asks: model.asks, notifier: AskNotifier(asks: model.asks))
        model.start()
        if model.settings.preferences.showInDock { DockPresence.apply(true) }
    }

    /// Clicking the Dock icon opens the window when none is visible.
    func applicationShouldHandleReopen(_ sender: NSApplication, hasVisibleWindows flag: Bool) -> Bool {
        if !flag { AppRuntime.showMainWindow() }
        return true
    }

    /// The menu bar item keeps running when the window closes.
    func applicationShouldTerminateAfterLastWindowClosed(_ sender: NSApplication) -> Bool {
        false
    }

    func applicationDockMenu(_ sender: NSApplication) -> NSMenu? {
        let menu = NSMenu()
        let agent = AppRuntime.model.editor.config.handoff.defaultAgent
        menu.addItem(item("Open Shell", #selector(openShell)))
        if agent != .shell { menu.addItem(item("Start \(agent.displayName)", #selector(startDefaultAgent))) }
        menu.addItem(.separator())
        menu.addItem(item("Sandbox…", #selector(showSandbox)))
        menu.addItem(item("Activity…", #selector(showActivity)))
        return menu
    }

    private func item(_ title: String, _ action: Selector) -> NSMenuItem {
        let item = NSMenuItem(title: title, action: action, keyEquivalent: "")
        item.target = self
        return item
    }

    @objc private func openShell() {
        Task { await AppRuntime.model.sandbox.open(.shell) }
    }

    @objc private func startDefaultAgent() {
        let model = AppRuntime.model
        Task { await model.sandbox.open(model.editor.config.handoff.defaultAgent) }
    }

    @objc private func showSandbox() {
        AppRuntime.showMainWindow(.sandbox)
    }

    @objc private func showActivity() {
        AppRuntime.showMainWindow(.activity)
    }

    func applicationWillTerminate(_ notification: Notification) {
        AppRuntime.model.stop()
    }
}

extension BundledTools {
    /// svctl, svctl-helper and sandvault-netd in Contents/MacOS.
    static func inMainBundle() -> BundledTools {
        func path(_ name: String) -> String? {
            Bundle.main.url(forAuxiliaryExecutable: name)?.path
        }
        return BundledTools(svctl: path("svctl"), helper: path("svctl-helper"), netd: path("sandvault-netd"))
    }
}
