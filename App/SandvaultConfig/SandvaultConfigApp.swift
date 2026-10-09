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
}

@MainActor
final class AppDelegate: NSObject, NSApplicationDelegate {
    private var askPanels: AskPanelController?

    func applicationDidFinishLaunching(_ notification: Notification) {
        let model = AppRuntime.model
        askPanels = AskPanelController(asks: model.asks, notifier: AskNotifier(asks: model.asks))
        model.start()
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
