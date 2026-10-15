import SwiftUI
import TipKit

// Tips for newcomers (D53). They show in Easy and Advanced only: every place that shows one checks
// `model.mode != .expert`. `Tips.configure()` runs once in `SandvaultConfigApp.init`.

/// Home, above the protection picker.
struct ProtectionTip: Tip {
    var title: Text { Text("Ask is the safe choice") }

    var message: Text? {
        Text("New websites wait for your answer. Watch lets everything through but lists it. Block All cuts the network.")
    }

    var image: Image? { Image(systemName: "checkmark.shield") }
}

/// Home, while the developer basics apply.
struct DeveloperBasicsTip: Tip {
    var title: Text { Text("Developer basics are already allowed") }

    var message: Text? {
        Text("GitHub, npm, Python packages, Homebrew and AI services work right away. Change the list in Settings › Websites.")
    }

    var image: Image? { Image(systemName: "shippingbox") }
}

/// The mode pill at the bottom of the sidebar.
struct ModeTip: Tip {
    var title: Text { Text("Want to see more?") }

    var message: Text? {
        Text("Advanced adds Activity, the Sandbox page and Tools. Click here to change the mode.")
    }

    var image: Image? { Image(systemName: "slider.horizontal.3") }
}
