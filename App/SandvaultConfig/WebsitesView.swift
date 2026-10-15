import SandvaultAppModel
import SwiftUI

/// Websites: every website the sandbox used, what is allowed and blocked, and the developer basics (D53).
struct WebsitesView: View {
    let model: AppModel

    var body: some View {
        HostsView(activity: model.activity)
            .navigationTitle(Screen.websites.title)
    }
}
