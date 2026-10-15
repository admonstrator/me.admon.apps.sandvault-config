import SandvaultAppModel
import SwiftUI

/// Diagnostics: the setup checks and what the app found out about the Mac (D53).
struct DiagnosticsView: View {
    let model: AppModel

    var body: some View {
        OverviewView(model: model)
            .navigationTitle(Screen.diagnostics.title)
    }
}
