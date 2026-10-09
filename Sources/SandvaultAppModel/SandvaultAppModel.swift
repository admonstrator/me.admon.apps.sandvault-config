import Observation
import SandvaultCore

/// Model layer of the SwiftUI app (agent E): `@Observable` view models over the library modules,
/// free of SwiftUI and AppKit so it builds and tests on Linux. `App/` holds only views and platform glue.
public enum AppModelInfo {
    public static let refreshInterval: Double = 2
}
