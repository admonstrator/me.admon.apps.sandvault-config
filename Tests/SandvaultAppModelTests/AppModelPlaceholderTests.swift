import Testing
@testable import SandvaultAppModel

@Suite struct AppModelPlaceholderTests {
    @Test func moduleLinks() {
        #expect(AppModelInfo.refreshInterval > 0)
    }
}
