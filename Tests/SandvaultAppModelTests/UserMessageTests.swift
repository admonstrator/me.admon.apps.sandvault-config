import Foundation
import SandvaultCore
import Testing
@testable import SandvaultAppModel

@Suite struct UserMessageTests {
    @Test func errorsBecomeMessages() {
        let missing = UserMessage(error: SandvaultError.notImplemented("Workflow.handOff"), action: "Hand off")
        #expect(missing.kind == .notAvailable)
        #expect(missing.title == "Not available yet")

        let sudo = UserMessage(error: SandvaultError.permissionDenied("helper sudoers rule missing; run `svctl helper install`"), action: "Apply rules")
        #expect(sudo.kind == .error)
        #expect(sudo.title == "Apply rules failed")
        #expect(sudo.suggestedCommand == "svctl helper install")

        let netd = UserMessage(error: SandvaultError.notInstalled("sandvault-netd is not running (no control socket at /x)"), action: "Answer")
        #expect(netd.suggestedCommand == "svctl netd install")

        let ca = UserMessage(error: SandvaultError.notInstalled("inspection CA (run `svctl ca create`)"), action: "Publish")
        #expect(ca.suggestedCommand == "svctl ca create")

        let platform = UserMessage(error: SandvaultError.unsupportedPlatform("pf"), action: "Apply firewall")
        #expect(platform.kind == .warning)
        #expect(platform.title == "Apply firewall is not supported here")

        let failed = UserMessage(error: SandvaultError.commandFailed("git fetch", 128, "fatal: no remote"), action: "Fetch")
        #expect(failed.detail == "command failed (exit 128): git fetch\nfatal: no remote")
        #expect(failed.suggestedCommand == nil)
    }

    @Test func formatting() {
        #expect(Format.bytes(512) == "512 B")
        #expect(Format.bytes(1_234_567) == "1.2 MB")
        #expect(Format.kibibytes(2048) == "2.1 MB")
        #expect(Format.duration(45) == "45s")
        #expect(Format.duration(723) == "12m 03s")
        #expect(Format.duration(11_100) == "3h 05m")
        #expect(Format.duration(187_200) == "2d 04h")
        #expect(Format.countdown(65) == "1:05")
        #expect(Format.endpoint("example.com", 443) == "example.com:443")
        #expect(Format.endpoint("example.com", nil) == "example.com")
        #expect(Format.shortSession("6F1C8D2E-0000-4000-8000-00000000000A") == "6f1c8d2e")
        #expect(FirewallMode.proxyOnly.displayName == "Proxy only")
        #expect(ConnectionDecision.timedOut.tint == .red)
    }
}
