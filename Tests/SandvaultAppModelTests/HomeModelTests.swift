import Foundation
import SandvaultCore
import Testing
@testable import SandvaultAppModel

@Suite struct HomeModelTests {
    @Test func statusPutsTheStopAndAMissingNetdFirst() {
        let stopped = HomeStatus(protection: .blockAll, panicActive: true, netdMissing: true, firewallMode: .blocked, developerBasics: true)
        #expect(stopped.title == "Everything in the sandbox is stopped")
        #expect(stopped.tint == .red)
        let noNetd = HomeStatus(protection: .ask, panicActive: false, netdMissing: true, firewallMode: .proxyOnly, developerBasics: true)
        #expect(noNetd.tint == .orange)
        #expect(noNetd.title == "Websites do not work right now")
    }

    @Test func statusDescribesEachLevel() {
        func status(_ level: ProtectionLevel?, basics: Bool = true) -> HomeStatus {
            HomeStatus(protection: level, panicActive: false, netdMissing: false, firewallMode: .open, developerBasics: basics)
        }
        #expect(status(.ask).title == "Your sandbox is protected")
        #expect(status(.ask).detail.contains("Developer basics"))
        #expect(!status(.ask, basics: false).detail.contains("Developer basics"))
        #expect(status(.watch).tint == .blue)
        #expect(status(.blockAll).symbolName == "network.slash")
        #expect(status(.off).tint == .orange)
        #expect(status(nil).detail == "Firewall mode Open. Choosing a level replaces it.")
    }

    @Test func stepsGetDirectActions() {
        #expect(HomeStep(.installHelper, mode: .easy).action == .installHelper)
        #expect(HomeStep(.startNetd, mode: .expert).action == .startNetd)
        #expect(HomeStep(.createSandbox(fix: nil), mode: .advanced).action == .createSandbox)
        #expect(HomeStep(.endPanic, mode: .easy).action == .endStop)
        #expect(HomeStep(.endPanic, mode: .expert).action == .open(.firewall))
        #expect(HomeStep(.applyFirewall, mode: .advanced).action == .applyFirewall)
        #expect(HomeStep(.enableFirewall, mode: .easy).action == nil)
        #expect(HomeStep(.enableFirewall, mode: .expert).actionTitle == "Open Firewall & Proxy")
        #expect(HomeStep(.ready, mode: .easy).isDone)
        #expect(HomeStep(.ready, mode: .easy).action == nil)
    }

    @Test func stepsUsePlainWordsBelowExpert() {
        let easy = HomeStep(.startNetd, mode: .easy)
        #expect(easy.title == "Start the network monitor")
        #expect(easy.command == nil)
        let expert = HomeStep(.startNetd, mode: .expert)
        #expect(expert.title == SetupStep.startNetd.title)
        #expect(expert.command == "svctl netd install")
        // Installing sv has no button, so its command shows in every mode.
        #expect(HomeStep(.installSandvault(fix: "brew install sandvault"), mode: .easy).command == "brew install sandvault")
    }

    @Test func sidebarStatusIsPlainBelowExpert() {
        func status(_ mode: InterfaceMode, _ level: ProtectionLevel? = .ask, panic: Bool = false, netdMissing: Bool = false) -> SidebarStatus {
            SidebarStatus(mode: mode, protection: level, panicActive: panic, netdMissing: netdMissing, netdSummary: "sandvault-netd: proxy only")
        }
        #expect(status(.easy).text == "Protection on · Ask")
        #expect(status(.easy, .off).tint == .orange)
        #expect(status(.advanced, netdMissing: true).text == "Network monitor stopped. Websites do not work.")
        #expect(status(.expert).text == "sandvault-netd: proxy only")
        #expect(status(.expert, panic: true).tint == .red)
        #expect(status(.easy, nil).text == "Custom protection")
    }

    @Test func resumeKeepsTheLevelTheModeOffers() {
        #expect(ProtectionLevel.resume(from: .watch, mode: .easy) == .watch)
        #expect(ProtectionLevel.resume(from: .off, mode: .easy) == .ask)
        #expect(ProtectionLevel.resume(from: .off, mode: .advanced) == .off)
        #expect(ProtectionLevel.resume(from: nil, mode: .expert) == .ask)
    }

    @Test func recentWebsitesListHostsOnly() {
        let items = [
            ActivityItem(kind: .icmp, title: "ping 1.1.1.1", detail: "", status: "Running", tint: .orange),
            ActivityItem(kind: .host, title: "github.com", detail: "", status: "Allowed", tint: .green, host: "github.com"),
            ActivityItem(kind: .direct, title: "1.2.3.4:22", detail: "", status: "Direct", tint: .gray),
            ActivityItem(kind: .host, title: "npmjs.org", detail: "", status: "Allowed", tint: .green, host: "npmjs.org"),
            ActivityItem(kind: .host, title: "pypi.org", detail: "", status: "Blocked", tint: .red, host: "pypi.org", blocked: true),
        ]
        #expect(ActivityItem.recentWebsites(items, limit: 2).map(\.title) == ["github.com", "npmjs.org"])
        #expect(ActivityItem.recentWebsites(items).count == 3)
    }
}
