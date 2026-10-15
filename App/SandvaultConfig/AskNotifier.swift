import Foundation
import SandvaultAppModel
import SandvaultCore
import UserNotifications

/// User notifications for asks raised while the app is in the background. Answer action identifiers are
/// `AskDecision` raw values; an "always" action saves a rule for the most specific scope the panel offers. Easy
/// offers Allow and Deny for this request only, Advanced and Expert also the rule answers (D53). Details, and a
/// plain click, bring the request panels to the front.
@MainActor
final class AskNotifier: NSObject, UNUserNotificationCenterDelegate {
    static let category = "me.admon.apps.sandvault-config.ask"
    static let easyCategory = "me.admon.apps.sandvault-config.ask.easy"
    static let detailsAction = "details"

    private let asks: AsksModel

    init(asks: AsksModel) {
        self.asks = asks
        super.init()
        let center = UNUserNotificationCenter.current()
        center.delegate = self
        center.setNotificationCategories([
            Self.makeCategory(Self.category, mode: .expert),
            Self.makeCategory(Self.easyCategory, mode: .easy),
        ])
        center.requestAuthorization(options: [.alert, .sound]) { _, _ in }
    }

    /// `title` and `body` come from `AsksModel` (destination, verdict, process and, outside Easy, port).
    func post(_ ask: AskRequest, title: String, body: String, mode: InterfaceMode) {
        let content = UNMutableNotificationContent()
        content.title = title
        content.body = body
        content.categoryIdentifier = mode == .easy ? Self.easyCategory : Self.category
        content.userInfo = ["askID": ask.id.uuidString]
        let request = UNNotificationRequest(identifier: ask.id.uuidString, content: content, trigger: nil)
        UNUserNotificationCenter.current().add(request, withCompletionHandler: nil)
    }

    func withdraw(_ id: UUID) {
        let center = UNUserNotificationCenter.current()
        center.removeDeliveredNotifications(withIdentifiers: [id.uuidString])
        center.removePendingNotificationRequests(withIdentifiers: [id.uuidString])
    }

    private static func makeCategory(_ identifier: String, mode: InterfaceMode) -> UNNotificationCategory {
        let answers = AsksModel.notificationDecisions(for: mode).map { decision in
            UNNotificationAction(
                identifier: decision.rawValue, title: title(decision, mode: mode),
                options: decision == .denyAlways || decision == .denyOnce ? [.destructive] : []
            )
        }
        let details = UNNotificationAction(identifier: detailsAction, title: "Details", options: [.foreground])
        return UNNotificationCategory(identifier: identifier, actions: answers + [details], intentIdentifiers: [], options: [])
    }

    /// Easy answers only this request, so its buttons need no "once".
    private static func title(_ decision: AskDecision, mode: InterfaceMode) -> String {
        guard mode == .easy else { return decision.displayName }
        return decision == .allowOnce ? "Allow" : decision == .denyOnce ? "Deny" : decision.displayName
    }

    private func handle(action: String, askID: String?) {
        if action == Self.detailsAction || action == UNNotificationDefaultActionIdentifier {
            AppRuntime.showAskPanels()
            return
        }
        guard let decision = AskDecision(rawValue: action),
              let askID, let id = UUID(uuidString: askID),
              let ask = asks.pending.first(where: { $0.id == id })
        else { return }
        Task { await asks.answer(ask, decision) }
    }

    nonisolated func userNotificationCenter(
        _ center: UNUserNotificationCenter, didReceive response: UNNotificationResponse,
        withCompletionHandler completionHandler: @escaping () -> Void
    ) {
        let action = response.actionIdentifier
        let askID = response.notification.request.content.userInfo["askID"] as? String
        Task { @MainActor in self.handle(action: action, askID: askID) }
        completionHandler()
    }

    nonisolated func userNotificationCenter(
        _ center: UNUserNotificationCenter, willPresent notification: UNNotification,
        withCompletionHandler completionHandler: @escaping (UNNotificationPresentationOptions) -> Void
    ) {
        completionHandler([.banner, .sound])
    }
}
