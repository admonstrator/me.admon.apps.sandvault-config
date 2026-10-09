import Foundation
import SandvaultAppModel
import SandvaultCore
import UserNotifications

/// User notifications for asks raised while the app is in the background, with the four answers as actions.
/// Action identifiers are `AskDecision` raw values; a plain click does nothing (the ask panel is on screen).
@MainActor
final class AskNotifier: NSObject, UNUserNotificationCenterDelegate {
    static let category = "me.admon.apps.sandvault-config.ask"

    private let asks: AsksModel

    init(asks: AsksModel) {
        self.asks = asks
        super.init()
        let center = UNUserNotificationCenter.current()
        center.delegate = self
        center.setNotificationCategories([Self.makeCategory()])
        center.requestAuthorization(options: [.alert, .sound]) { _, _ in }
    }

    func post(_ ask: AskRequest, detail: String) {
        let content = UNMutableNotificationContent()
        content.title = "Allow \(ask.host)?"
        content.body = detail
        content.categoryIdentifier = Self.category
        content.userInfo = ["askID": ask.id.uuidString]
        let request = UNNotificationRequest(identifier: ask.id.uuidString, content: content, trigger: nil)
        UNUserNotificationCenter.current().add(request, withCompletionHandler: nil)
    }

    func withdraw(_ id: UUID) {
        let center = UNUserNotificationCenter.current()
        center.removeDeliveredNotifications(withIdentifiers: [id.uuidString])
        center.removePendingNotificationRequests(withIdentifiers: [id.uuidString])
    }

    private static func makeCategory() -> UNNotificationCategory {
        let actions = [AskDecision.allowOnce, .allowAlways, .denyOnce, .denyAlways].map { decision in
            UNNotificationAction(
                identifier: decision.rawValue, title: decision.displayName,
                options: decision == .denyAlways || decision == .denyOnce ? [.destructive] : []
            )
        }
        return UNNotificationCategory(identifier: category, actions: actions, intentIdentifiers: [], options: [])
    }

    private func handle(action: String, askID: String?) {
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
