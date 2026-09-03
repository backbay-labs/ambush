import AmbushPushKit
import Foundation
import Security
import UserNotifications

final class AmbushOneShotCompletion {
  private let lock = NSLock()
  private var completion: (() -> Void)?

  init(_ completion: @escaping () -> Void) {
    self.completion = completion
  }

  func call() {
    lock.lock()
    let completion = completion
    self.completion = nil
    lock.unlock()
    completion?()
  }
}

enum AmbushPushNotificationResponseCoordinator {
  static func handle(
    actionIdentifier: String,
    userInfo: [AnyHashable: Any],
    onTarget: (AmbushPushNavigationTarget) -> Void,
    forwardToFlutter: (@escaping () -> Void) -> Void,
    completion: @escaping () -> Void
  ) {
    let completionGate = AmbushOneShotCompletion(completion)
    defer { completionGate.call() }

    if actionIdentifier == UNNotificationDefaultActionIdentifier,
      let target = AmbushPushNavigationTarget.decodeIfPresent(from: userInfo)
    {
      onTarget(target)
    }
    forwardToFlutter { completionGate.call() }
  }
}

enum AmbushPushKeychain {
  static let service = "ambush.push.nse.signing"

  static func replace(signingKeys: [String: String], accessGroup: String?) throws {
    var query = baseQuery(accessGroup: accessGroup)
    SecItemDelete(query as CFDictionary)
    for (communityID, privateKeyHex) in signingKeys {
      query[kSecAttrAccount as String] = communityID
      query[kSecValueData as String] = Data(privateKeyHex.utf8)
      query[kSecAttrAccessible as String] = kSecAttrAccessibleAfterFirstUnlock
      let status = SecItemAdd(query as CFDictionary, nil)
      guard status == errSecSuccess else {
        SecItemDelete(baseQuery(accessGroup: accessGroup) as CFDictionary)
        throw NSError(
          domain: NSOSStatusErrorDomain, code: Int(status),
          userInfo: [
            NSLocalizedDescriptionKey: SecCopyErrorMessageString(status, nil)
              ?? "Keychain write failed" as CFString
          ]
        )
      }
      query.removeValue(forKey: kSecValueData as String)
      query.removeValue(forKey: kSecAttrAccessible as String)
      query.removeValue(forKey: kSecAttrAccount as String)
    }
  }

  private static func baseQuery(accessGroup: String?) -> [String: Any] {
    var query: [String: Any] = [
      kSecClass as String: kSecClassGenericPassword,
      kSecAttrService as String: service,
    ]
    if let accessGroup, !accessGroup.isEmpty {
      query[kSecAttrAccessGroup as String] = accessGroup
    }
    return query
  }
}
