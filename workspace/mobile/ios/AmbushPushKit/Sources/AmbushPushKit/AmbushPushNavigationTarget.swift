import Foundation

/// A stable destination attached by the notification service extension after
/// it resolves and verifies the event that produced a push wake.
public struct AmbushPushNavigationTarget: Codable, Equatable, Sendable {
  public static let userInfoKey = "ambush_push_navigation"

  public let eventID: String
  public let communityID: String
  public let channelID: String

  public init(eventID: String, communityID: String, channelID: String) {
    self.eventID = eventID
    self.communityID = communityID
    self.channelID = channelID
  }

  public var userInfoValue: [String: String] {
    [
      "event_id": eventID,
      "community_id": communityID,
      "channel_id": channelID,
    ]
  }

  /// Decodes a target without trusting other fields from the APNs payload.
  public static func decodeIfPresent(
    from userInfo: [AnyHashable: Any]
  ) -> AmbushPushNavigationTarget? {
    guard let raw = userInfo[userInfoKey] as? [String: Any],
      raw.count == 3,
      let eventID = raw["event_id"] as? String,
      let communityID = raw["community_id"] as? String,
      let channelID = raw["channel_id"] as? String,
      !eventID.isEmpty,
      !communityID.isEmpty,
      !channelID.isEmpty
    else {
      return nil
    }
    return AmbushPushNavigationTarget(
      eventID: eventID,
      communityID: communityID,
      channelID: channelID
    )
  }

}

/// Thread-safe one-item buffer spanning notification delivery and Flutter
/// engine startup during a cold notification launch.
public final class AmbushPushNavigationBuffer: @unchecked Sendable {
  private let lock = NSLock()
  private var target: AmbushPushNavigationTarget?

  public init() {}

  public func record(_ target: AmbushPushNavigationTarget) {
    lock.lock()
    self.target = target
    lock.unlock()
  }

  public func peek() -> AmbushPushNavigationTarget? {
    lock.lock()
    defer { lock.unlock() }
    return target
  }

  public func take() -> AmbushPushNavigationTarget? {
    lock.lock()
    defer { lock.unlock() }
    let current = target
    target = nil
    return current
  }

  public func remove(ifMatching expected: AmbushPushNavigationTarget) {
    lock.lock()
    defer { lock.unlock() }
    if target == expected {
      target = nil
    }
  }
}
