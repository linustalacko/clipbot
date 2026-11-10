import AppKit

/// The complete record-or-drop decision for one pasteboard change, in the order that keeps secrets
/// from ever being read: secure input, marker types and source apps (all metadata) first, then
/// data, then secret patterns over every text form. A copy that matches a secret pattern is kept,
/// but only briefly and only in memory (`HistoryStore.secretLifetime`), so an important copy that
/// happens to contain a key is never lost outright.
public enum ClipGate {
    public enum Result: Codable, Equatable, Sendable {
        case record(CapturedClip)
        /// Contains a well-known secret format: keep in memory only, for `HistoryStore.secretLifetime`.
        case recordBriefly(CapturedClip)
        case dropped(SecretFilter.Reason)
        case skipped
    }

    /// - Parameters:
    ///   - secureInput: whether secure keyboard input was on (a password field had focus).
    ///   - sourceBundleIDs: every app that was frontmost since the previous change.
    public static func evaluate(items: [NSPasteboardItem], secureInput: Bool, sourceBundleIDs: Set<String>,
                                filter: SecretFilter) -> Result {
        if secureInput { return .dropped(.secureInput) }
        let types = items.flatMap { $0.types.map(\.rawValue) }
        if let reason = filter.dropReason(types: types, sourceBundleIDs: sourceBundleIDs) { return .dropped(reason) }
        guard let clip = ClipCapture.capture(items: items) else { return .skipped }
        if clip.texts.contains(where: SecretFilter.looksLikeSecret) { return .recordBriefly(clip) }
        return .record(clip)
    }
}
