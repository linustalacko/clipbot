import AppKit
import ClipbotCore

/// Polls the general pasteboard's change count (macOS has no change notification) and hands each
/// change to the isolated ClipReader helper, which reads and checks it. Dclip only ever sees the
/// checked result: own-write check → helper (secure input → metadata filter → read → secret
/// patterns → changeCount re-check) → store.
@MainActor
final class PasteboardWatcher {
    private let pb = NSPasteboard.general
    private let store: HistoryStore
    private let filter: () -> SecretFilter
    private var tracker: ChangeTracker
    private var timer: Timer?
    /// Every app that was frontmost since the last processed change — the copy came from one of them.
    private var sources: Set<String> = []
    private var activationObserver: NSObjectProtocol?
    private let reader = ReaderClient()
    /// A read is in flight; later changes wait for it (the next tick picks up the newest one).
    private var reading = false
    private var secureInputDrops = 0
    private var warnedSecureInput = false

    /// Called once per launch when secure input keeps blocking recording. Argument: holder app name.
    var onSecureInputStuck: ((String?) -> Void)?

    init(store: HistoryStore, filter: @escaping () -> SecretFilter) {
        self.store = store
        self.filter = filter
        tracker = ChangeTracker(initial: NSPasteboard.general.changeCount)
    }

    func start() {
        resetSources()
        activationObserver = NSWorkspace.shared.notificationCenter.addObserver(
            forName: NSWorkspace.didActivateApplicationNotification, object: nil, queue: .main
        ) { [weak self] note in
            let id = (note.userInfo?[NSWorkspace.applicationUserInfoKey] as? NSRunningApplication)?.bundleIdentifier
            MainActor.assumeIsolated { if let id { self?.sources.insert(id) } }
        }
        let t = Timer(timeInterval: 0.5, repeats: true) { [weak self] _ in
            MainActor.assumeIsolated { self?.tick() }
        }
        t.tolerance = 0.1
        RunLoop.main.add(t, forMode: .common)
        timer = t
    }

    func noteOwnWrite() { tracker.noteOwnWrite(pb.changeCount) }

    private func resetSources() {
        sources = Set([NSWorkspace.shared.frontmostApplication?.bundleIdentifier].compactMap { $0 })
    }

    private func tick() {
        store.removeExpired()
        guard !reading else { return }
        let count = pb.changeCount
        guard tracker.observe(count) else { return }
        if let front = NSWorkspace.shared.frontmostApplication?.bundleIdentifier { sources.insert(front) }
        let request = ReadRequest(changeCount: count, secureInput: SecureInput.isOn, sourceBundleIDs: Array(sources),
                                  ignoredBundleIDs: Array(filter().ignoredBundleIDs))
        resetSources()
        reading = true
        reader.read(request) { [weak self] outcome in
            guard let self else { return }
            reading = false
            switch outcome {
            case .failed(let why):
                Log.app.error("clip dropped: reader \(why, privacy: .public)")
            case .response(let r):
                guard let result = r.result else { Log.app.info("clip dropped: pasteboard changed during read"); return }
                handle(result)
            }
        }
    }

    private func handle(_ result: ClipGate.Result) {
        noteSecureInput(result == .dropped(.secureInput))
        switch result {
        case .dropped(let reason):
            Log.app.info("clip dropped: \(String(describing: reason), privacy: .public)")
        case .skipped:
            Log.app.info("clip skipped: empty, unsupported or too large")
        case .record(let clip):
            record(clip, expiresAfter: nil)
        case .recordBriefly(let clip):
            record(clip, expiresAfter: HistoryStore.secretLifetime)
        }
    }

    private func record(_ clip: CapturedClip, expiresAfter: TimeInterval?) {
        do {
            try store.add(clip.payload, kind: clip.kind, preview: clip.preview, thumbnail: clip.thumbnail,
                          searchText: clip.searchText, expiresAfter: expiresAfter)
            let how = expiresAfter == nil ? "recorded" : "kept in memory for 10 min (secret pattern)"
            Log.app.info("clip \(how, privacy: .public): \(clip.kind.rawValue, privacy: .public), history=\(self.store.entries.count, privacy: .public)")
        } catch {
            Log.app.error("clip store failed: \(String(describing: type(of: error)), privacy: .public)")
        }
    }

    /// Warns once per launch when secure input keeps blocking recording (stuck, or an app with
    /// "Secure Keyboard Entry" always on).
    private func noteSecureInput(_ dropped: Bool) {
        secureInputDrops = dropped ? secureInputDrops + 1 : 0
        guard secureInputDrops >= 3, !warnedSecureInput else { return }
        warnedSecureInput = true
        onSecureInputStuck?(SecureInput.holder())
    }
}
