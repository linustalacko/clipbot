import Foundation

/// Encrypted clipboard history: `index.bin` (sealed JSON of entries, newest first) plus one sealed
/// payload per clip in `clips/<uuid>.bin`. Not thread-safe; use from the main thread.
///
/// A clip added with `expiresAfter` (one that contains a secret format) is kept in memory only:
/// it shows in `entries` like any clip, but neither it nor its index entry is ever written to disk,
/// and it's gone at its expiry time, on Clear History, or when the app quits.
public final class HistoryStore {
    public static let keyAccount = "clip-key"
    /// How long a copy containing a secret format stays in history (memory only).
    public static let secretLifetime: TimeInterval = 10 * 60
    private static let indexName = "index.bin"
    private static let clipsName = "clips"
    /// AES-GCM nonce (12) + tag (16): anything smaller can't be a sealed file.
    private static let minSealedSize = 28

    public private(set) var entries: [ClipEntry] = []
    /// True when existing history couldn't be decrypted (key missing or index corrupt) and was
    /// moved aside into `Unreadable-<date>/`. The app warns once.
    public private(set) var recoveredFromMissingKey = false

    public let capacity: Int
    private let directory: URL
    private let keys: KeyProviding
    private var sealer: Sealer
    /// Payloads of memory-only clips, by entry id.
    private var inMemory: [UUID: ClipPayload] = [:]

    private var indexURL: URL { directory.appendingPathComponent(Self.indexName) }
    private var clipsURL: URL { directory.appendingPathComponent(Self.clipsName) }
    private func clipURL(_ id: UUID) -> URL { clipsURL.appendingPathComponent("\(id.uuidString).bin") }

    public init(directory: URL, keys: KeyProviding, capacity: Int = 100) throws {
        self.directory = directory
        self.keys = keys
        self.capacity = capacity
        try SecureFiles.ensureDirectory(directory)

        let fm = FileManager.default
        let hasData = fm.fileExists(atPath: directory.appendingPathComponent(Self.indexName).path)
            || !((try? fm.contentsOfDirectory(atPath: directory.appendingPathComponent(Self.clipsName).path)) ?? []).isEmpty
        let opened = try StoreBootstrap.open(keys: keys, account: Self.keyAccount, directory: directory,
                                             files: [Self.indexName, Self.clipsName], hasData: hasData) { sealer in
            try JSONDecoder().decode([ClipEntry].self,
                                     from: sealer.open(Data(contentsOf: directory.appendingPathComponent(Self.indexName)), context: Self.indexContext))
        }
        sealer = opened.sealer
        entries = opened.value ?? []
        recoveredFromMissingKey = opened.recovered
        try SecureFiles.ensureDirectory(clipsURL)
        try dropEntriesWithMissingFiles()
        sweepOrphans()
    }

    // MARK: Public API

    /// - Parameter expiresAfter: keep the clip in memory only, for this long (copies containing a
    ///   secret format). Copying it again restarts the time.
    public func add(_ payload: ClipPayload, kind: ClipKind, preview: String, thumbnail: Data?, searchText: String? = nil,
                    expiresAfter: TimeInterval? = nil, now: Date = Date()) throws {
        removeExpired(now: now)
        let expires = expiresAfter.map { now.addingTimeInterval($0) }
        let tag = sealer.tag(payload.canonicalBytes)
        if let existing = entries.first(where: { $0.tag == tag }) {
            try moveToTop(existing.id)
            if expires != nil, entries[0].expires != nil { entries[0].expires = expires }
            return
        }
        var entry = ClipEntry(id: UUID(), lastUsed: now, kind: kind, preview: preview, thumbnail: thumbnail, tag: tag,
                              searchText: searchText.map { String($0.prefix(PopupSearch.maxTextLength)) })
        entry.expires = expires
        if expires != nil {
            inMemory[entry.id] = payload
        } else {
            try SecureFiles.writeAtomically(try sealer.seal(JSONEncoder().encode(payload), context: Self.clipContext(entry.id)), to: clipURL(entry.id))
        }
        entries.insert(entry, at: 0)
        let evicted = entries.count > capacity ? Array(entries[capacity...]) : []
        entries.removeLast(evicted.count)
        for e in evicted { inMemory[e.id] = nil }
        try saveIndex()
        for e in evicted { try? FileManager.default.removeItem(at: clipURL(e.id)) }
    }

    /// Removes memory-only clips whose time is up. Returns whether any were removed.
    @discardableResult
    public func removeExpired(now: Date = Date()) -> Bool {
        let before = entries.count
        entries.removeAll { e in
            guard let t = e.expires, t <= now else { return false }
            inMemory[e.id] = nil
            return true
        }
        return entries.count != before
    }

    /// Decrypts a clip's payload. A clip that fails authentication is removed from history.
    public func payload(for id: UUID) throws -> ClipPayload {
        if let p = inMemory[id] { return p }
        do {
            return try JSONDecoder().decode(ClipPayload.self, from: sealer.open(Data(contentsOf: clipURL(id)), context: Self.clipContext(id)))
        } catch {
            try? remove(id)
            throw error
        }
    }

    public func moveToTop(_ id: UUID) throws {
        guard let i = entries.firstIndex(where: { $0.id == id }) else { return }
        var e = entries.remove(at: i)
        e.lastUsed = Date()
        entries.insert(e, at: 0)
        try saveIndex()
    }

    /// Removes one clip and its file. Unknown ids are ignored.
    public func delete(_ id: UUID) throws {
        guard entries.contains(where: { $0.id == id }) else { return }
        try remove(id)
    }

    /// Deletes every clip and rotates the key, so leftover ciphertext on disk is unreadable.
    public func clear() throws {
        let fm = FileManager.default
        entries = []
        inMemory = [:]
        try? fm.removeItem(at: clipsURL)
        try? fm.removeItem(at: indexURL)
        sealer = Sealer(key: try keys.createKey(Self.keyAccount))
        try SecureFiles.ensureDirectory(clipsURL)
        try saveIndex()
    }

    // MARK: Private

    private func remove(_ id: UUID) throws {
        entries.removeAll { $0.id == id }
        inMemory[id] = nil
        try? FileManager.default.removeItem(at: clipURL(id))
        try saveIndex()
    }

    /// Memory-only clips are never part of the saved index.
    private func saveIndex() throws {
        let saved = entries.filter { $0.expires == nil }
        try SecureFiles.writeAtomically(try sealer.seal(JSONEncoder().encode(saved), context: Self.indexContext), to: indexURL)
    }

    private static let indexContext = "io.linus.clipbot/index/v1"
    private static func clipContext(_ id: UUID) -> String { "io.linus.clipbot/clip/v1/\(id.uuidString)" }

    /// Removes clip files (and stray temp files) that no index entry references, e.g. after a crash.
    private func sweepOrphans() {
        let fm = FileManager.default
        let known = Set(entries.map { "\($0.id.uuidString).bin" })
        for dir in [clipsURL, directory] {
            for name in (try? fm.contentsOfDirectory(atPath: dir.path)) ?? [] {
                let orphanClip = dir == clipsURL && !known.contains(name)
                let strayTemp = name.hasPrefix(".") && name.hasSuffix(".tmp")
                if orphanClip || strayTemp { try? fm.removeItem(at: dir.appendingPathComponent(name)) }
            }
        }
    }

    private func dropEntriesWithMissingFiles() throws {
        let before = entries.count
        entries.removeAll { e in
            let size = (try? FileManager.default.attributesOfItem(atPath: clipURL(e.id).path)[.size] as? Int) ?? 0
            return size < Self.minSealedSize
        }
        if entries.count != before { try saveIndex() }
    }

}
