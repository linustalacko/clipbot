import AppKit
import CryptoKit
import XCTest
@testable import ClipbotCore

/// The whole record-or-drop decision for one pasteboard change.
final class ClipGateTests: PasteboardTestCase {
    let filter = SecretFilter(ignoredBundleIDs: SecretFilter.defaultIgnoredBundleIDs)

    func gate(sources: Set<String> = ["com.apple.TextEdit"], secureInput: Bool = false) -> ClipGate.Result {
        ClipGate.evaluate(items: pb.pasteboardItems ?? [], secureInput: secureInput, sourceBundleIDs: sources, filter: filter)
    }

    /// A copy with a secret format is kept, but only in memory and only briefly (HistoryStore).
    func assertKeptBriefly(_ r: ClipGate.Result, file: StaticString = #filePath, line: UInt = #line) {
        guard case .recordBriefly = r else { return XCTFail("expected recordBriefly, got \(r)", file: file, line: line) }
    }

    func testSecureInputDropsBeforeAnythingIsRead() {
        pb.setString("typed into a password field", forType: .string)
        XCTAssertEqual(gate(secureInput: true), .dropped(.secureInput))
    }

    func testPlainCopyIsRecorded() {
        pb.setString("hello", forType: .string)
        guard case .record(let c) = gate() else { return XCTFail() }
        XCTAssertEqual(c.preview, "hello")
    }

    func testMarkerOnAnyItemDropsWholeChange() {
        let a = NSPasteboardItem(); a.setString("visible", forType: .string)
        let b = NSPasteboardItem(); b.setString("hunter2", forType: .string)
        b.setData(Data(), forType: .init("org.nspasteboard.ConcealedType"))
        pb.writeObjects([a, b])
        XCTAssertEqual(gate(), .dropped(.marker))
    }

    func testAnyIgnoredSourceSinceLastChangeDrops() {
        pb.setString("from keychain", forType: .string)
        // User copied in Keychain Access, then ⌘-Tabbed to TextEdit before the poll ran.
        XCTAssertEqual(gate(sources: ["com.apple.keychainaccess", "com.apple.TextEdit"]), .dropped(.ignoredApp))
    }

    func testSecretInRTFOnlyClipIsKeptBriefly() throws {
        let key = "sk-" + String(repeating: "aB3", count: 14)
        let rtf = try rtfData(key)
        pb.setData(rtf, forType: .rtf)
        assertKeptBriefly(gate())
    }

    func testSecretPlainTextIsKeptBriefly() {
        pb.setString("ghp_" + String(repeating: "a1", count: 18), forType: .string)
        assertKeptBriefly(gate())
    }

    func testSecretTextAlongsideImageIsKeptBriefly() {
        // Spreadsheets put a picture of the cell next to its text.
        let img = NSImage(size: NSSize(width: 10, height: 10), flipped: false) { r in NSColor.blue.setFill(); r.fill(); return true }
        let item = NSPasteboardItem()
        item.setData(img.tiffRepresentation!, forType: .tiff)
        item.setString("AKIAIOSFODNN7EXAMPLE", forType: .string)
        pb.writeObjects([item])
        assertKeptBriefly(gate())
    }

    func testSecretTextAlongsidePDFIsKeptBriefly() {
        let item = NSPasteboardItem()
        item.setData(Data("%PDF-1.4".utf8), forType: .pdf)
        item.setString("sk_live_" + String(repeating: "Ab3", count: 9), forType: .string)
        pb.writeObjects([item])
        assertKeptBriefly(gate())
    }

    func testRTFDOnlyCopyIsSkippedNotParsed() {
        // Malformed RTFD must never reach AppKit's parser (it raises an uncatchable exception).
        pb.setData(Data("not really rtfd".utf8), forType: .rtfd)
        XCTAssertEqual(gate(), .skipped)
    }

    func testEmptyIsSkipped() {
        pb.setString("  ", forType: .string)
        XCTAssertEqual(gate(), .skipped)
    }
}

/// A Keychain item that exists but can't be unwrapped (new Mac, reset Secure Enclave).
final class UnusableKeyStore: KeyProviding, @unchecked Sendable {
    let inner = InMemoryKeyStore()
    var unusable: Set<String> = []
    func existingKey(_ a: String) throws -> SymmetricKey? {
        if unusable.contains(a) { throw KeyUnusableError() }
        return try inner.existingKey(a)
    }
    var retired: [String] = []
    func createKey(_ a: String) throws -> SymmetricKey { unusable.remove(a); return try inner.createKey(a) }
    func deleteKey(_ a: String) throws { unusable.remove(a); try inner.deleteKey(a) }
    func retireKey(_ a: String) throws { retired.append(a); unusable.remove(a) }
}

/// Keychain locked / access denied: must NOT quarantine (data is fine, key is just unavailable now).
final class LockedKeyStore: KeyProviding, @unchecked Sendable {
    func existingKey(_ a: String) throws -> SymmetricKey? { throw KeychainError(status: errSecInteractionNotAllowed) }
    func createKey(_ a: String) throws -> SymmetricKey { throw KeychainError(status: errSecInteractionNotAllowed) }
    func deleteKey(_ a: String) throws {}
    func retireKey(_ a: String) throws {}
}

final class KeyRecoveryTests: TempDirTestCase {

    func testUnwrappableHistoryKeyQuarantinesAndRecovers() throws {
        let keys = UnusableKeyStore()
        try HistoryStore(directory: dir, keys: keys).add(textPayload("x"), kind: .text, preview: "x", thumbnail: nil)
        keys.unusable = [HistoryStore.keyAccount]
        let h = try HistoryStore(directory: dir, keys: keys)
        XCTAssertTrue(h.recoveredFromMissingKey)
        XCTAssertTrue(h.entries.isEmpty)
        XCTAssertEqual(keys.retired, [HistoryStore.keyAccount], "the old key is set aside, never deleted")
        try h.add(textPayload("y"), kind: .text, preview: "y", thumbnail: nil)
        XCTAssertEqual(try HistoryStore(directory: dir, keys: keys).entries.map(\.preview), ["y"])
    }

    @MainActor
    func testUnwrappableSnippetKeyQuarantinesAndRecovers() throws {
        let keys = UnusableKeyStore()
        try SnippetStore(directory: dir, keys: keys).folders = [SnippetFolder(title: "f")]
        keys.unusable = [SnippetStore.keyAccount]
        let s = try SnippetStore(directory: dir, keys: keys)
        XCTAssertTrue(s.recoveredFromMissingKey)
        XCTAssertTrue(s.folders.isEmpty)
        XCTAssertTrue(try FileManager.default.contentsOfDirectory(atPath: dir.path).contains { $0.hasPrefix("Unreadable-") })
    }

    func testLockedKeychainThrowsWithoutQuarantining() throws {
        let keys = InMemoryKeyStore()
        try HistoryStore(directory: dir, keys: keys).add(textPayload("x"), kind: .text, preview: "x", thumbnail: nil)
        XCTAssertThrowsError(try HistoryStore(directory: dir, keys: LockedKeyStore()))
        XCTAssertFalse(try FileManager.default.contentsOfDirectory(atPath: dir.path).contains { $0.hasPrefix("Unreadable-") })
        XCTAssertEqual(try HistoryStore(directory: dir, keys: keys).entries.count, 1, "data intact once keychain unlocks")
    }

    func testKeychainRetireKeepsTheOldItem() throws {
        let service = "io.linus.clipbot.tests", account = "retire-\(UUID().uuidString)"
        let store = KeychainKeyStore(service: service)
        let old = try store.createKey(account)
        try store.retireKey(account)
        XCTAssertNil(try store.existingKey(account))
        let q: [String: Any] = [kSecClass as String: kSecClassGenericPassword, kSecAttrService as String: service,
                                kSecMatchLimit as String: kSecMatchLimitAll, kSecReturnAttributes as String: true]
        var out: CFTypeRef?
        XCTAssertEqual(SecItemCopyMatching(q as CFDictionary, &out), errSecSuccess)
        let accounts = ((out as? [[String: Any]]) ?? []).compactMap { $0[kSecAttrAccount as String] as? String }
        let retired = try XCTUnwrap(accounts.first { $0.hasPrefix(account + ".unreadable-") })
        XCTAssertEqual(try store.existingKey(retired).map { $0.withUnsafeBytes { Data($0) } }, old.withUnsafeBytes { Data($0) })
        try store.deleteKey(retired)
    }

    func testKeychainStoreReportsCorruptItemAsUnusable() throws {
        let service = "io.linus.clipbot.tests", account = "corrupt-\(UUID().uuidString)"
        let q: [String: Any] = [kSecClass as String: kSecClassGenericPassword, kSecAttrService as String: service,
                                kSecAttrAccount as String: account, kSecValueData as String: Data([1, 2, 3])]
        XCTAssertEqual(SecItemAdd(q as CFDictionary, nil), errSecSuccess)
        defer { SecItemDelete(q as CFDictionary) }
        XCTAssertThrowsError(try KeychainKeyStore(service: service).existingKey(account)) { XCTAssertTrue($0 is KeyUnusableError) }
    }
}

final class HardeningTests: TempDirTestCase {

    func testSwappedClipFilesDoNotDecryptAsEachOther() throws {
        let keys = InMemoryKeyStore()
        let s = try HistoryStore(directory: dir, keys: keys)
        try s.add(textPayload("A"), kind: .text, preview: "A", thumbnail: nil)
        try s.add(textPayload("B"), kind: .text, preview: "B", thumbnail: nil)
        let (b, a) = (s.entries[0].id, s.entries[1].id)
        let clips = dir.appendingPathComponent("clips")
        try FileManager.default.removeItem(at: clips.appendingPathComponent("\(a.uuidString).bin"))
        try FileManager.default.copyItem(at: clips.appendingPathComponent("\(b.uuidString).bin"), to: clips.appendingPathComponent("\(a.uuidString).bin"))
        let r = try HistoryStore(directory: dir, keys: keys)
        XCTAssertThrowsError(try r.payload(for: a), "file bound to its id via AAD")
    }

    func testOrphanClipFilesAreSweptOnOpen() throws {
        let keys = InMemoryKeyStore()
        _ = try HistoryStore(directory: dir, keys: keys)
        let orphan = dir.appendingPathComponent("clips/\(UUID().uuidString).bin")
        try Data(repeating: 7, count: 64).write(to: orphan)
        _ = try HistoryStore(directory: dir, keys: keys)
        XCTAssertFalse(FileManager.default.fileExists(atPath: orphan.path))
    }

    /// A file sealed without the snippets context (an old format, or a file planted from elsewhere)
    /// is never opened: it's quarantined like any unreadable data.
    @MainActor
    func testUnboundSnippetFileIsQuarantinedNotOpened() throws {
        let keys = InMemoryKeyStore()
        let key = try keys.createKey(SnippetStore.keyAccount)
        try SecureFiles.ensureDirectory(dir)
        let unbound = try XCTUnwrap(AES.GCM.seal(JSONEncoder().encode([SnippetFolder(title: "old")]), using: key).combined)
        try unbound.write(to: dir.appendingPathComponent("snippets.bin"))
        let s = try SnippetStore(directory: dir, keys: keys)
        XCTAssertTrue(s.folders.isEmpty)
        XCTAssertTrue(s.recoveredFromMissingKey)
    }

    func testPreviewStripsBidiAndControlCharacters() {
        XCTAssertEqual(Preview.text("abc\u{202E}gpj.exe"), "abcgpj.exe")
        XCTAssertEqual(Preview.text("a\u{0000}b\u{200B}c\u{2066}d"), "abcd")
        XCTAssertEqual(Preview.text("👨‍👩‍👧 family"), "👨‍👩‍👧 family", "ZWJ inside emoji sequences is kept")
    }

    func testPreviewOfHugeTextIsCheap() {
        let huge = String(repeating: "word ", count: 2_000_000)
        let t0 = Date()
        XCTAssertEqual(Preview.text(huge).count, 61)
        XCTAssertLessThan(Date().timeIntervalSince(t0), 0.05)
    }

    func testReservedShortcutsRejected() {
        for key in [9, 8, 7, 6, 0, 12, 13, 48, 49] { // V C X Z A Q W Tab Space with ⌘
            XCTAssertFalse(Shortcut(keyCode: UInt16(key), modifierFlags: [.command]).isValid, "⌘ + key \(key)")
        }
        XCTAssertTrue(Shortcut.mainDefault.isValid)
        XCTAssertTrue(Shortcut(keyCode: 9, modifierFlags: [.command, .option]).isValid)
    }

    func testHugeDeclaredImageGetsNoThumbnailAndDoesNotDecode() throws {
        // A tiny PNG header claiming 60000×60000 px must not be decoded at full size.
        var png = Data([0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A, 0, 0, 0, 13, 0x49, 0x48, 0x44, 0x52])
        png.append(contentsOf: [0x00, 0x00, 0xEA, 0x60, 0x00, 0x00, 0xEA, 0x60, 8, 6, 0, 0, 0, 0, 0, 0, 0])
        XCTAssertNil(ClipCapture.thumbnail(fromImageData: png))
    }

    func testThumbnailFromNormalImage() throws {
        let img = NSImage(size: NSSize(width: 300, height: 100), flipped: false) { r in NSColor.red.setFill(); r.fill(); return true }
        let thumb = try XCTUnwrap(ClipCapture.thumbnail(fromImageData: img.tiffRepresentation!).flatMap(NSBitmapImageRep.init(data:)))
        XCTAssertLessThanOrEqual(max(thumb.pixelsWide, thumb.pixelsHigh), 64)
    }

    func testExportDropsXMLIllegalCharactersAndReimports() throws {
        let f = [SnippetFolder(title: "t\u{0001}", snippets: [Snippet(title: "s", content: "a\u{0008}b\tc\n")])]
        let back = try ClipyXML.parse(ClipyXML.export(f))
        XCTAssertEqual(back.first?.title, "t")
        XCTAssertEqual(back.first?.snippets.first?.content, "ab\tc\n")
    }
}
