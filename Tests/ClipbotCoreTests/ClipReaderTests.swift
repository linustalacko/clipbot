import AppKit
import XCTest
@testable import ClipbotCore

/// The logic the isolated ClipReader helper runs, tested in-process on a private pasteboard.
final class ClipReaderTests: PasteboardTestCase {
    func request(secureInput: Bool = false, sources: [String] = ["com.apple.TextEdit"]) -> ReadRequest {
        ReadRequest(changeCount: pb.changeCount, secureInput: secureInput, sourceBundleIDs: sources,
                    ignoredBundleIDs: Array(SecretFilter.defaultIgnoredBundleIDs))
    }

    func testRecordsAPlainCopy() {
        pb.setString("hello", forType: .string)
        guard case .record(let clip)? = ClipReaderCore.handle(request(), pasteboard: pb).result else { return XCTFail() }
        XCTAssertEqual(clip.preview, "hello")
    }

    func testAppliesTheSameDropRulesAsTheGate() {
        pb.setString("x", forType: .string)
        XCTAssertEqual(ClipReaderCore.handle(request(secureInput: true), pasteboard: pb).result, .dropped(.secureInput))
        XCTAssertEqual(ClipReaderCore.handle(request(sources: ["com.1password.1password"]), pasteboard: pb).result, .dropped(.ignoredApp))
        pb.clearContents()
        pb.setString("AKIAIOSFODNN7EXAMPLE", forType: .string)
        guard case .recordBriefly? = ClipReaderCore.handle(request(), pasteboard: pb).result else { return XCTFail() }
    }

    func testStaleRequestIsNotRead() {
        pb.setString("first", forType: .string)
        let req = request()
        pb.clearContents()
        pb.setString("second", forType: .string) // the clipboard moved on before the helper read it
        let resp = ClipReaderCore.handle(req, pasteboard: pb)
        XCTAssertNil(resp.result)
        XCTAssertTrue(resp.changed)
    }

    func testRequestAndResponseSurviveEncoding() throws {
        pb.setString("round trip", forType: .string)
        let req = request()
        XCTAssertEqual(try ReadRequest.decode(req.encoded()), req)
        let resp = ClipReaderCore.handle(req, pasteboard: pb)
        XCTAssertEqual(try ReadResponse.decode(resp.encoded()), resp)
        XCTAssertThrowsError(try ReadResponse.decode(Data("garbage".utf8)))
    }

    func testRTFThatHangsApplesParserIsTheFixture() throws {
        // Documents the input found by the stress suite. It is only safe to feed to the isolated
        // helper (where the watchdog kills it); never parse it in a test process.
        let url = Bundle(for: Self.self).url(forResource: "rtf-tokenizer-hang", withExtension: "rtf")
            ?? URL(fileURLWithPath: #filePath).deletingLastPathComponent().deletingLastPathComponent()
                .appendingPathComponent("Fixtures/rtf-tokenizer-hang.rtf")
        XCTAssertEqual(try Data(contentsOf: url).count, 170)
    }
}

final class WatchdogTests: XCTestCase {
    func testFiresWhenWorkOverruns() {
        let fired = expectation(description: "watchdog fired")
        let dog = Watchdog(timeout: 0.1) { fired.fulfill() }
        dog.arm()
        wait(for: [fired], timeout: 2)
    }

    func testDoesNotFireWhenWorkFinishes() {
        let fired = expectation(description: "watchdog fired")
        fired.isInverted = true
        let dog = Watchdog(timeout: 0.2) { fired.fulfill() }
        dog.arm()
        dog.disarm()
        wait(for: [fired], timeout: 0.5)
    }
}
