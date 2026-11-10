import Foundation

public enum ClipKind: String, Codable, Sendable {
    case text, richText, image, pdf, file, url
}

public struct ClipRepresentation: Codable, Equatable, Sendable {
    public let type: String
    public let data: Data
    public init(type: String, data: Data) { self.type = type; self.data = data }
}

public struct ClipPayload: Codable, Equatable, Sendable {
    public let representations: [ClipRepresentation]
    public init(representations: [ClipRepresentation]) { self.representations = representations }

    public var byteCount: Int { representations.reduce(0) { $0 + $1.data.count } }

    /// Length-prefixed type ‖ data for each representation; input to the dedupe tag.
    var canonicalBytes: Data {
        var out = Data()
        func append(_ d: Data) {
            var n = UInt64(d.count).bigEndian
            out.append(Data(bytes: &n, count: 8))
            out.append(d)
        }
        for r in representations { append(Data(r.type.utf8)); append(r.data) }
        return out
    }
}

public struct ClipEntry: Codable, Identifiable, Equatable, Sendable {
    public let id: UUID
    public var lastUsed: Date
    public let kind: ClipKind
    public let preview: String
    public let thumbnail: Data?
    public let tag: Data
    /// The clip's text (capped), so search can match more than the preview without opening the
    /// sealed payload. nil for clips recorded before search existed; they're searched by preview.
    public let searchText: String?
    /// Set only on clips kept in memory (they contain a secret format); they're removed at this
    /// time and never written to disk. nil for every saved clip.
    public var expires: Date? = nil
}
