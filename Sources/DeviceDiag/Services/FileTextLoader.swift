import Foundation

/// Loads a text-ish file (`.txt`, `.log`, `.plist`, `.json`, `.csv`) for
/// display in `FileViewerView`, instead of handing it to whatever app macOS
/// has registered as the default handler. That default-handler route (via
/// `NSWorkspace.shared.open`) is what made the Files tab's "Open" button
/// feel slow or hung in practice — a cold Xcode launch to view a `.plist`,
/// or TextEdit choking while rendering a multi-megabyte `.txt` dump like
/// spindump.txt. Reading the file ourselves and rendering it the same
/// lightweight, LazyVStack-of-lines way TroubleshootingTabView already
/// renders log query output is dramatically faster and has no external
/// dependency.
enum FileTextLoader {
    struct Loaded {
        var lines: [String]
        var totalLines: Int
        var truncated: Bool
    }

    /// Plain `String` doesn't conform to `Error`, so `Result<Loaded, String>`
    /// won't compile — this is just a message wrapper to satisfy `Result`.
    struct LoadError: Error {
        let message: String
    }

    /// Caps how many lines get rendered so a huge dump can't make the
    /// viewer itself slow — matches the cap TroubleshootingTabView uses for
    /// log query results.
    static let lineCap = 4000

    /// Extensions the fast in-app viewer(s) can render directly — shared by
    /// the Files tab and the Log Stream window's "open alongside" file
    /// picker, so both agree on what counts as viewable without the list
    /// drifting between two separate copies.
    static let viewableExtensions: Set<String> = ["txt", "log", "plist", "json", "csv"]

    static func load(path: String) -> Result<Loaded, LoadError> {
        let url = URL(fileURLWithPath: path)
        guard let data = try? Data(contentsOf: url) else {
            return .failure(LoadError(message: "Couldn't read this file."))
        }

        let text: String
        if url.pathExtension.lowercased() == "plist", let pretty = prettyPlist(data) {
            text = pretty
        } else {
            text = String(data: data, encoding: .utf8) ?? String(decoding: data, as: UTF8.self)
        }

        var lines = text.components(separatedBy: "\n")
        let total = lines.count
        let truncated = total > lineCap
        if truncated {
            lines = Array(lines.prefix(lineCap))
        }
        return .success(Loaded(lines: lines, totalLines: total, truncated: truncated))
    }

    /// Like `load`, but returns every line with no cap at all. Used by the
    /// Log Stream window's companion file pane, which has to search the
    /// *entire* file for the line nearest a target timestamp — capping to
    /// the first `lineCap` lines the way `load` does for the Files tab
    /// viewer could hide the very moment being searched for if it falls
    /// later in a large file.
    static func loadAllLines(path: String) -> Result<[String], LoadError> {
        let url = URL(fileURLWithPath: path)
        guard let data = try? Data(contentsOf: url) else {
            return .failure(LoadError(message: "Couldn't read this file."))
        }

        let text: String
        if url.pathExtension.lowercased() == "plist", let pretty = prettyPlist(data) {
            text = pretty
        } else {
            text = String(data: data, encoding: .utf8) ?? String(decoding: data, as: UTF8.self)
        }

        return .success(text.components(separatedBy: "\n"))
    }

    /// Re-serializes a binary/XML plist as readable XML text — the same
    /// idea as `plutil -p`/Xcode's plist editor, without spawning a process
    /// or waiting on an external app to launch.
    private static func prettyPlist(_ data: Data) -> String? {
        guard let plist = try? PropertyListSerialization.propertyList(from: data, options: [], format: nil),
              let xmlData = try? PropertyListSerialization.data(fromPropertyList: plist, format: .xml, options: 0) else {
            return nil
        }
        return String(data: xmlData, encoding: .utf8)
    }
}
