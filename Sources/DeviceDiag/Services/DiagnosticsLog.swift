import AppKit
import Foundation
import os

/// A small, always-on log of DeviceDiag's *own* behavior — not to be
/// confused with `LogArchiveService`, which reads logs out of the
/// sysdiagnose being analyzed. Nothing recorded anything about the app's
/// own behavior before this: a slow/failed `tar` extraction, a `log show`
/// query that silently hit its timeout, or a caught `AnalysisError` only
/// ever showed up (if at all) as a transient error banner that vanished the
/// moment it was dismissed or the next analysis started. On a large
/// sysdiagnose where something intermittently hangs or comes back empty,
/// that leaves nothing to go on afterward — this exists so there's always
/// something concrete to look at.
///
/// Every entry also goes to the unified log via `os.Logger` (subsystem
/// `com.devicediag.app`) for live viewing/filtering in Console.app while
/// actively reproducing something, in addition to the persisted file
/// below, which doesn't require knowing an os_log subsystem to find.
enum DiagnosticsLog {
    private static let logger = Logger(subsystem: "com.devicediag.app", category: "general")

    /// `~/Library/Logs/DeviceDiag/DeviceDiag.log` — the standard per-user
    /// location macOS apps put their own log files, so it's where someone
    /// would already think to look (Console.app's "Log Reports" sidebar
    /// section surfaces `~/Library/Logs` automatically, too).
    static let fileURL: URL = {
        let base = FileManager.default.urls(for: .libraryDirectory, in: .userDomainMask)[0]
            .appendingPathComponent("Logs/DeviceDiag", isDirectory: true)
        try? FileManager.default.createDirectory(at: base, withIntermediateDirectories: true)
        return base.appendingPathComponent("DeviceDiag.log")
    }()

    private static let queue = DispatchQueue(label: "com.devicediag.diagnosticslog")
    /// Once the file passes this size, it's trimmed down to its newest
    /// half rather than left to grow forever across a long-running session.
    private static let maxBytes = 5 * 1024 * 1024

    private static let formatter: DateFormatter = {
        let f = DateFormatter()
        f.dateFormat = "yyyy-MM-dd HH:mm:ss.SSS"
        return f
    }()

    static func info(_ message: String) {
        write("INFO", message)
        logger.info("\(message, privacy: .public)")
    }

    static func error(_ message: String) {
        write("ERROR", message)
        logger.error("\(message, privacy: .public)")
    }

    private static func write(_ level: String, _ message: String) {
        let line = "\(formatter.string(from: Date())) [\(level)] \(message)\n"
        queue.async {
            guard let data = line.data(using: .utf8) else { return }
            if let handle = try? FileHandle(forWritingTo: fileURL) {
                defer { try? handle.close() }
                handle.seekToEndOfFile()
                handle.write(data)
            } else {
                try? data.write(to: fileURL)
            }
            trimIfNeeded()
        }
    }

    /// Drops the oldest half of the file once it passes `maxBytes`, so a
    /// trim still leaves recent context intact rather than wiping
    /// everything. Runs on `queue`, after every write, so it only ever
    /// looks at a file this same serial queue just finished writing to.
    private static func trimIfNeeded() {
        guard let attrs = try? FileManager.default.attributesOfItem(atPath: fileURL.path),
              let size = attrs[.size] as? Int, size > maxBytes,
              let text = try? String(contentsOf: fileURL, encoding: .utf8) else { return }
        let lines = text.components(separatedBy: "\n")
        let kept = lines.suffix(lines.count / 2).joined(separator: "\n")
        try? kept.data(using: .utf8)?.write(to: fileURL)
    }

    /// Reveals the log file in Finder — used by the Help menu/window's
    /// "Reveal Diagnostics Log" action.
    @MainActor
    static func reveal() {
        NSWorkspace.shared.activateFileViewerSelecting([fileURL])
    }
}
