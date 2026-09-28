import AppKit
import Foundation

/// Port of the `/open-file` route — opens a sysdiagnose file in its default
/// macOS application via `NSWorkspace`.
enum FileOpener {
    enum Result {
        case opened
        case notFound(String)
        case failed(String)
    }

    static func open(path: String) -> Result {
        guard !path.isEmpty else { return .failed("No path provided.") }
        let resolved = URL(fileURLWithPath: path).resolvingSymlinksInPath()
        guard FileManager.default.fileExists(atPath: resolved.path) else {
            return .notFound("File no longer exists at:\n\(path)\n\nRe-run the analysis to restore access to the extracted files.")
        }
        let ok = NSWorkspace.shared.open(resolved)
        return ok ? .opened : .failed("Could not open file.")
    }

    /// Reveals a set of related files (e.g. launchd's per-UID dumps) all
    /// selected together in a single Finder window, rather than opening any
    /// one of them individually.
    static func revealMultiple(paths: [String]) -> Result {
        let urls = paths.compactMap { p -> URL? in
            let u = URL(fileURLWithPath: p).resolvingSymlinksInPath()
            return FileManager.default.fileExists(atPath: u.path) ? u : nil
        }
        guard !urls.isEmpty else {
            return .notFound("None of these files exist anymore.\n\nRe-run the analysis to restore access to the extracted files.")
        }
        NSWorkspace.shared.activateFileViewerSelecting(urls)
        return .opened
    }
}

/// Port of the `/export-log` route — shows a native save panel and writes the
/// exported log lines to the chosen path.
enum LogExportService {
    @MainActor
    static func export(lines: [String], suggestedName: String) -> Bool {
        guard !lines.isEmpty else { return false }
        let panel = NSSavePanel()
        panel.nameFieldStringValue = suggestedName
        panel.directoryURL = FileManager.default.urls(for: .desktopDirectory, in: .userDomainMask).first
        panel.canCreateDirectories = true

        let response = panel.runModal()
        guard response == .OK, let url = panel.url else { return false }

        let content = lines.joined(separator: "\n")
        do {
            try content.write(to: url, atomically: true, encoding: .utf8)
            return true
        } catch {
            return false
        }
    }
}
