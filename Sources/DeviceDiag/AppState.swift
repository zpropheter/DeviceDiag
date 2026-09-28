import Foundation
import SwiftUI

/// One open sysdiagnose analysis — its own upload/analyzing/result/error
/// state, entirely independent of every other open tab. `AppState` holds a
/// list of these instead of a single result so more than one sysdiagnose can
/// be open (and compared) at the same time via the sidebar tab list.
///
/// `@MainActor`: only ever constructed/read/mutated from `AppState` (itself
/// `@MainActor`) or from SwiftUI view bodies (implicitly main-actor), but
/// without this annotation the compiler still treats `troubleshootModel`'s
/// default value below as running in a plain, non-isolated context — since
/// a struct's synthesized initializer isn't isolated just because every
/// actual call site happens to be — and `TroubleshootingModel()`'s own
/// `@MainActor` initializer can't be called from there synchronously. This
/// is what that call site actually needs, not `troubleshootModel` becoming
/// lazy or optional.
@MainActor
struct AnalysisSession: Identifiable {
    let id = UUID()
    var result: AnalysisResult?
    var isAnalyzing = false
    var errorMessage: String?
    /// The expanded input path this tab was (or is being) analyzed from —
    /// used to detect "this exact file/folder is already open elsewhere"
    /// and redirect to it instead of running a duplicate analysis. Nil for
    /// a tab that's never had anything analyzed into it.
    var sourcePath: String?
    /// This tab's Troubleshooting query filters/results/companion-file
    /// state — owned here (rather than as `@State` on
    /// `TroubleshootingTabView`) so that view can be mounted only while the
    /// Troubleshooting report tab is actually selected, like every other
    /// tab, without losing anything when it's torn down. See
    /// `TroubleshootingModel` for the full reasoning — this used to be the
    /// source of a real, reproducible performance problem (permanently
    /// mounting that view to preserve its state made SwiftUI re-touch its
    /// entire tree on every window activate/deactivate and every tab
    /// switch). One instance per open sysdiagnose tab, since `let` here
    /// only means the *reference* to it never changes for this session —
    /// its own properties still mutate freely.
    let troubleshootModel = TroubleshootingModel()

    /// What shows in the sidebar tab row.
    var displayName: String {
        result?.name ?? "New Analysis"
    }
}

/// Holds every open analysis session and which one is currently showing, and
/// drives navigation between each tab's upload screen and results screen.
/// Equivalent to the Flask app's server-side session state (`_last_tmp_dirs`
/// + whatever was last rendered to `results.html`), extended to track more
/// than one at once.
@MainActor
final class AppState: ObservableObject {
    @Published var sessions: [AnalysisSession] = []
    @Published var selectedSessionID: UUID?

    /// The most recently selected report section (Device, Config Profiles,
    /// Troubleshooting, etc.), shared across every open sysdiagnose. When
    /// `linkReportTab` is on, switching which sysdiagnose is selected in the
    /// sidebar re-applies this so you land on the same section you were just
    /// looking at, instead of always landing back on Device.
    @Published var linkedReportTab: ResultsTab = .device
    /// On by default — turn off to have every sysdiagnose always open to
    /// Device when selected, regardless of what section you were last on.
    @Published var linkReportTab: Bool = true

    /// Narrows the sidebar to an icon-only strip so the report gets more
    /// width — toggled from the button at the bottom of the sidebar.
    @Published var sidebarCollapsed: Bool = false

    init() {
        // Never start on an empty sidebar — open to one blank upload tab.
        newTab()
    }

    var selectedSession: AnalysisSession? {
        guard let id = selectedSessionID else { return nil }
        return sessions.first { $0.id == id }
    }

    /// Hidden until there's actually something to switch between — a single
    /// freshly-launched tab that hasn't loaded anything yet shouldn't show a
    /// tab strip with one entry in it, since there's nothing to navigate.
    var shouldShowSidebar: Bool {
        sessions.count > 1 || sessions.contains { $0.result != nil }
    }

    /// Adds a fresh upload-screen tab and selects it — Cmd+N, and the
    /// sidebar's "+" button.
    func newTab() {
        let session = AnalysisSession()
        sessions.append(session)
        selectedSessionID = session.id
    }

    /// Opens a path directly into a brand-new tab and selects it — used by
    /// file-open events (double-click, "Open With," Dock drop), where the
    /// intent is always "add a tab," never "replace whatever's open."
    func openInNewTab(path: String) {
        let session = AnalysisSession()
        sessions.append(session)
        selectedSessionID = session.id
        analyze(path: path, in: session.id)
    }

    /// Closes a tab, cleaning up any temp directories it created. Selects a
    /// neighbor if the closed tab was selected; opens a fresh blank tab if
    /// that was the last one open, so the sidebar is never left empty.
    func closeTab(_ id: UUID) {
        guard let idx = sessions.firstIndex(where: { $0.id == id }) else { return }
        AnalysisEngine.cleanup(sessions[idx].result)
        sessions.remove(at: idx)

        if sessions.isEmpty {
            newTab()
            return
        }
        if selectedSessionID == id {
            selectedSessionID = sessions[min(idx, sessions.count - 1)].id
        }
    }

    /// Resets one tab back to its upload screen — that tab's own "Start
    /// Over," distinct from closing it outright.
    func startOver(_ id: UUID) {
        guard let idx = sessions.firstIndex(where: { $0.id == id }) else { return }
        AnalysisEngine.cleanup(sessions[idx].result)
        sessions[idx].result = nil
        sessions[idx].errorMessage = nil
        sessions[idx].sourcePath = nil
    }

    func clearError(_ id: UUID) {
        guard let idx = sessions.firstIndex(where: { $0.id == id }) else { return }
        sessions[idx].errorMessage = nil
    }

    func analyze(path: String, in id: UUID) {
        guard let idx = sessions.firstIndex(where: { $0.id == id }) else { return }
        let inputPath = path.trimmingCharacters(in: .whitespaces)
        guard !inputPath.isEmpty else {
            sessions[idx].errorMessage = "Please provide a file path or folder."
            return
        }
        let expanded = (inputPath as NSString).expandingTildeInPath

        // The exact same file/folder is already open in another tab —
        // switch to it instead of running a duplicate analysis. If the tab
        // we were about to use is still a pristine, never-touched blank
        // tab, drop it rather than leaving a redundant empty one behind.
        if let existing = sessions.first(where: { $0.id != id && $0.sourcePath == expanded }) {
            selectedSessionID = existing.id
            if sessions[idx].result == nil && sessions[idx].sourcePath == nil {
                sessions.remove(at: idx)
            }
            return
        }

        // Clean up temp dirs from this tab's previous analysis, if any —
        // every other open tab's temp dirs are untouched.
        AnalysisEngine.cleanup(sessions[idx].result)

        sessions[idx].sourcePath = expanded
        sessions[idx].isAnalyzing = true
        sessions[idx].errorMessage = nil

        Task.detached(priority: .userInitiated) {
            do {
                let analyzed = try AnalysisEngine.analyze(inputPath: inputPath)
                await MainActor.run {
                    guard let i = self.sessions.firstIndex(where: { $0.id == id }) else { return }
                    self.sessions[i].result = analyzed
                    self.sessions[i].isAnalyzing = false
                }
            } catch {
                DiagnosticsLog.error("Analysis failed for \(inputPath): \(error.localizedDescription)")
                await MainActor.run {
                    guard let i = self.sessions.firstIndex(where: { $0.id == id }) else { return }
                    self.sessions[i].errorMessage = error.localizedDescription
                    self.sessions[i].isAnalyzing = false
                }
            }
        }
    }

    /// Opens every path from a multi-file drop (sidebar, Dock icon, or
    /// "Open With") in one shot. If `primarySessionID` names a tab that's
    /// still blank (never analyzed), the first path analyzes directly into
    /// it — same as dropping one file there — instead of leaving that tab
    /// empty and opening a redundant extra one; every other path (and the
    /// first, if there's no such blank tab) gets its own new tab.
    func openDropped(paths: [String], primarySessionID: UUID? = nil) {
        guard !paths.isEmpty else { return }
        var remaining = paths
        if let primarySessionID,
           let idx = sessions.firstIndex(where: { $0.id == primarySessionID }),
           sessions[idx].result == nil, !sessions[idx].isAnalyzing {
            let first = remaining.removeFirst()
            analyze(path: first, in: primarySessionID)
        }
        for path in remaining {
            openInNewTab(path: path)
        }
    }

    /// Cleans up every open tab's temp directories — called on app quit.
    /// With a single global result, starting a new analysis was always the
    /// moment the previous temp dir got deleted; with several tabs open at
    /// once there may be no "next analysis" to trigger that, so this is the
    /// backstop that runs from `applicationWillTerminate`.
    func cleanupAll() {
        for session in sessions {
            AnalysisEngine.cleanup(session.result)
        }
    }
}
