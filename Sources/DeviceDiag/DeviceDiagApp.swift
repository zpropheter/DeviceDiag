import SwiftUI

/// Receives files handed to the app by macOS — double-clicking a sysdiagnose
/// archive, using Finder's "Open With ▸ DeviceDiag", or dragging one onto
/// the Dock icon all route through `application(_:open:)`, not through
/// UploadView's own drag-and-drop. Requires the CFBundleDocumentTypes entry
/// in Packaging/Info.plist so Launch Services knows DeviceDiag can open
/// these files in the first place.
final class AppDelegate: NSObject, NSApplicationDelegate, ObservableObject {
    @Published var openedFilePaths: [String] = []

    /// Set once by `DeviceDiagApp` right after `AppState` exists, purely so
    /// `applicationWillTerminate` can reach it. With a single global result,
    /// starting a new analysis was always the moment the previous temp dir
    /// got cleaned up; now that several tabs can be open at once, quitting
    /// with more than one tab open is a real path with no "next analysis"
    /// to trigger that cleanup, so it has to happen here instead.
    weak var appState: AppState?

    func application(_ application: NSApplication, open urls: [URL]) {
        // Every one of them opens its own tab — dropping several sysdiagnoses
        // on the Dock icon (or "Open With ▸ DeviceDiag" on a multi-selection)
        // at once shouldn't silently drop all but the last.
        openedFilePaths = urls.map { $0.path }
        // Bring the (single, shared) window to the front — dropping a file
        // on the Dock icon while the window is behind something else, or
        // minimized, should surface it rather than opening silently behind
        // whatever's frontmost.
        NSApp.activate(ignoringOtherApps: true)
    }

    func applicationWillTerminate(_ notification: Notification) {
        appState?.cleanupAll()
    }
}

@main
struct DeviceDiagApp: App {
    @NSApplicationDelegateAdaptor(AppDelegate.self) private var appDelegate
    @StateObject private var appState = AppState()
    @Environment(\.openWindow) private var openWindow

    var body: some Scene {
        // `Window` (singular), not `WindowGroup` — a `WindowGroup` lets
        // macOS spin up an entirely new window per "open a document" event
        // for an app that (like this one) declares CFBundleDocumentTypes,
        // which is exactly the "drag onto the Dock icon opens a second
        // window" bug this app doesn't want: every tab already lives in the
        // sidebar of one window, so a second window would just show a
        // second, redundant copy of the same sidebar. `Window` guarantees
        // there is only ever one, and file-open events reuse it.
        Window("DeviceDiag", id: "main") {
            RootView()
                .environmentObject(appState)
                .frame(minWidth: 980, minHeight: 680)
                // Cold launch (app wasn't already running — e.g. dropping a
                // file on the Dock icon, or double-clicking one) calls
                // `application(_:open:)` very early, typically before this
                // view has appeared and its `.onChange` below is even
                // subscribed. `@Published` doesn't replay a missed change to
                // a late subscriber, so without this the path was getting
                // set on the delegate and then silently never picked up —
                // the app would just launch to the empty landing page.
                // `.onAppear` catches that case by reading whatever's
                // already there; `.onChange` covers the warm-launch case
                // (app already running, a second file gets opened into it).
                .onAppear {
                    appDelegate.appState = appState
                    openPendingFilesIfAny()
                }
                .onChange(of: appDelegate.openedFilePaths) { _, _ in openPendingFilesIfAny() }
        }
        .windowResizability(.contentSize)
        .commands {
            CommandGroup(replacing: .newItem) {
                Button("New Analysis…") {
                    appState.newTab()
                }
                .keyboardShortcut("n", modifiers: .command)
            }
            CommandGroup(replacing: .help) {
                Button("DeviceDiag Help") {
                    openWindow(id: "help")
                }
                .keyboardShortcut("?", modifiers: .command)

                Divider()

                // Surfaces DiagnosticsLog's file (~/Library/Logs/DeviceDiag/
                // DeviceDiag.log) directly in Finder — the one place to look
                // when a large sysdiagnose intermittently hangs or comes back
                // empty and there's nothing left on screen to explain why.
                Button("Reveal Diagnostics Log") {
                    DiagnosticsLog.reveal()
                }
            }
        }

        // A separate, small `Window` rather than a sheet on the main window —
        // help should stay open and readable side-by-side with a report,
        // not block interaction with it the way a sheet would.
        Window("DeviceDiag Help", id: "help") {
            HelpView()
        }
        .windowResizability(.contentSize)
    }

    private func openPendingFilesIfAny() {
        guard !appDelegate.openedFilePaths.isEmpty else { return }
        let paths = appDelegate.openedFilePaths
        appDelegate.openedFilePaths = []
        // Opening files from outside the app (double-click, "Open With,"
        // Dock drop) always adds a new tab per file rather than replacing
        // whatever's already open — same intent as dropping a file into the
        // sidebar's "+" tab.
        appState.openDropped(paths: paths)
    }
}

/// Sidebar (every open sysdiagnose) + whichever one is currently selected,
/// showing that tab's own upload screen or results screen. `.id(session.id)`
/// on both branches is what keeps each tab's view-local `@State` (typed
/// paths, selected report tab, search text, scroll position, etc.) from
/// leaking into whichever tab is selected next — without it, SwiftUI treats
/// this as the same view being updated in place rather than a different
/// session's, since it's always the same spot in the view tree.
struct RootView: View {
    @EnvironmentObject var appState: AppState

    var body: some View {
        HStack(spacing: 0) {
            // Hidden on the very first, still-blank tab — a tab strip with
            // exactly one empty entry has nothing to switch between and is
            // just confusing. Appears once there's a second tab, or the
            // first one has actually loaded something.
            if appState.shouldShowSidebar {
                SessionSidebarView()
                    .frame(width: appState.sidebarCollapsed ? 52 : 220)
                Divider()
            }
            Group {
                if let session = appState.selectedSession {
                    if let result = session.result {
                        ResultsView(result: result, sessionID: session.id)
                            .id(session.id)
                    } else {
                        UploadView(sessionID: session.id)
                            .id(session.id)
                    }
                } else {
                    Color(nsColor: .windowBackgroundColor)
                }
            }
            .frame(maxWidth: .infinity, maxHeight: .infinity)
        }
        .animation(.default, value: appState.shouldShowSidebar)
        .animation(.default, value: appState.selectedSession?.result != nil)
        .animation(.default, value: appState.sidebarCollapsed)
    }
}
