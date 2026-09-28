import AppKit
import SwiftUI

enum ResultsTab: Hashable {
    case device, declarations, profiles, networking, settings, troubleshoot, files, notes
}

struct TabInfo: Identifiable, Hashable {
    let id: ResultsTab
    let label: String
}

/// Equivalent of `results.html` — the tabbed report screen. One instance per
/// open tab; `sessionID` is only needed so "Start Over" can reset this one
/// tab's `AnalysisSession` without touching any other open tab.
struct ResultsView: View {
    @EnvironmentObject var appState: AppState
    let result: AnalysisResult
    let sessionID: UUID
    @State private var selectedTab: ResultsTab = .device

    /// Troubleshooting's query filters/results/companion-file state, owned
    /// by this sysdiagnose's `AnalysisSession` rather than by
    /// `TroubleshootingTabView` itself — see `TroubleshootingModel` for the
    /// full reasoning. That's what lets `body` below mount
    /// `TroubleshootingTabView` only while it's actually the selected tab,
    /// exactly like every other report tab, without losing anything when
    /// it's torn down. (An earlier version kept it permanently mounted,
    /// just opacity-toggled, specifically to avoid that loss — profiling a
    /// real, reproducible 1-2s hitch on every window activation, and on
    /// switching between *any* report tabs once Troubleshooting had been
    /// opened once, traced straight to that always-live tree being walked
    /// by SwiftUI on every such update.) Falls back to a throwaway instance
    /// if the session can't be found, which shouldn't happen in practice —
    /// this view only exists once `session.result` does.
    private var troubleshootModel: TroubleshootingModel {
        appState.sessions.first(where: { $0.id == sessionID })?.troubleshootModel ?? TroubleshootingModel()
    }

    private var availableTabs: [TabInfo] {
        var tabs: [TabInfo] = []
        tabs.append(TabInfo(id: .device, label: result.isMobile ? "📱 Device" : "💻 Device"))
        if result.declarations.found {
            let count = result.declarations.blueprints.count
            tabs.append(TabInfo(id: .declarations, label: count > 0 ? "📋 Declarations (\(count))" : "📋 Declarations"))
        }
        if result.configProfiles.found {
            tabs.append(TabInfo(id: .profiles, label: "🔒 Config Profiles (\(result.configProfiles.profiles.count))"))
        }
        if result.networkReport.found {
            tabs.append(TabInfo(id: .networking, label: "📶 Networking"))
        }
        if result.isMobile && result.settingsAttribution.found {
            tabs.append(TabInfo(id: .settings, label: "🗂 Settings (\(result.settingsAttribution.total))"))
        }
        tabs.append(TabInfo(id: .troubleshoot, label: "🔍 Troubleshooting"))
        tabs.append(TabInfo(id: .files, label: "📁 Files"))
        if !result.notes.isEmpty {
            tabs.append(TabInfo(id: .notes, label: "⚠️ Notes (\(result.notes.count))"))
        }
        return tabs
    }

    var body: some View {
        VStack(spacing: 0) {
            topBar
            Divider()
            tabBar
            Divider()
            // Troubleshooting is mounted only while it's the selected tab now,
            // same as every other one — its state lives on `troubleshootModel`
            // (owned by this sysdiagnose's `AnalysisSession`, not by the view),
            // so tearing the view down when you switch away no longer loses
            // anything.
            if selectedTab == .troubleshoot {
                // Gets the full width/height (no 1100pt cap, no outer
                // ScrollView) since it manages its own scrolling and long
                // monospaced log lines read better with the extra room.
                TroubleshootingTabView(model: troubleshootModel, archivePath: result.logArchivePath, sysdiagFiles: result.sysdiagFiles, isMobile: result.isMobile)
                    .padding(24)
                    .frame(maxWidth: .infinity, maxHeight: .infinity)
            } else if selectedTab == .profiles || selectedTab == .networking || selectedTab == .declarations {
                // Config Profiles, Networking, and Declarations all get a
                // plain vertical-only ScrollView with no forced minimum
                // width, rather than the bidirectional one below — none of
                // their tables actually have fixed-width columns that add
                // up to more than what's available even at the app's
                // smallest window size, so forcing extra width (and the
                // horizontal scrollbar that comes with it) was just making
                // people scroll sideways to see rows that would've fit fine
                // reflowed to whatever width they actually had.
                //
                // Declarations' flexible-width columns (Activations/
                // Configurations in the Blueprint table, Last Value in the
                // Status Key Paths table) are exactly why this matters
                // beyond just "less scrolling": a value like a raw
                // NSError description (softwareupdate's `failure-reason`,
                // say) has no line breaks of its own, and `Text` only
                // wraps a long single-line value like that when its
                // container gives it a genuinely bounded width to wrap
                // within. A `ScrollView` that includes `.horizontal` never
                // does that — offering unbounded width to scroll into is
                // the entire point of that axis — so that value rendered
                // as one arbitrarily long horizontally-scrolling line
                // instead of wrapping at the window's actual edge. The
                // vertical-only `ScrollView` here bounds the width like
                // normal, so `Text` wraps like normal.
                //
                // (Config Profiles has an additional, separate reason to
                // avoid the horizontal axis here too: it's built from
                // `LazyVStack` — see the comment in
                // `ConfigProfilesTabView` — and mixing an unused
                // `.horizontal` scroll axis into a `ScrollView` wrapping a
                // `LazyVStack` is a known SwiftUI trap where the lazy
                // stack's "what's currently visible" calculation gets
                // computed against the combined scroll offset instead of
                // just the vertical one, so cards outside the initial
                // viewport render inconsistently.)
                ScrollView(.vertical) {
                    otherTabContent
                        .padding(24)
                        .frame(maxWidth: .infinity, alignment: .leading)
                }
                .frame(maxWidth: .infinity, maxHeight: .infinity)
            } else {
                // Vertical-only used to be all this needed, but Device's
                // table (and the macOS Device Information + FileVault cards
                // sitting side by side) lay out with fixed widths that add
                // up to more than what's actually available once the
                // window is resized narrower than its full-screen width —
                // with only a vertical ScrollView, that overflow was
                // clipped at the trailing edge instead of reachable, which
                // is what "text isn't visible when resized" actually was.
                // Scrolling horizontally too means nothing is ever
                // unreachable, even though it doesn't reflow to fit.
                ScrollView([.vertical, .horizontal]) {
                    otherTabContent
                        .padding(24)
                        .frame(minWidth: 1100, alignment: .leading)
                }
                .frame(maxWidth: .infinity, maxHeight: .infinity)
            }
        }
        // Applied once at the root rather than on every individual Text: lets
        // people select/copy any text anywhere in the report (device info,
        // UUIDs, log lines, payload values, etc.) without hunting for which
        // fields happen to support it.
        .textSelection(.enabled)
        .onAppear {
            // Each sysdiagnose tab is its own `ResultsView` instance (see
            // `.id(session.id)` in RootView), so this runs fresh every time
            // you switch which one's selected in the sidebar. With "sync
            // tab" on, land on whatever section was last viewed anywhere
            // (falling back to Device if this sysdiagnose doesn't have that
            // section — e.g. it has no Settings tab); with it off, always
            // land on Device, same as before this existed.
            if appState.linkReportTab, availableTabs.contains(where: { $0.id == appState.linkedReportTab }) {
                selectedTab = appState.linkedReportTab
            } else if !availableTabs.contains(where: { $0.id == selectedTab }) {
                selectedTab = .device
            }
        }
        .onChange(of: selectedTab) { _, newValue in
            if appState.linkReportTab {
                appState.linkedReportTab = newValue
            }
        }
    }

    private var topBar: some View {
        HStack(spacing: 16) {
            Text("DeviceDiag").font(.headline)
            Text(result.name)
                .font(.system(.caption, design: .monospaced))
                .foregroundStyle(.secondary)
                .lineLimit(1)
                .truncationMode(.middle)
            Spacer()
            Text(result.analyzedAt).font(.caption).foregroundStyle(.secondary)
            Button("↺ Start Over") { appState.startOver(sessionID) }
                .buttonStyle(.link)
                .help("Reset this tab back to the upload screen")
        }
        .padding(.horizontal, 20)
        .frame(height: 48)
        .background(Color(nsColor: .windowBackgroundColor))
    }

    private var tabBar: some View {
        ScrollView(.horizontal, showsIndicators: false) {
            HStack(spacing: 4) {
                ForEach(availableTabs) { tab in
                    Button {
                        selectedTab = tab.id
                    } label: {
                        Text(tab.label)
                            .font(.system(size: 13, weight: selectedTab == tab.id ? .semibold : .regular))
                            .foregroundStyle(selectedTab == tab.id ? Color.accentColor : (tab.id == .notes ? Color.orange : Color.secondary))
                            .padding(.vertical, 10)
                            .padding(.horizontal, 4)
                            .overlay(alignment: .bottom) {
                                if selectedTab == tab.id {
                                    Rectangle().fill(Color.accentColor).frame(height: 2)
                                }
                            }
                            // `.buttonStyle(.plain)` otherwise only hit-tests
                            // the label's actual rendered content (the text
                            // glyphs), not the padding around it — clicking
                            // the blank space above/below a tab's label
                            // silently did nothing. This makes the button's
                            // whole padded frame clickable.
                            .contentShape(Rectangle())
                    }
                    .buttonStyle(.plain)
                }
            }
            .padding(.horizontal, 20)
        }
        .background(Color(nsColor: .windowBackgroundColor))
    }

    // Troubleshooting is handled separately in `body` (always mounted, just
    // hidden when not selected — see the comment there) so it's not part of
    // this switch at all.
    @ViewBuilder
    private var otherTabContent: some View {
        switch selectedTab {
        case .device: DeviceTabView(result: result)
        case .declarations: DeclarationsTabView(declarations: result.declarations, logArchivePath: result.logArchivePath, sysdiagFiles: result.sysdiagFiles)
        case .profiles: ConfigProfilesTabView(profiles: result.configProfiles, isMobile: result.isMobile)
        case .networking: NetworkingTabView(report: result.networkReport, wifiHistory: result.wifiHistory)
        case .settings: SettingsAttributionTabView(attribution: result.settingsAttribution)
        case .troubleshoot: EmptyView()
        case .files: FilesTabView(groups: result.sysdiagFiles)
        case .notes: NotesTabView(notes: result.notes)
        }
    }
}

// MARK: - Shared UI building blocks

struct CardView<Content: View>: View {
    var title: String?
    @ViewBuilder var content: Content

    var body: some View {
        VStack(alignment: .leading, spacing: 0) {
            if let title {
                Text(title)
                    .font(.system(size: 14, weight: .semibold))
                    .padding(.horizontal, 16)
                    .padding(.vertical, 10)
                    .frame(maxWidth: .infinity, alignment: .leading)
                    .background(Color.secondary.opacity(0.06))
                Divider()
            }
            content
        }
        .background(Color(nsColor: .controlBackgroundColor))
        .clipShape(RoundedRectangle(cornerRadius: 10))
        .overlay(RoundedRectangle(cornerRadius: 10).strokeBorder(Color.secondary.opacity(0.15)))
    }
}

struct InfoRow: View {
    var label: String
    var value: String
    var monospaced = true
    @Environment(\.findQuery) private var findQuery

    var body: some View {
        HStack(alignment: .top) {
            Text(label)
                .font(.system(size: 12))
                .foregroundStyle(.secondary)
                .frame(width: 190, alignment: .leading)
            HighlightedText(text: value, query: findQuery)
                .font(monospaced ? .system(size: 12, design: .monospaced) : .system(size: 12))
            Spacer(minLength: 0)
        }
        .padding(.horizontal, 16)
        .padding(.vertical, 7)
    }
}

struct Badge: View {
    var text: String
    var color: Color = .blue

    var body: some View {
        Text(text)
            .font(.system(size: 11, weight: .semibold))
            .padding(.horizontal, 8)
            .padding(.vertical, 2)
            .background(color.opacity(0.14))
            .foregroundStyle(color)
            .clipShape(Capsule())
    }
}

struct EmptyStateView: View {
    var text: String
    var body: some View {
        Text(text)
            .foregroundStyle(.secondary)
            .frame(maxWidth: .infinity)
            .padding(28)
    }
}
