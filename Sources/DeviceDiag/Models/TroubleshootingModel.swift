import Foundation

/// Everything about one open sysdiagnose's Troubleshooting tab that needs to
/// survive the tab being unmounted: query filters, results, the pinned
/// companion-file moment, and the multi-line copy selection. Owned by that
/// sysdiagnose's `AnalysisSession` (see `AppState.swift`) — one instance per
/// open tab — rather than living as `@State` on `TroubleshootingTabView`
/// itself.
///
/// The previous design kept `TroubleshootingTabView` permanently mounted
/// inside `ResultsView` (just `opacity`/`allowsHitTesting`-toggled while
/// looking at another report tab) specifically so its `@State` wouldn't be
/// thrown away when the view itself was torn down. That worked, but it meant
/// the view's entire tree — every picker, every popover, and any
/// already-run result rows — was permanently "live" in the SwiftUI view
/// graph, and got walked by SwiftUI/AppKit's own window-active-state update
/// on *every* window activate/deactivate (confirmed with Time Profiler:
/// `-[NSWindow resignKeyWindow]`'s notification cascade), and by every
/// ordinary re-render triggered by switching to a different report tab, even
/// while completely invisible. That's what caused real, reproducible 1-2s
/// hitches once a person had opened Troubleshooting even a single time.
///
/// Moving the state here instead means `TroubleshootingTabView` can be
/// mounted only while actually selected — exactly like every other report
/// tab — since tearing it down no longer throws anything away: the data
/// lives on this object, not on the view.
@MainActor
final class TroubleshootingModel: ObservableObject {
    @Published var category: String = ""
    @Published var topic: String = "" // only used for Custom category's Subsystem/Process type picker now
    @Published var customType: String = "" // "subsystem" | "process"
    @Published var customValue: String = ""

    // Timeframe is a free-typed amount + a Minutes/Days unit, rather than a
    // fixed 1-day/7-day/all picker — left blank, it queries all time. Kept
    // as a String (not Int?) so the field can hold "" without fighting
    // SwiftUI over what an empty numeric binding means.
    @Published var timeframeAmount: String = ""
    @Published var timeframeUnit: TimeframeUnit = .days

    // Predefined-category filter picker: a checkbox dropdown of the actual
    // process/subsystem/keyword terms pulled out of that category's topics
    // (see TroubleshootCatalog.filterOptions), plus any hand-typed
    // additions, so admins can mix and match facets across topics instead
    // of being locked into one topic's fixed predicate. `customOptions` is
    // reset whenever the category changes since it's specific to whichever
    // category's picker it was typed into.
    @Published var selectedTerms: Set<LogFilterTerm> = []
    @Published var customOptions: [CatalogFilterOption] = []
    @Published var showFilterPicker = false
    @Published var pendingCustomField: LogFilterTerm.Field = .process
    @Published var pendingCustomValue: String = ""

    // Severity-level filter — an exact multi-select over log show's own
    // messageType values (Debug/Info/Default/Error/Fault), independent of
    // category/topic. Not reset on category change, same reasoning as
    // timeframeAmount/timeframeUnit above: it's an orthogonal setting, not
    // something tied to a particular category.
    @Published var selectedLevels: Set<LogLevel> = []
    @Published var showLevelPicker = false
    @Published var isRunning = false
    @Published var showFilter = false
    @Published var queryResult: TroubleshootQueryResult?
    // Not `@Published` — nothing renders this directly, it's only ever
    // `.cancel()`'d or reassigned, and `Task` isn't `Equatable` anyway.
    var queryTask: Task<Void, Never>?
    @Published var findText = ""
    // Filtering (and highlighting) potentially many thousands of lines on
    // every keystroke was starting to feel heavy once highlighting was
    // added, so — same as Config Profiles — the actual filter runs off a
    // debounced copy.
    @Published var committedFindText = ""
    @Published var showFindBar = false

    // Results can run into the tens of thousands of lines for "All time"
    // queries. Rendering them all at once (even lazily) makes scrolling feel
    // heavy, so only `visibleLineCount` are shown at a time; "Load More"
    // reveals the next chunk. Export always writes the full, unpaginated set.
    @Published var visibleLineCount = 2000

    // Cross-file "open at this same moment" — click a result line to pin it
    // as the anchor, then use the file menu to open another sysdiagnose
    // file alongside it, scrolled/highlighted to whichever of its own lines
    // is closest in time. Tracked by the line's index into the *full*,
    // unpaginated `queryResult.lines` array (see `TroubleshootingTabView.
    // DisplayedLine`) rather than its text, so two identical log lines
    // (heartbeats, retries, repeated errors are extremely common) are never
    // conflated into "the same line."
    @Published var anchorLineIndex: Int?
    @Published var anchorTimestamp: Date?

    // Multi-line selection for copying several lines at once — tracked by
    // index into the full result set for the same reason `anchorLineIndex`
    // is.
    @Published var selectedLineIndices: Set<Int> = []

    @Published var companionFile: SysdiagFileEntry?
    @Published var companionLines: [String] = []
    @Published var companionMatchIndex: Int?
    @Published var companionLoading = false
    @Published var companionError: String?
}
