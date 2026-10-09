import AppKit
import SwiftUI

enum TimeframeUnit: String, CaseIterable {
    case minutes, days

    /// The suffix `log show --last` expects.
    var suffix: String {
        switch self {
        case .minutes: return "m"
        case .days: return "d"
        }
    }

    var displayName: String {
        switch self {
        case .minutes: return "Minutes"
        case .days: return "Days"
        }
    }

    func label(for amount: Int) -> String {
        switch self {
        case .minutes: return amount == 1 ? "minute" : "minutes"
        case .days: return amount == 1 ? "day" : "days"
        }
    }
}

struct TroubleshootingTabView: View {
    // Owns none of this state directly — it all lives on `TroubleshootingModel`
    // (see that file for the full reasoning), persisted on this sysdiagnose's
    // `AnalysisSession` so it survives this view being mounted only while the
    // Troubleshooting tab is actually selected, same as every other report tab.
    @ObservedObject var model: TroubleshootingModel
    let archivePath: String?
    let sysdiagFiles: [SysdiagFileGroup]
    let isMobile: Bool

    @FocusState private var findFieldFocused: Bool

    // Results can run into the tens of thousands of lines for "All time"
    // queries. Rendering them all at once (even lazily) makes scrolling feel
    // heavy, so only `model.visibleLineCount` are shown at a time; "Load
    // More" reveals the next chunk. Export always writes the full,
    // unpaginated set.
    private let pageSize = 2000

    // The position (within whatever's currently displayed, not the full
    // result) of the last plain/Cmd-click — only meaningful for the instant
    // between one click and the next Shift-click that extends a range from
    // it, and only ever read right after a click. Unlike everything on
    // `TroubleshootingModel`, it's fine for this to reset to nil whenever
    // this view is torn down and rebuilt (switching away from this tab, or
    // search re-filtering what's on screen) — there's nothing meaningful to
    // lose.
    @State private var lastClickedIndex: Int?

    private var categories: [String] { TroubleshootCatalog.sortedCategories(isMobile: isMobile) }

    private var candidateFiles: [(group: String, files: [SysdiagFileEntry])] {
        FileInventory.viewableCandidates(from: sysdiagFiles)
    }

    private var hasCandidateFiles: Bool {
        candidateFiles.contains { !$0.files.isEmpty }
    }

    /// One rendered log line paired with its index into the full,
    /// unpaginated `queryResult.lines` array. `id` is that index, not the
    /// text, precisely so two rows with identical text (very common in a
    /// log — heartbeats, retries, repeated errors) are still two distinct,
    /// independently selectable/clickable rows to SwiftUI.
    private struct DisplayedLine: Identifiable {
        let index: Int
        let text: String
        var id: Int { index }
    }

    private var displayedLines: [DisplayedLine] {
        guard let lines = model.queryResult?.lines else { return [] }
        guard !model.committedFindText.isEmpty else {
            return Array(lines.prefix(model.visibleLineCount)).enumerated()
                .map { DisplayedLine(index: $0.offset, text: $0.element) }
        }
        // Searching runs over the complete result set — it's already in
        // memory, so there's no reason to hide unloaded matches from find.
        return lines.enumerated()
            .filter { $0.element.localizedCaseInsensitiveContains(model.committedFindText) }
            .map { DisplayedLine(index: $0.offset, text: $0.element) }
    }

    private var hasMoreLines: Bool {
        guard model.committedFindText.isEmpty, let total = model.queryResult?.lines.count else { return false }
        return model.visibleLineCount < total
    }

    /// Every checkable option for the current category's filter picker —
    /// the catalog-derived ones plus whatever's been hand-typed into this
    /// picker session, grouped by field (Process / Subsystem / Keyword) in
    /// that fixed order.
    private var groupedFilterOptions: [(field: LogFilterTerm.Field, options: [CatalogFilterOption])] {
        let all = TroubleshootCatalog.filterOptions(for: model.category, isMobile: isMobile) + model.customOptions
        let grouped = Dictionary(grouping: all, by: { $0.term.field })
        return LogFilterTerm.Field.allCases.compactMap { field in
            guard let options = grouped[field], !options.isEmpty else { return nil }
            return (field, options)
        }
    }

    private var filterButtonLabel: String {
        model.selectedTerms.isEmpty ? "Select filters…" : "\(model.selectedTerms.count) filter\(model.selectedTerms.count == 1 ? "" : "s") selected"
    }

    private var levelButtonLabel: String {
        model.selectedLevels.isEmpty ? "All levels" : model.selectedLevels.sorted { $0.sortRank < $1.sortRank }.map(\.displayName).joined(separator: ", ")
    }

    private func isLevelSelected(_ level: LogLevel) -> Binding<Bool> {
        Binding(
            get: { model.selectedLevels.contains(level) },
            set: { isOn in
                if isOn { model.selectedLevels.insert(level) } else { model.selectedLevels.remove(level) }
            }
        )
    }

    private var customFieldPlaceholder: String {
        switch model.pendingCustomField {
        case .process: return "processname"
        case .subsystem: return "com.example.subsystem"
        case .keyword: return "CategoryName"
        }
    }

    private func isSelected(_ term: LogFilterTerm) -> Binding<Bool> {
        Binding(
            get: { model.selectedTerms.contains(term) },
            set: { isOn in
                if isOn { model.selectedTerms.insert(term) } else { model.selectedTerms.remove(term) }
            }
        )
    }

    /// Adds whatever's typed into the picker's custom-term row as a new
    /// checked option — as a process this defaults to an exact match
    /// (`==`, matching how catalog process terms are usually written), and
    /// as a subsystem or keyword to a looser `CONTAINS` match (matching
    /// the old free-text "Custom" category's behavior), which is a more
    /// forgiving default for something typed by hand.
    private func addCustomTerm() {
        let value = model.pendingCustomValue.trimmingCharacters(in: .whitespaces)
        guard !value.isEmpty else { return }
        let op: LogFilterTerm.Op = model.pendingCustomField == .process ? .equals : .contains
        let term = LogFilterTerm(field: model.pendingCustomField, op: op, value: value)
        let alreadyListed = TroubleshootCatalog.filterOptions(for: model.category, isMobile: isMobile).contains { $0.term == term }
            || model.customOptions.contains { $0.term == term }
        if !alreadyListed {
            model.customOptions.append(CatalogFilterOption(term: term, topics: []))
        }
        model.selectedTerms.insert(term)
        model.pendingCustomValue = ""
    }

    var body: some View {
        CardView {
            VStack(spacing: 0) {
                toolbar
                if model.showFilter, let cmd = model.queryResult?.command {
                    Divider()
                    Text(cmd)
                        .font(.system(size: 11, design: .monospaced))
                        .padding(10)
                        .frame(maxWidth: .infinity, alignment: .leading)
                        .background(Color.secondary.opacity(0.06))
                }
                if model.showFindBar {
                    Divider()
                    findBar
                }
                Divider()
                if model.companionFile != nil {
                    HStack(spacing: 0) {
                        outputArea
                            .frame(maxWidth: .infinity, maxHeight: .infinity)
                        Divider()
                        companionPane
                            .frame(maxWidth: .infinity, maxHeight: .infinity)
                    }
                } else {
                    outputArea
                }
                if let result = model.queryResult, !result.lines.isEmpty {
                    Divider()
                    HStack {
                        Text(statusBarText(for: result))
                            .font(.caption2)
                            .foregroundStyle(.secondary)
                        Spacer()
                        if !model.selectedLineIndices.isEmpty {
                            Button("Clear Selection") { model.selectedLineIndices = []; lastClickedIndex = nil }
                                .buttonStyle(.borderless)
                                .controlSize(.small)
                            Button("Copy \(model.selectedLineIndices.count) Line\(model.selectedLineIndices.count == 1 ? "" : "s")", action: copySelectedLines)
                                .buttonStyle(.bordered)
                                .controlSize(.small)
                        }
                    }
                    .padding(.horizontal, 16).padding(.vertical, 6)
                    .background(Color.secondary.opacity(0.06))
                }
            }
            // Lets the card (and, in turn, outputArea's own maxHeight below)
            // grow to fill whatever space ResultsView hands this tab, rather
            // than hugging a fixed height — this is what makes the log
            // viewer actually get bigger when the window does.
            .frame(maxWidth: .infinity, maxHeight: .infinity)
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity)
        .environment(\.findQuery, model.committedFindText)
        .background(FindShortcut { model.showFindBar = true; findFieldFocused = true })
        .task(id: model.findText) {
            try? await Task.sleep(nanoseconds: 150_000_000)
            if !Task.isCancelled {
                model.committedFindText = model.findText
                // The line at a given *position* can change once search
                // re-filters `displayedLines` — `model.selectedLineIndices`
                // and `model.anchorLineIndex` themselves stay valid
                // (they're indices into the full, unfiltered
                // `queryResult.lines`, not positions in the filtered view),
                // but a stale `lastClickedIndex` (a position) could extend a
                // Shift-click range against the wrong set of rows, so only
                // that gets reset.
                lastClickedIndex = nil
            }
        }
        .onChange(of: model.anchorTimestamp) { _, _ in resyncCompanion() }
    }

    private func statusBarText(for result: TroubleshootQueryResult) -> String {
        var base = model.committedFindText.isEmpty
            ? "Showing \(displayedLines.count) of \(result.lines.count) lines — \(timeframeLabel)"
            : "\(displayedLines.count) of \(result.lines.count) lines match \"\(model.committedFindText)\""
        if hasCandidateFiles {
            base += " · Click a line, then use the file menu to open another file at that same moment."
        }
        return base
    }

    private var findBar: some View {
        FindBarView(placeholder: "Find in results", text: $model.findText,
                    matchCount: model.committedFindText.isEmpty ? nil : displayedLines.count,
                    isFocused: $findFieldFocused) {
            model.showFindBar = false
            model.findText = ""
        }
    }

    /// Parsed amount, or `nil` if the field is blank/not a positive integer
    /// — either way means "all time".
    private var parsedTimeframeAmount: Int? {
        let trimmed = model.timeframeAmount.trimmingCharacters(in: .whitespaces)
        guard let n = Int(trimmed), n > 0 else { return nil }
        return n
    }

    /// What actually gets passed to `log show --last`, e.g. `"30m"`/`"7d"` —
    /// `nil` when the amount field is blank, which queries all time.
    private var lastArgValue: String? {
        guard let n = parsedTimeframeAmount else { return nil }
        return "\(n)\(model.timeframeUnit.suffix)"
    }

    private var timeframeLabel: String {
        guard let n = parsedTimeframeAmount else { return "all time" }
        return "\(n) \(model.timeframeUnit.label(for: n))"
    }

    // This toolbar has the most controls of any single row in the app
    // (category, filters, levels, timeframe, run, plus the query/export/
    // open-alongside buttons once there's a result) — added up, their
    // widths already exceed the window's own enforced minimum size once
    // the sidebar's taking some of it too, which is what "buttons get cut
    // off when the window isn't full screen" actually was.
    //
    // A horizontal `ScrollView` was the first fix, but scrolling a toolbar
    // reads as things randomly disappearing off the edge rather than a
    // deliberate layout, and it only shrinks one control's worth of space
    // at a time as the window narrows rather than reflowing cleanly.
    // `ViewThatFits` instead offers two whole candidate layouts — the
    // normal single row, and a two-row split (query controls on top,
    // result actions below) — and SwiftUI picks whichever one actually
    // fits the available width, so it snaps to the two-row layout at one
    // clean breakpoint instead of degrading gradually. (This only works
    // measured against a real width constraint from the parent, which is
    // why there's no ScrollView around it: a ScrollView offers its content
    // an unconstrained width to grow into, so `ViewThatFits` would always
    // see "plenty of room" and never pick the narrower candidate.)
    private var toolbar: some View {
        ViewThatFits(in: .horizontal) {
            HStack(spacing: 10) {
                queryControls
                Spacer(minLength: 12)
                resultActions
            }
            .padding(12)
            VStack(alignment: .leading, spacing: 8) {
                HStack(spacing: 10) {
                    queryControls
                    Spacer(minLength: 0)
                }
                if hasResultActions {
                    HStack(spacing: 10) {
                        resultActions
                        Spacer(minLength: 0)
                    }
                }
            }
            .padding(12)
        }
    }

    /// Category/Custom-type/Filters, Levels, Timeframe, and Run — the
    /// controls that build and fire a query. Bare content (no enclosing
    /// `HStack`) since `toolbar` above embeds this in two different
    /// layouts depending on how much width is actually available.
    @ViewBuilder
    private var queryControls: some View {
        Text("Category").font(.caption).bold()
        Picker("", selection: $model.category) {
            Text("— Select a category —").tag("")
            ForEach(categories, id: \.self) { Text($0).tag($0) }
            Text("Custom").tag("Custom")
        }
        .labelsHidden()
        .frame(width: 200)
        .onChange(of: model.category) { _, _ in categoryChanged() }

        if model.category == "Custom" {
            Text(model.customType.isEmpty ? "Type" : model.customType.capitalized).font(.caption).bold()
            if model.customType.isEmpty {
                Picker("", selection: $model.topic) {
                    Text("— Select a type —").tag("")
                    Text("Subsystem").tag("Subsystem")
                    Text("Process").tag("Process")
                }
                .labelsHidden()
                .frame(width: 160)
                .onChange(of: model.topic) { _, newVal in
                    if !newVal.isEmpty { model.customType = newVal.lowercased() }
                }
            } else {
                TextField(model.customType == "process" ? "yourprocess" : "com.app.example", text: $model.customValue)
                    .textFieldStyle(.roundedBorder)
                    .font(.system(.caption, design: .monospaced))
                    .frame(width: 200)
                    .onSubmit(runQuery)
            }
        } else {
            Text("Filters").font(.caption).bold()
            Button {
                model.showFilterPicker = true
            } label: {
                HStack(spacing: 4) {
                    Text(filterButtonLabel).lineLimit(1)
                    Image(systemName: "chevron.down").font(.caption2)
                }
                .frame(minWidth: 180, alignment: .leading)
            }
            .disabled(model.category.isEmpty)
            .popover(isPresented: $model.showFilterPicker, arrowEdge: .bottom) {
                filterPickerPopover
            }
        }

        Text("Levels").font(.caption).bold()
        Button {
            model.showLevelPicker = true
        } label: {
            HStack(spacing: 4) {
                Text(levelButtonLabel).lineLimit(1)
                Image(systemName: "chevron.down").font(.caption2)
            }
            .frame(minWidth: 110, maxWidth: 160, alignment: .leading)
        }
        .popover(isPresented: $model.showLevelPicker, arrowEdge: .bottom) {
            levelPickerPopover
        }

        Text("Timeframe").font(.caption).bold()
        TextField("All", text: $model.timeframeAmount)
            .textFieldStyle(.roundedBorder)
            .multilineTextAlignment(.trailing)
            .frame(width: 46)
            .onChange(of: model.timeframeAmount) { _, newValue in
                let digitsOnly = newValue.filter(\.isNumber)
                if digitsOnly != newValue { model.timeframeAmount = digitsOnly }
            }
            .onSubmit(runQuery)
            .help("Leave blank to query all time")
        Picker("", selection: $model.timeframeUnit) {
            ForEach(TimeframeUnit.allCases, id: \.self) { Text($0.displayName).tag($0) }
        }
        .labelsHidden()
        .frame(width: 100)

        // A single, explicit action to actually run the query — kept
        // separate from anything inside the filter picker (see
        // filterPickerPopover's "Done" button) so checking boxes there
        // can never itself fire a query off by accident.
        Button("Run", action: runQuery)
            .buttonStyle(.borderedProminent)
            .disabled(!canRun)
    }

    /// Show/Hide Query, Export, and Open Alongside — everything that acts
    /// on a query that's already run, kept separate from `queryControls`
    /// so `toolbar` can put it on its own row once there isn't width for
    /// one long line.
    @ViewBuilder
    private var resultActions: some View {
        if model.queryResult?.command != nil {
            // Renamed from "Show/Hide Filter" now that "Filters" is
            // also the label on the checkbox dropdown above — this one
            // reveals the literal `log show` command that was run, which
            // is a different thing.
            Button(model.showFilter ? "Hide Query" : "Show Query") { model.showFilter.toggle() }
                .buttonStyle(.bordered).controlSize(.small)
        }
        if let result = model.queryResult, !result.lines.isEmpty {
            Button("Export") { exportLog(result.lines) }
                .buttonStyle(.bordered).controlSize(.small)
                .tint(.green)
        }
        if hasCandidateFiles, let result = model.queryResult, !result.lines.isEmpty {
            openAlongsideMenu
        }
    }

    private var hasResultActions: Bool {
        model.queryResult?.command != nil || !(model.queryResult?.lines.isEmpty ?? true)
    }

    private var canRun: Bool {
        if model.category == "Custom" {
            return !model.customType.isEmpty && !model.customValue.trimmingCharacters(in: .whitespaces).isEmpty
        }
        return !model.category.isEmpty && !model.selectedTerms.isEmpty
    }

    /// The checkbox dropdown itself: every available term for the current
    /// category, grouped by field, with a row at the bottom to type in a
    /// process/subsystem/keyword that isn't already covered by a catalog
    /// topic. Nothing in here runs a query — checking/unchecking boxes and
    /// adding custom terms just updates `model.selectedTerms`, which is
    /// retained as-is when the picker closes (whether via "Done" or
    /// clicking outside). The only way to actually run anything is the
    /// toolbar's "Run" button, once a timeframe (or none, for all time) is
    /// chosen.
    private var filterPickerPopover: some View {
        VStack(alignment: .leading, spacing: 0) {
            Text("Filter — \(model.category)")
                .font(.system(size: 12, weight: .semibold))
                .padding(12)
            Divider()
            ScrollView {
                VStack(alignment: .leading, spacing: 14) {
                    ForEach(groupedFilterOptions, id: \.field) { entry in
                        VStack(alignment: .leading, spacing: 4) {
                            Text(entry.field.displayName)
                                .font(.caption).bold()
                                .foregroundStyle(.secondary)
                            ForEach(entry.options) { option in
                                Toggle(isOn: isSelected(option.term)) {
                                    HStack(spacing: 5) {
                                        Text(option.term.value)
                                            .font(.system(size: 12, design: .monospaced))
                                        Text(option.topicsLabel)
                                            .font(.caption2)
                                            .foregroundStyle(.secondary)
                                            .lineLimit(1)
                                    }
                                }
                                .toggleStyle(.checkbox)
                            }
                        }
                    }
                    if groupedFilterOptions.isEmpty {
                        Text("No predefined filters for this category yet — add one below.")
                            .font(.caption).foregroundStyle(.secondary)
                    }
                }
                .padding(12)
            }
            .frame(maxHeight: 320)
            Divider()
            HStack(spacing: 6) {
                Picker("", selection: $model.pendingCustomField) {
                    ForEach(LogFilterTerm.Field.allCases, id: \.self) { Text($0.displayName).tag($0) }
                }
                .labelsHidden()
                .frame(width: 110)
                TextField(customFieldPlaceholder, text: $model.pendingCustomValue)
                    .textFieldStyle(.roundedBorder)
                    .font(.system(.caption, design: .monospaced))
                    .onSubmit(addCustomTerm)
                Button("Add", action: addCustomTerm)
                    .buttonStyle(.bordered)
                    .controlSize(.small)
                    .disabled(model.pendingCustomValue.trimmingCharacters(in: .whitespaces).isEmpty)
            }
            .padding(10)
            Divider()
            HStack {
                Button("Clear") { model.selectedTerms.removeAll() }
                    .buttonStyle(.borderless)
                    .disabled(model.selectedTerms.isEmpty)
                Spacer()
                // Just closes the picker — checked boxes are already
                // reflected in `model.selectedTerms` and stay that way.
                // Running the query is a separate, deliberate step via the
                // toolbar's "Run" button, once a timeframe's chosen too.
                Button("Done") { model.showFilterPicker = false }
                    .buttonStyle(.borderedProminent)
            }
            .padding(10)
        }
        .frame(width: 380)
    }

    /// Same shape as `filterPickerPopover` — checking/unchecking a level
    /// just updates `model.selectedLevels`, nothing runs until "Run". An
    /// empty selection (the default) means every level shows, same as
    /// before this existed.
    private var levelPickerPopover: some View {
        VStack(alignment: .leading, spacing: 0) {
            Text("Severity levels")
                .font(.system(size: 12, weight: .semibold))
                .padding(12)
            Divider()
            VStack(alignment: .leading, spacing: 4) {
                ForEach(LogLevel.allCases.sorted { $0.sortRank < $1.sortRank }) { level in
                    Toggle(level.displayName, isOn: isLevelSelected(level))
                        .toggleStyle(.checkbox)
                        .font(.system(size: 12))
                }
            }
            .padding(12)
            Divider()
            HStack {
                Button("Clear") { model.selectedLevels.removeAll() }
                    .buttonStyle(.borderless)
                    .disabled(model.selectedLevels.isEmpty)
                Spacer()
                Button("Done") { model.showLevelPicker = false }
                    .buttonStyle(.borderedProminent)
            }
            .padding(10)
        }
        .frame(width: 220)
    }

    /// Lists every openable sysdiagnose file, grouped like the Files tab,
    /// for the currently pinned "anchor" line (see `model.anchorLineIndex`)
    /// to be compared against. This is what "open another file at this
    /// same moment" actually means in practice — the file opens in a
    /// companion pane scrolled/highlighted to whichever of its own lines is
    /// closest in time to the clicked result line.
    @ViewBuilder
    private var openAlongsideMenu: some View {
        Menu {
            if model.companionFile != nil {
                Button("Close Companion File", systemImage: "xmark.circle") {
                    closeCompanion()
                }
                Divider()
            }
            ForEach(candidateFiles, id: \.group) { group in
                Section(header: Text(group.group)) {
                    ForEach(group.files) { file in
                        Button(file.name) {
                            openCompanion(file)
                        }
                    }
                }
            }
        } label: {
            Label(model.companionFile.map { "Alongside: \($0.name)" } ?? "Open File Alongside…",
                  systemImage: "rectangle.split.2x1")
        }
        .controlSize(.small)
        .fixedSize()
    }

    @ViewBuilder
    private var outputArea: some View {
        ScrollView {
            if model.isRunning {
                HStack(spacing: 10) {
                    ProgressView().controlSize(.small)
                    Text("Running log query…").foregroundStyle(.secondary)
                }
                .frame(maxWidth: .infinity, minHeight: 240)
            } else if let result = model.queryResult {
                if let error = result.error {
                    Text("⚠ \(error)").foregroundStyle(.orange).padding(20)
                } else if result.lines.isEmpty {
                    Text("(No matching log entries found for \(timeframeLabel))")
                        .foregroundStyle(.secondary)
                        .padding(20)
                } else if !model.committedFindText.isEmpty && displayedLines.isEmpty {
                    Text("No lines match \"\(model.committedFindText)\".")
                        .foregroundStyle(.secondary)
                        .padding(20)
                } else {
                    let lines = displayedLines
                    LazyVStack(alignment: .leading, spacing: 0) {
                        ForEach(lines.indices, id: \.self) { pos in
                            let line = lines[pos]
                            // Each row is one whole log entry (timestamp,
                            // process, message — everything `log show`
                            // printed for that line), selected and copied
                            // as a single unit rather than as arbitrary
                            // character ranges within it. This used to
                            // layer a plain click on top of SwiftUI's own
                            // `.textSelection(.enabled)` (inherited from
                            // ResultsView's root) via `.simultaneousGesture`,
                            // so a click-drag could still select/copy a
                            // sub-string of one line the native way — but
                            // that meant two gesture recognizers (the tap,
                            // and text selection's own drag) were competing
                            // for the same pointer events, which is almost
                            // certainly why clicking a line to pin the
                            // companion-file anchor felt unreliable.
                            // `.textSelection(.disabled)` below removes that
                            // competing recognizer entirely — a click now
                            // always does exactly one thing: select (and
                            // pin) this whole row — and copying is solely
                            // the job of the selection model: the status
                            // bar's "Copy N Lines" button, or right-click.
                            HighlightedText(text: line.text, query: model.committedFindText)
                                .font(.system(size: 11, design: .monospaced))
                                .frame(maxWidth: .infinity, alignment: .leading)
                                .padding(.horizontal, 16).padding(.vertical, 3)
                                .background(rowBackground(pos: pos, line: line))
                                .contentShape(Rectangle())
                                .textSelection(.disabled)
                                .onTapGesture { handleLineClick(line, pos: pos, in: lines) }
                                .contextMenu {
                                    let toCopy = linesToCopy(rightClicking: line)
                                    Button(toCopy.count == 1 ? "Copy Line" : "Copy \(toCopy.count) Lines") {
                                        copyToPasteboard(toCopy)
                                    }
                                }
                                .help(lineRowHelp)
                        }
                        if hasMoreLines {
                            Button {
                                model.visibleLineCount = min(model.visibleLineCount + pageSize, result.lines.count)
                            } label: {
                                Text("Load \(min(pageSize, result.lines.count - model.visibleLineCount)) More Lines")
                                    .font(.caption)
                                    .frame(maxWidth: .infinity)
                            }
                            .buttonStyle(.bordered)
                            .controlSize(.small)
                            .padding(.horizontal, 16).padding(.vertical, 12)
                        }
                    }
                }
            } else {
                VStack(spacing: 6) {
                    Text("Select a category above, then choose filters (or pick Custom) to query the unified log.")
                        .foregroundStyle(.secondary)
                    if (archivePath ?? "").isEmpty {
                        Text("⚠ No logarchive found in this sysdiagnose — queries will not return results.")
                            .font(.caption2).foregroundStyle(.orange)
                    }
                }
                .frame(maxWidth: .infinity, minHeight: 240)
                .italic()
            }
        }
        // No maxHeight cap — this is the one part of the tab meant to grow
        // with the window, so longer log lines have real room to read.
        .frame(minHeight: 320, maxHeight: .infinity)
    }

    private func rowBackground(pos: Int, line: DisplayedLine) -> Color {
        if model.selectedLineIndices.contains(line.index) { return Color.accentColor.opacity(0.30) }
        if line.index == model.anchorLineIndex { return Color.accentColor.opacity(0.18) }
        return pos.isMultiple(of: 2) ? Color.secondary.opacity(0.13) : Color.clear
    }

    private var lineRowHelp: String {
        var parts = [
            "Click to select (Shift-click for a range, Cmd-click to add/remove one)",
            "right-click to copy",
        ]
        if hasCandidateFiles {
            parts.append("a plain click also pins this moment for the companion file")
        }
        return parts.joined(separator: " — ")
    }

    /// Click = select just this line, by its index into the full result
    /// set (and, preserving the previous behavior, pin it as the
    /// companion-file anchor). Shift-click extends a contiguous *visual*
    /// range — from wherever was clicked last to this one, among whatever
    /// is currently on screen — which is why that part of the math still
    /// uses `pos` (position within `displayed`) rather than `line.index`;
    /// a Shift-click should select what's visually between two rows, not
    /// try to span the gaps search may have filtered out in between.
    /// Cmd-click toggles this one line in or out of the selection without
    /// touching the rest — same three conventions as a Finder or Mail
    /// list.
    private func handleLineClick(_ line: DisplayedLine, pos: Int, in displayed: [DisplayedLine]) {
        let flags = NSEvent.modifierFlags
        if flags.contains(.shift), let last = lastClickedIndex, displayed.indices.contains(last) {
            let lo = min(last, pos), hi = max(last, pos)
            model.selectedLineIndices.formUnion(displayed[lo...hi].map(\.index))
        } else if flags.contains(.command) {
            if model.selectedLineIndices.contains(line.index) {
                model.selectedLineIndices.remove(line.index)
            } else {
                model.selectedLineIndices.insert(line.index)
            }
            lastClickedIndex = pos
        } else {
            model.selectedLineIndices = [line.index]
            lastClickedIndex = pos
            selectLine(line)
        }
    }

    /// Every selected line's text, in the order it appears in the full
    /// result (not click order) — sorting the selected indices themselves
    /// does this directly, and correctly, regardless of whatever
    /// pagination/search happens to be showing right now.
    private var orderedSelectedLines: [String] {
        guard !model.selectedLineIndices.isEmpty, let lines = model.queryResult?.lines else { return [] }
        return model.selectedLineIndices.sorted().compactMap { lines.indices.contains($0) ? lines[$0] : nil }
    }

    /// What a right-click "Copy" on `line` should act on: the current
    /// multi-selection, if `line` is part of it, or just `line` by itself
    /// otherwise — the same way right-clicking an item Finder doesn't
    /// currently have selected acts on just that item rather than a stale
    /// selection elsewhere in the list.
    private func linesToCopy(rightClicking line: DisplayedLine) -> [String] {
        guard let lines = model.queryResult?.lines else { return [] }
        let indices = model.selectedLineIndices.contains(line.index) ? model.selectedLineIndices : [line.index]
        return indices.sorted().compactMap { lines.indices.contains($0) ? lines[$0] : nil }
    }

    private func copySelectedLines() {
        copyToPasteboard(orderedSelectedLines)
    }

    /// Joins the given lines with newlines and puts the result on the
    /// pasteboard, as one plain-text block reading like the original log
    /// stream — shared by the status bar's "Copy N Lines" button and each
    /// row's right-click "Copy" menu item.
    private func copyToPasteboard(_ lines: [String]) {
        guard !lines.isEmpty else { return }
        NSPasteboard.general.clearContents()
        NSPasteboard.general.setString(lines.joined(separator: "\n"), forType: .string)
    }

    @ViewBuilder
    private var companionPane: some View {
        if let companionFile = model.companionFile {
            VStack(spacing: 0) {
                HStack(spacing: 8) {
                    Text(companionFile.name)
                        .font(.system(size: 12, weight: .semibold))
                        .lineLimit(1)
                        .truncationMode(.middle)
                    Spacer()
                    if model.companionLoading {
                        ProgressView().controlSize(.small)
                    } else if model.companionMatchIndex == nil {
                        Text("No matching timestamp found in this file")
                            .font(.caption2)
                            .foregroundStyle(.secondary)
                    }
                    Button {
                        closeCompanion()
                    } label: {
                        Image(systemName: "xmark.circle.fill")
                    }
                    .buttonStyle(.plain)
                    .foregroundStyle(.secondary)
                    .help("Close this file")
                }
                .padding(.horizontal, 12)
                .padding(.vertical, 8)
                .background(Color.secondary.opacity(0.06))
                Divider()

                if model.companionLoading {
                    VStack(spacing: 10) {
                        ProgressView()
                        Text("Reading \(companionFile.name)…").font(.caption).foregroundStyle(.secondary)
                    }
                    .frame(maxWidth: .infinity, maxHeight: .infinity)
                } else if let companionError = model.companionError {
                    Text(companionError)
                        .foregroundStyle(.secondary)
                        .frame(maxWidth: .infinity, maxHeight: .infinity)
                } else {
                    ScrollViewReader { proxy in
                        ScrollView {
                            LazyVStack(alignment: .leading, spacing: 0) {
                                ForEach(model.companionLines.indices, id: \.self) { idx in
                                    Text(model.companionLines[idx].isEmpty ? " " : model.companionLines[idx])
                                        .font(.system(size: 10, design: .monospaced))
                                        .frame(maxWidth: .infinity, alignment: .leading)
                                        .padding(.horizontal, 10)
                                        .padding(.vertical, 1)
                                        .background(companionRowBackground(idx))
                                        .id(idx)
                                }
                            }
                        }
                        .onAppear {
                            if let match = model.companionMatchIndex {
                                proxy.scrollTo(match, anchor: .center)
                            }
                        }
                        .onChange(of: model.companionMatchIndex) { _, newValue in
                            guard let newValue else { return }
                            withAnimation { proxy.scrollTo(newValue, anchor: .center) }
                        }
                    }
                }
            }
        }
    }

    private func companionRowBackground(_ idx: Int) -> Color {
        if idx == model.companionMatchIndex { return Color.orange.opacity(0.25) }
        return idx.isMultiple(of: 2) ? Color.secondary.opacity(0.05) : Color.clear
    }

    private func selectLine(_ line: DisplayedLine) {
        guard let ts = TimestampLineMatcher.leadingISOTimestamp(in: line.text) else { return }
        model.anchorLineIndex = line.index
        model.anchorTimestamp = ts
    }

    private func openCompanion(_ file: SysdiagFileEntry) {
        model.companionFile = file
        model.companionError = nil
        model.companionMatchIndex = nil
        model.companionLines = []
        loadCompanion(file)
    }

    private func closeCompanion() {
        model.companionFile = nil
        model.companionLines = []
        model.companionMatchIndex = nil
        model.companionError = nil
        model.companionLoading = false
    }

    /// Clears everything about the companion pane, the pinned anchor, and
    /// the multi-line copy selection — run whenever a new query starts,
    /// since none of them almost certainly exist in the new result set.
    private func resetCompanionState() {
        model.anchorLineIndex = nil
        model.anchorTimestamp = nil
        model.selectedLineIndices = []
        lastClickedIndex = nil
        closeCompanion()
    }

    private func loadCompanion(_ file: SysdiagFileEntry) {
        let model = self.model // captured once so the Task closure below doesn't need `self`
        guard let path = file.path else { return }
        model.companionLoading = true
        let target = model.anchorTimestamp ?? Date()

        Task.detached(priority: .userInitiated) {
            let result = FileTextLoader.loadAllLines(path: path)
            await MainActor.run {
                // The user may have closed this file (or opened a different
                // one) before the read finished — don't clobber whatever's
                // showing now with a stale result.
                guard model.companionFile?.id == file.id else { return }
                switch result {
                case .success(let lines):
                    model.companionLines = lines
                    model.companionMatchIndex = TimestampLineMatcher.nearestLine(to: target, in: lines)
                    model.companionLoading = false
                case .failure(let error):
                    model.companionError = error.message
                    model.companionLoading = false
                }
            }
        }
    }

    /// Re-runs the timestamp search against the already-loaded companion
    /// file whenever the anchor changes (i.e. a different result line was
    /// clicked) — no need to re-read the file from disk for that.
    private func resyncCompanion() {
        let model = self.model // captured once so the Task closure below doesn't need `self`
        guard model.companionFile != nil, !model.companionLines.isEmpty else { return }
        let target = model.anchorTimestamp ?? Date()
        let lines = model.companionLines
        Task.detached(priority: .userInitiated) {
            let match = TimestampLineMatcher.nearestLine(to: target, in: lines)
            await MainActor.run {
                model.companionMatchIndex = match
            }
        }
    }

    private func categoryChanged() {
        model.topic = ""
        model.customType = ""
        model.customValue = ""
        // Timeframe amount/unit deliberately isn't reset here — it's an
        // orthogonal setting, not something tied to a particular category.
        model.selectedTerms = []
        model.customOptions = []
        model.pendingCustomValue = ""
        model.showFilterPicker = false
        model.queryResult = nil
        model.showFilter = false
        model.showFindBar = false
        model.findText = ""
        model.committedFindText = ""
        model.visibleLineCount = pageSize
        model.queryTask?.cancel()
        resetCompanionState()
    }

    private func runQuery() {
        let model = self.model // captured once so the Task closures below don't need `self`
        model.queryTask?.cancel()
        guard let archivePath, !archivePath.isEmpty else {
            model.queryResult = TroubleshootQueryResult(error: "No logarchive available for this sysdiagnose.")
            return
        }

        let cat = model.category
        let last = lastArgValue
        let levels = model.selectedLevels

        if cat == "Custom" {
            let top = model.customValue.trimmingCharacters(in: .whitespaces)
            guard !top.isEmpty else { return }
            let cType = model.customType
            model.isRunning = true
            model.queryResult = nil
            model.findText = ""
            model.committedFindText = ""
            model.visibleLineCount = pageSize
            resetCompanionState()
            model.queryTask = Task.detached(priority: .userInitiated) {
                let result = LogArchiveService.runTroubleshootQuery(archive: archivePath, category: cat, topic: top, lastArg: last, customType: cType, levels: levels)
                if Task.isCancelled { return }
                await MainActor.run {
                    model.queryResult = result
                    model.isRunning = false
                }
            }
        } else {
            let terms = model.selectedTerms
            guard !terms.isEmpty else { return }
            model.isRunning = true
            model.queryResult = nil
            model.findText = ""
            model.committedFindText = ""
            model.visibleLineCount = pageSize
            resetCompanionState()
            model.queryTask = Task.detached(priority: .userInitiated) {
                let result = LogArchiveService.runTroubleshootFilterQuery(archive: archivePath, terms: terms, lastArg: last, levels: levels)
                if Task.isCancelled { return }
                await MainActor.run {
                    model.queryResult = result
                    model.isRunning = false
                }
            }
        }
    }

    private func exportLog(_ lines: [String]) {
        let label = model.category == "Custom"
            ? model.customValue
            : model.selectedTerms.map { $0.value }.sorted().joined(separator: "-")
        let tfPart = lastArgValue ?? "all"
        let safePart = "\(model.category)-\(label)-\(tfPart)"
            .lowercased()
            .replacingOccurrences(of: "[^a-z0-9]+", with: "-", options: .regularExpression)
        let filename = "sysdiagnose-\(safePart).log"
        _ = LogExportService.export(lines: lines, suggestedName: filename)
    }
}
