import SwiftUI

/// Equivalent of `/log-stream` — a filtered, live-ish view of the logarchive
/// for one specific MDM status key path. Presented as a sheet from the
/// Declarations tab's "Open" action.
///
/// Also hosts the "open another file at this same moment" feature: clicking
/// a log line sets it as the anchor timestamp, and the file menu on the
/// right opens any other text-ish sysdiagnose file in a companion pane,
/// scrolled and highlighted to whichever of its own lines has the closest
/// timestamp — e.g. clicking a declaration error at 8:01 AM and opening
/// install.log alongside it jumps straight to 8:01 AM in that file too,
/// instead of making you scroll two files independently trying to line up
/// the same moment by eye.
struct LogStreamView: View {
    let archivePath: String
    let keyPath: String
    let sysdiagFiles: [SysdiagFileGroup]

    @Environment(\.dismiss) private var dismiss
    @State private var entries: [LogEntry] = []
    @State private var isLoading = true
    @State private var findText = ""
    @State private var showFindBar = false
    @FocusState private var findFieldFocused: Bool

    /// The log line currently "pinned" as the moment of interest — set by
    /// clicking a row, defaulting to the newest entry once entries load.
    /// Driving the companion pane off this (rather than off whatever's
    /// merely scrolled into view) is what makes "open at this timestamp"
    /// mean something specific and re-clickable, rather than a one-shot
    /// jump that immediately goes stale as you scroll either pane.
    @State private var selectedEntryID: UUID?
    @State private var anchorTimestamp: Date?

    @State private var companionFile: SysdiagFileEntry?
    @State private var companionLines: [String] = []
    @State private var companionMatchIndex: Int?
    @State private var companionLoading = false
    @State private var companionError: String?

    private var displayedEntries: [LogEntry] {
        let ordered = entries.reversed().map { $0 } // newest first, matches original
        guard !findText.isEmpty else { return ordered }
        return ordered.filter { $0.message.localizedCaseInsensitiveContains(findText) || $0.process.localizedCaseInsensitiveContains(findText) }
    }

    private var candidateFiles: [(group: String, files: [SysdiagFileEntry])] {
        FileInventory.viewableCandidates(from: sysdiagFiles)
    }

    private var hasCandidateFiles: Bool {
        candidateFiles.contains { !$0.files.isEmpty }
    }

    var body: some View {
        VStack(spacing: 0) {
            header
            Divider()
            if showFindBar {
                findBar
                Divider()
            }
            if companionFile != nil {
                HStack(spacing: 0) {
                    content
                        .frame(maxWidth: .infinity, maxHeight: .infinity)
                    Divider()
                    companionPane
                        .frame(maxWidth: .infinity, maxHeight: .infinity)
                }
            } else {
                content
            }
        }
        .frame(width: companionFile != nil ? 1180 : 720, height: 560)
        .animation(.default, value: companionFile != nil)
        // This sheet is its own view hierarchy rather than a child of
        // ResultsView (which sets this at its own root), so it needs its
        // own copy to make log lines and companion-file lines selectable —
        // otherwise SwiftUI's default (no selection) applies here too.
        .textSelection(.enabled)
        .background(FindShortcut { showFindBar = true; findFieldFocused = true })
        .task {
            let path = archivePath
            let kp = keyPath
            let result = await Task.detached(priority: .userInitiated) {
                LogArchiveService.readLogStream(archive: path, keyPath: kp)
            }.value
            entries = result
            isLoading = false
            if anchorTimestamp == nil, let newest = result.last {
                selectedEntryID = newest.id
                anchorTimestamp = TimestampLineMatcher.parseLogEntryTimestamp(newest.timestamp)
            }
        }
        .onChange(of: anchorTimestamp) { _, _ in resyncCompanion() }
    }

    private var header: some View {
        VStack(alignment: .leading, spacing: 4) {
            HStack(spacing: 10) {
                Text("📋 Log Stream").font(.headline)
                Text(keyPath)
                    .font(.system(size: 11, design: .monospaced))
                    .padding(.horizontal, 8).padding(.vertical, 2)
                    .background(Color.accentColor.opacity(0.12))
                    .foregroundStyle(Color.accentColor)
                    .clipShape(Capsule())
                Spacer()
                if !isLoading {
                    Text("\(displayedEntries.count) entries · last 24 h")
                        .font(.caption2)
                        .foregroundStyle(.secondary)
                }
                openAlongsideMenu
                Button("Done") { dismiss() }
                    .keyboardShortcut(.defaultAction)
            }
            if hasCandidateFiles && !isLoading {
                Text("Click a log line, then use the file menu to open another file at that same moment.")
                    .font(.caption2)
                    .foregroundStyle(.secondary)
            }
        }
        .padding(14)
    }

    @ViewBuilder
    private var openAlongsideMenu: some View {
        if hasCandidateFiles {
            Menu {
                if companionFile != nil {
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
                Label(companionFile.map { "Alongside: \($0.name)" } ?? "Open File Alongside…",
                      systemImage: "rectangle.split.2x1")
                    .font(.caption)
            }
            .menuStyle(.borderlessButton)
            .fixedSize()
        }
    }

    private var findBar: some View {
        FindBarView(placeholder: "Find in log stream", text: $findText,
                    matchCount: findText.isEmpty ? nil : displayedEntries.count,
                    isFocused: $findFieldFocused) {
            showFindBar = false
            findText = ""
        }
    }

    @ViewBuilder
    private var content: some View {
        if isLoading {
            VStack(spacing: 10) {
                ProgressView()
                Text("Querying logarchive…").font(.caption).foregroundStyle(.secondary)
            }
            .frame(maxWidth: .infinity, maxHeight: .infinity)
        } else if displayedEntries.isEmpty {
            Text(findText.isEmpty
                 ? "No matching log entries found in the last 24 hours of this archive."
                 : "No entries match \"\(findText)\".")
                .foregroundStyle(.secondary)
                .frame(maxWidth: .infinity, maxHeight: .infinity)
        } else {
            ScrollView {
                LazyVStack(alignment: .leading, spacing: 0) {
                    ForEach(Array(displayedEntries.enumerated()), id: \.1.id) { idx, entry in
                        LogStreamEntryRow(
                            entry: entry,
                            findQuery: findText,
                            isAnchor: entry.id == selectedEntryID,
                            onSelect: { selectEntry(entry) }
                        )
                        .background(idx.isMultiple(of: 2) ? Color.secondary.opacity(0.08) : Color.clear)
                    }
                }
            }
        }
    }

    @ViewBuilder
    private var companionPane: some View {
        if let companionFile {
            VStack(spacing: 0) {
                HStack(spacing: 8) {
                    Text(companionFile.name)
                        .font(.system(size: 12, weight: .semibold))
                        .lineLimit(1)
                        .truncationMode(.middle)
                    Spacer()
                    if companionLoading {
                        ProgressView().controlSize(.small)
                    } else if companionMatchIndex == nil {
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

                if companionLoading {
                    VStack(spacing: 10) {
                        ProgressView()
                        Text("Reading \(companionFile.name)…").font(.caption).foregroundStyle(.secondary)
                    }
                    .frame(maxWidth: .infinity, maxHeight: .infinity)
                } else if let companionError {
                    Text(companionError)
                        .foregroundStyle(.secondary)
                        .frame(maxWidth: .infinity, maxHeight: .infinity)
                } else {
                    ScrollViewReader { proxy in
                        ScrollView {
                            LazyVStack(alignment: .leading, spacing: 0) {
                                ForEach(companionLines.indices, id: \.self) { idx in
                                    Text(companionLines[idx].isEmpty ? " " : companionLines[idx])
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
                            if let match = companionMatchIndex {
                                proxy.scrollTo(match, anchor: .center)
                            }
                        }
                        .onChange(of: companionMatchIndex) { _, newValue in
                            guard let newValue else { return }
                            withAnimation { proxy.scrollTo(newValue, anchor: .center) }
                        }
                    }
                }
            }
        }
    }

    private func companionRowBackground(_ idx: Int) -> Color {
        if idx == companionMatchIndex { return Color.orange.opacity(0.25) }
        return idx.isMultiple(of: 2) ? Color.secondary.opacity(0.05) : Color.clear
    }

    private func selectEntry(_ entry: LogEntry) {
        selectedEntryID = entry.id
        anchorTimestamp = TimestampLineMatcher.parseLogEntryTimestamp(entry.timestamp)
    }

    private func openCompanion(_ file: SysdiagFileEntry) {
        companionFile = file
        companionError = nil
        companionMatchIndex = nil
        companionLines = []
        loadCompanion(file)
    }

    private func closeCompanion() {
        companionFile = nil
        companionLines = []
        companionMatchIndex = nil
        companionError = nil
        companionLoading = false
    }

    private func loadCompanion(_ file: SysdiagFileEntry) {
        guard let path = file.path else { return }
        companionLoading = true
        let target = anchorTimestamp ?? Date()

        Task.detached(priority: .userInitiated) {
            let result = FileTextLoader.loadAllLines(path: path)
            await MainActor.run {
                // The user may have closed this file (or opened a different
                // one) before the read finished — don't clobber whatever's
                // showing now with a stale result.
                guard self.companionFile?.id == file.id else { return }
                switch result {
                case .success(let lines):
                    self.companionLines = lines
                    self.companionMatchIndex = TimestampLineMatcher.nearestLine(to: target, in: lines)
                    self.companionLoading = false
                case .failure(let error):
                    self.companionError = error.message
                    self.companionLoading = false
                }
            }
        }
    }

    /// Re-runs the timestamp search against the already-loaded companion
    /// file whenever the anchor changes (i.e. a different log line was
    /// clicked) — no need to re-read the file from disk for that.
    private func resyncCompanion() {
        guard companionFile != nil, !companionLines.isEmpty else { return }
        let target = anchorTimestamp ?? Date()
        let lines = companionLines
        Task.detached(priority: .userInitiated) {
            let match = TimestampLineMatcher.nearestLine(to: target, in: lines)
            await MainActor.run {
                self.companionMatchIndex = match
            }
        }
    }
}

private struct LogStreamEntryRow: View {
    let entry: LogEntry
    let findQuery: String
    let isAnchor: Bool
    let onSelect: () -> Void

    // "warning" was previously an invented sixth level that never actually
    // appears in `log show` output (see `LogArchiveService.levelMap`'s doc
    // comment) — this switch's "warning" case was consequently dead code,
    // and along with the numeric mapping bug it masked, real Fault entries
    // were tinted identically to Error. Fault (the more severe of the two)
    // now gets the stronger red; Error gets orange, matching this app's
    // own fail/warn severity color convention used elsewhere (e.g.
    // `FindingSeverity` in the Networking tab).
    private var levelTint: Color? {
        switch entry.level {
        case "fault": return .red
        case "error": return .orange
        case "debug": return .blue
        default: return nil
        }
    }

    // Not a Button, and no .textSelection(.disabled)/.allowsHitTesting(false)
    // on the Text views — both of those make the row reliably clickable but
    // claim the click exclusively, which also disables macOS's native
    // text selection/copy inside the row. `.simultaneousGesture` attaches
    // the click handler alongside Text's own built-in click/selection
    // handling instead of replacing it, so a single click still selects
    // this line as the timestamp anchor, while click-drag / double-click
    // still selects text for copying, same fix as the Troubleshooting tab.
    var body: some View {
        HStack(alignment: .top, spacing: 8) {
            Text(entry.timestamp)
                .font(.system(size: 10, design: .monospaced))
                .foregroundStyle(.secondary)
                .frame(width: 150, alignment: .leading)
            HighlightedText(text: entry.process, query: findQuery)
                .font(.system(size: 10, weight: .semibold, design: .monospaced))
                .foregroundStyle(.secondary)
                .frame(width: 130, alignment: .leading)
                .lineLimit(1)
            HighlightedText(text: entry.message, query: findQuery)
                .font(.system(size: 11, design: .monospaced))
                .frame(maxWidth: .infinity, alignment: .leading)
        }
        .padding(.horizontal, 14).padding(.vertical, 5)
        .frame(maxWidth: .infinity, alignment: .leading)
        .background((levelTint ?? .clear).opacity(levelTint == nil ? 0 : 0.10))
        .overlay(alignment: .leading) {
            if isAnchor {
                Rectangle().fill(Color.accentColor).frame(width: 3)
            }
        }
        .background(isAnchor ? Color.accentColor.opacity(0.12) : Color.clear)
        .contentShape(Rectangle())
        .simultaneousGesture(TapGesture().onEnded { onSelect() })
        .help("Click to sync the file opened alongside this to this moment (drag to select/copy text)")
    }
}
