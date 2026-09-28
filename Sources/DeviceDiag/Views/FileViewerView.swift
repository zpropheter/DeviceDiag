import AppKit
import SwiftUI

/// Fast in-app viewer for a single text-ish file from the Files tab —
/// presented instead of handing the file to NSWorkspace/whatever app macOS
/// has registered as the default handler, which is what made "Open" feel
/// slow or hung. See FileTextLoader for why.
struct FileViewerView: View {
    let fileName: String
    let filePath: String

    @Environment(\.dismiss) private var dismiss
    @State private var lines: [String] = []
    @State private var totalLines = 0
    @State private var truncated = false
    @State private var loadError: String?
    @State private var isLoading = true
    @State private var findText = ""
    @State private var showFindBar = false
    @State private var currentMatchIndex = 0
    @FocusState private var findFieldFocused: Bool

    /// Indices (into `lines`) of every line containing the current query.
    /// Unlike the other tabs' Cmd+F, the file viewer doesn't filter content
    /// down to matches — for a raw file you want to see a hit in context,
    /// not lose everything around it — so Cmd+F instead jumps to the first
    /// match, then the next on Enter/the chevrons.
    private var matchLineIndices: [Int] {
        guard !findText.isEmpty else { return [] }
        return lines.indices.filter { lines[$0].localizedCaseInsensitiveContains(findText) }
    }

    private func jump(by delta: Int) {
        guard !matchLineIndices.isEmpty else { return }
        currentMatchIndex = (currentMatchIndex + delta + matchLineIndices.count) % matchLineIndices.count
    }

    var body: some View {
        VStack(spacing: 0) {
            header
            Divider()
            if showFindBar {
                FindBarView(placeholder: "Find in \(fileName)", text: $findText,
                            matchCount: findText.isEmpty ? nil : matchLineIndices.count,
                            currentMatchIndex: (findText.isEmpty || matchLineIndices.isEmpty) ? nil : currentMatchIndex + 1,
                            isFocused: $findFieldFocused,
                            onNext: { jump(by: 1) },
                            onPrevious: { jump(by: -1) }) {
                    showFindBar = false
                    findText = ""
                }
                Divider()
            }
            content
        }
        .frame(width: 860, height: 560)
        .background(FindShortcut { showFindBar = true; findFieldFocused = true })
        .task {
            let path = filePath
            let result = await Task.detached(priority: .userInitiated) {
                FileTextLoader.load(path: path)
            }.value
            switch result {
            case .success(let loaded):
                lines = loaded.lines
                totalLines = loaded.totalLines
                truncated = loaded.truncated
            case .failure(let error):
                loadError = error.message
            }
            isLoading = false
        }
    }

    private var header: some View {
        HStack(spacing: 10) {
            Text(fileName).font(.headline).lineLimit(1).truncationMode(.middle)
            Spacer()
            if truncated {
                Text("Showing first \(lines.count) of \(totalLines) lines")
                    .font(.caption2).foregroundStyle(.orange)
            }
            Button("Reveal in Finder") {
                NSWorkspace.shared.activateFileViewerSelecting([URL(fileURLWithPath: filePath)])
            }
            .buttonStyle(.bordered).controlSize(.small)
            Button("Done") { dismiss() }
                .keyboardShortcut(.defaultAction)
        }
        .padding(14)
    }

    @ViewBuilder
    private var content: some View {
        if isLoading {
            VStack(spacing: 10) {
                ProgressView()
                Text("Reading file…").font(.caption).foregroundStyle(.secondary)
            }
            .frame(maxWidth: .infinity, maxHeight: .infinity)
        } else if let loadError {
            Text(loadError).foregroundStyle(.secondary)
                .frame(maxWidth: .infinity, maxHeight: .infinity)
        } else if !findText.isEmpty && matchLineIndices.isEmpty {
            Text("No lines match \"\(findText)\".").foregroundStyle(.secondary)
                .frame(maxWidth: .infinity, maxHeight: .infinity)
        } else {
            ScrollViewReader { proxy in
                ScrollView {
                    LazyVStack(alignment: .leading, spacing: 0) {
                        ForEach(lines.indices, id: \.self) { idx in
                            HighlightedText(text: lines[idx], query: findText)
                                .font(.system(size: 11, design: .monospaced))
                                .textSelection(.enabled)
                                .frame(maxWidth: .infinity, alignment: .leading)
                                .padding(.horizontal, 14).padding(.vertical, 2)
                                .background(rowBackground(idx))
                                .id(idx)
                        }
                    }
                }
                .onChange(of: findText) { _, _ in
                    currentMatchIndex = 0
                    scrollToCurrentMatch(proxy)
                }
                .onChange(of: currentMatchIndex) { _, _ in
                    scrollToCurrentMatch(proxy)
                }
            }
        }
    }

    /// Tints the line the cursor is currently sitting on so "jump to next
    /// match" is visible even when several matches are on screen at once —
    /// distinct from the yellow per-occurrence highlight `HighlightedText`
    /// already draws.
    private func rowBackground(_ idx: Int) -> Color {
        if !matchLineIndices.isEmpty, matchLineIndices[currentMatchIndex] == idx {
            return Color.orange.opacity(0.22)
        }
        return idx.isMultiple(of: 2) ? Color.secondary.opacity(0.06) : Color.clear
    }

    private func scrollToCurrentMatch(_ proxy: ScrollViewProxy) {
        guard currentMatchIndex >= 0, currentMatchIndex < matchLineIndices.count else { return }
        let target = matchLineIndices[currentMatchIndex]
        withAnimation {
            proxy.scrollTo(target, anchor: .center)
        }
    }
}
