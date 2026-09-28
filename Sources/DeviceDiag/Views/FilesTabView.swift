import Foundation
import SwiftUI

struct FilesTabView: View {
    let groups: [SysdiagFileGroup]
    @State private var toast: (message: String, isError: Bool)?
    @State private var viewerFile: ViewerTarget?

    @State private var findText = ""
    @State private var committedFindText = ""
    @State private var showFindBar = false
    @FocusState private var findFieldFocused: Bool

    private func matchingFiles(_ group: SysdiagFileGroup) -> [SysdiagFileEntry] {
        group.files.filter { $0.found && matchesAny([$0.name, $0.description], query: committedFindText) }
    }

    private var visibleGroups: [VisibleGroup] {
        groups.compactMap { group in
            let files = matchingFiles(group)
            return files.isEmpty ? nil : VisibleGroup(group: group, files: files)
        }
    }

    /// Splits `visibleGroups` into two columns by always adding the next
    /// group to whichever column is currently shorter (estimated by file
    /// count plus one for its own header row), rather than a plain
    /// left-right-left-right `LazyVGrid` placement. A fixed two-up grid
    /// pairs cards purely by position, so one oversized card (e.g. Storage
    /// & Security once it has several files) stretches its row-mate to
    /// match — even though they aren't related — leaving a tall gap of
    /// blank space above whatever card comes next in that same column.
    /// Balancing by estimated height keeps every card its own natural size.
    private var balancedColumns: [[VisibleGroup]] {
        var columns: [[VisibleGroup]] = [[], []]
        var heights = [0, 0]
        for entry in visibleGroups {
            let shorter = heights[0] <= heights[1] ? 0 : 1
            columns[shorter].append(entry)
            heights[shorter] += entry.files.count + 1
        }
        return columns
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 16) {
            if showFindBar {
                FindBarView(placeholder: "Find a file", text: $findText,
                            isFocused: $findFieldFocused) {
                    showFindBar = false
                    findText = ""
                }
            }
            if !committedFindText.isEmpty && visibleGroups.isEmpty {
                CardView { EmptyStateView(text: "No files match \"\(committedFindText)\".") }
            } else {
                ZStack(alignment: .bottom) {
                    HStack(alignment: .top, spacing: 16) {
                        ForEach(balancedColumns.indices, id: \.self) { columnIndex in
                            VStack(spacing: 16) {
                                ForEach(balancedColumns[columnIndex]) { entry in
                                    groupCard(entry.group, files: entry.files)
                                }
                            }
                            .frame(maxWidth: .infinity)
                        }
                    }

                    if let toast {
                        Text(toast.message)
                            .font(.caption)
                            .padding(.horizontal, 16).padding(.vertical, 9)
                            .background(toast.isError ? Color.red.opacity(0.12) : Color.green.opacity(0.12))
                            .foregroundStyle(toast.isError ? .red : .green)
                            .clipShape(RoundedRectangle(cornerRadius: 8))
                            .padding(.bottom, 12)
                            .transition(.opacity)
                    }
                }
            }
        }
        .environment(\.findQuery, committedFindText)
        .background(FindShortcut { showFindBar = true; findFieldFocused = true })
        .task(id: findText) {
            try? await Task.sleep(nanoseconds: 150_000_000)
            if !Task.isCancelled { committedFindText = findText }
        }
        .sheet(isPresented: Binding(
            get: { viewerFile != nil },
            set: { if !$0 { viewerFile = nil } }
        )) {
            if let viewerFile {
                FileViewerView(fileName: viewerFile.name, filePath: viewerFile.path)
            }
        }
    }

    private func groupCard(_ group: SysdiagFileGroup, files: [SysdiagFileEntry]) -> some View {
        CardView(title: group.group) {
            VStack(spacing: 0) {
                ForEach(files) { file in
                    FileRow(file: file, isLast: file.id == files.last?.id) {
                        openFile(file)
                    }
                }
            }
        }
    }

    private func openFile(_ file: SysdiagFileEntry) {
        guard let path = file.path else { return }

        if !file.groupedPaths.isEmpty {
            report(FileOpener.revealMultiple(paths: [path] + file.groupedPaths))
            return
        }

        var isDir: ObjCBool = false
        guard FileManager.default.fileExists(atPath: path, isDirectory: &isDir) else {
            report(.notFound("File no longer exists at:\n\(path)\n\nRe-run the analysis to restore access to the extracted files."))
            return
        }

        if isDir.boolValue {
            report(FileOpener.open(path: path))
            return
        }

        let ext = (path as NSString).pathExtension.lowercased()
        if FileTextLoader.viewableExtensions.contains(ext) {
            viewerFile = ViewerTarget(name: (path as NSString).lastPathComponent, path: path)
        } else {
            report(FileOpener.open(path: path))
        }
    }

    private func report(_ result: FileOpener.Result) {
        withAnimation {
            switch result {
            case .opened: toast = ("Opening…", false)
            case .notFound(let msg): toast = (msg, true)
            case .failed(let msg): toast = (msg, true)
            }
        }
        DispatchQueue.main.asyncAfter(deadline: .now() + 2.5) {
            withAnimation { toast = nil }
        }
    }
}

private struct VisibleGroup: Identifiable {
    let group: SysdiagFileGroup
    let files: [SysdiagFileEntry]
    var id: UUID { group.id }
}

private struct ViewerTarget: Identifiable {
    let name: String
    let path: String
    var id: String { path }
}

/// Extracted as a standalone View so its type is concrete for ForEach.
private struct FileRow: View {
    let file: SysdiagFileEntry
    let isLast: Bool
    let onOpen: () -> Void
    @Environment(\.findQuery) private var findQuery

    private var fileCount: Int { file.groupedPaths.count + 1 }

    var body: some View {
        VStack(spacing: 0) {
            HStack {
                if !file.groupedPaths.isEmpty || file.isDirectory {
                    Image(systemName: "folder").foregroundStyle(.secondary).font(.caption)
                }
                HighlightedText(text: file.name, query: findQuery)
                    .font(.system(size: 12, weight: .semibold, design: .monospaced))
                Spacer()
                Button(file.groupedPaths.isEmpty ? "Open" : "Reveal (\(fileCount))", action: onOpen)
                    .buttonStyle(.bordered)
                    .controlSize(.small)
            }
            .padding(.horizontal, 12).padding(.vertical, 8)
            if !isLast {
                Divider()
            }
        }
    }
}
