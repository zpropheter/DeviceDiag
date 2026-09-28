import SwiftUI
import UniformTypeIdentifiers

/// Left-side tab strip for switching between multiple open sysdiagnose
/// analyses. Added so a second (or third...) archive can be opened
/// alongside whatever's already loaded instead of always replacing it —
/// each row is one `AnalysisSession` from `AppState.sessions`.
struct SessionSidebarView: View {
    @EnvironmentObject var appState: AppState
    @State private var isTargeted = false

    private var isCollapsed: Bool { appState.sidebarCollapsed }

    var body: some View {
        VStack(spacing: 0) {
            header

            Divider()

            ScrollView {
                LazyVStack(spacing: 2) {
                    ForEach(appState.sessions) { session in
                        if isCollapsed {
                            CollapsedSessionRow(
                                session: session,
                                isSelected: session.id == appState.selectedSessionID,
                                onSelect: { appState.selectedSessionID = session.id }
                            )
                        } else {
                            SessionRow(
                                session: session,
                                isSelected: session.id == appState.selectedSessionID,
                                canClose: appState.sessions.count > 1,
                                onSelect: { appState.selectedSessionID = session.id },
                                onClose: { appState.closeTab(session.id) }
                            )
                        }
                    }
                }
                .padding(6)

                // Empty-space affordance so it's obvious you can drop here
                // even when there's just one or two rows above — otherwise
                // the drop target is easy to miss.
                if isTargeted && !isCollapsed {
                    VStack(spacing: 6) {
                        Image(systemName: "plus.rectangle.on.folder")
                            .font(.system(size: 20))
                        Text("Drop to open")
                            .font(.caption2)
                    }
                    .foregroundStyle(Color.accentColor)
                    .frame(maxWidth: .infinity)
                    .padding(.vertical, 20)
                }
            }

            Divider()
            footer
        }
        .frame(maxHeight: .infinity)
        // `.windowBackgroundColor` — the same semantic color topBar/tabBar/
        // UploadView already use — rather than `.underPageBackgroundColor`,
        // which doesn't track light/dark the way `.primary`/`.secondary`
        // text expects and was rendering as low-contrast dark-on-dark.
        .background(Color(nsColor: .windowBackgroundColor))
        .overlay {
            if isTargeted {
                RoundedRectangle(cornerRadius: 0)
                    .strokeBorder(Color.accentColor, lineWidth: 2)
            }
        }
        .onDrop(of: [.fileURL], isTargeted: $isTargeted) { providers in
            handleDrop(providers)
        }
    }

    @ViewBuilder
    private var header: some View {
        HStack {
            if !isCollapsed {
                Text("SYSDIAGNOSES")
                    .font(.system(size: 11, weight: .semibold))
                    .foregroundStyle(.secondary)
                Spacer()
            }
            Button {
                appState.newTab()
            } label: {
                Image(systemName: "plus.circle.fill")
            }
            .buttonStyle(.plain)
            .help("Open another sysdiagnose")
        }
        .padding(.horizontal, isCollapsed ? 0 : 12)
        .padding(.vertical, 10)
        .frame(maxWidth: .infinity)
    }

    /// Collapse (expanded state) on the left, Sync Tabs on the right, on one
    /// row — collapsed, there's no room (or need) for the Sync Tabs label,
    /// so this shrinks down to just the expand icon, centered like before.
    @ViewBuilder
    private var footer: some View {
        if isCollapsed {
            collapseButton
                .frame(maxWidth: .infinity)
                .padding(.vertical, 8)
        } else {
            HStack {
                collapseButton
                Spacer()
                // Only meaningful once there's something to sync between —
                // with a single sysdiagnose open this would just be noise.
                if appState.sessions.count > 1 {
                    Toggle(isOn: $appState.linkReportTab) {
                        Text("Sync Tabs")
                            .font(.caption2)
                            .foregroundStyle(.secondary)
                    }
                    .toggleStyle(.checkbox)
                    .help("When on, switching sysdiagnoses keeps you on the same report section (e.g. Config Profiles) instead of always landing back on Device.")
                }
            }
            .padding(.horizontal, 12)
            .padding(.vertical, 8)
        }
    }

    private var collapseButton: some View {
        Button {
            withAnimation(.default) { appState.sidebarCollapsed.toggle() }
        } label: {
            Image(systemName: isCollapsed ? "sidebar.leading" : "arrow.left.to.line")
                .font(.system(size: 12))
        }
        .buttonStyle(.plain)
        .foregroundStyle(.secondary)
        .help(isCollapsed ? "Expand the sidebar" : "Collapse the sidebar")
    }

    /// Loads every dropped file's URL (order preserved) before opening any
    /// of them — a single `NSItemProvider` load is async, so with several
    /// files dropped together this waits for all of them rather than only
    /// acting on whichever one loads first.
    private func handleDrop(_ providers: [NSItemProvider]) -> Bool {
        guard !providers.isEmpty else { return false }
        let group = DispatchGroup()
        var urlsByIndex: [Int: URL] = [:]
        let lock = NSLock()
        for (idx, provider) in providers.enumerated() {
            group.enter()
            _ = provider.loadObject(ofClass: URL.self) { url, _ in
                if let url {
                    lock.lock()
                    urlsByIndex[idx] = url
                    lock.unlock()
                }
                group.leave()
            }
        }
        group.notify(queue: .main) {
            let paths = urlsByIndex.keys.sorted().map { urlsByIndex[$0]!.path }
            appState.openDropped(paths: paths)
        }
        return true
    }
}

private struct SessionRow: View {
    let session: AnalysisSession
    let isSelected: Bool
    let canClose: Bool
    let onSelect: () -> Void
    let onClose: () -> Void

    @State private var isHovering = false

    var body: some View {
        Button(action: onSelect) {
            HStack(spacing: 8) {
                statusIcon
                VStack(alignment: .leading, spacing: 1) {
                    Text(session.displayName)
                        .font(.system(size: 12, weight: isSelected ? .semibold : .regular))
                        .foregroundStyle(isSelected ? Color.accentColor : Color.primary)
                        .lineLimit(1)
                        .truncationMode(.middle)
                    Text(statusSubtitle)
                        .font(.system(size: 10))
                        .foregroundStyle(.secondary)
                        .lineLimit(1)
                }
                Spacer(minLength: 4)
                if isHovering && canClose {
                    Button(action: onClose) {
                        Image(systemName: "xmark.circle.fill")
                            .foregroundStyle(.secondary)
                            .font(.system(size: 13))
                    }
                    .buttonStyle(.plain)
                    .help("Close this tab")
                }
            }
            .padding(.horizontal, 8)
            .padding(.vertical, 7)
            .frame(maxWidth: .infinity, alignment: .leading)
            .background(isSelected ? Color.accentColor.opacity(0.15) : Color.clear)
            .clipShape(RoundedRectangle(cornerRadius: 6))
            // Without this, the row's hoverable/tappable area is just the
            // bounding box of its actual content (text + icons) — the blank
            // space the Spacer above leaves between a short name and the
            // close button isn't part of that, so crossing it while moving
            // toward the × counted as leaving the row and hid the button
            // again mid-click. This makes the whole padded frame one
            // hit-testable shape, closing that gap.
            .contentShape(Rectangle())
        }
        .buttonStyle(.plain)
        .onHover { isHovering = $0 }
    }

    private var statusSubtitle: String {
        if session.isAnalyzing { return "Analyzing…" }
        if session.errorMessage != nil { return "Error" }
        if let result = session.result { return result.analyzedAt }
        return "Not analyzed yet"
    }

    private var statusIcon: some View {
        sessionStatusIcon(for: session)
    }
}

/// Shared between the full row and the collapsed icon-only row so both
/// agree on what each session's status looks like.
@ViewBuilder
private func sessionStatusIcon(for session: AnalysisSession) -> some View {
    if session.isAnalyzing {
        ProgressView()
            .controlSize(.small)
            .scaleEffect(0.6)
            .frame(width: 16, height: 16)
    } else if session.errorMessage != nil {
        Image(systemName: "exclamationmark.triangle.fill")
            .foregroundStyle(.orange)
            .font(.system(size: 12))
            .frame(width: 16, height: 16)
    } else if let result = session.result {
        Text(result.isMobile ? "📱" : "💻")
            .font(.system(size: 12))
            .frame(width: 16, height: 16)
    } else {
        Image(systemName: "doc.badge.plus")
            .foregroundStyle(.secondary)
            .font(.system(size: 12))
            .frame(width: 16, height: 16)
    }
}

/// Icon-only row shown when the sidebar is collapsed — same sessions, same
/// selection, just without the name/subtitle/close button that don't fit
/// in a narrow strip. Hover the icon for the full name via `.help`.
private struct CollapsedSessionRow: View {
    let session: AnalysisSession
    let isSelected: Bool
    let onSelect: () -> Void

    var body: some View {
        Button(action: onSelect) {
            sessionStatusIcon(for: session)
                .frame(maxWidth: .infinity)
                .padding(.vertical, 8)
                .background(isSelected ? Color.accentColor.opacity(0.15) : Color.clear)
                .clipShape(RoundedRectangle(cornerRadius: 6))
        }
        .buttonStyle(.plain)
        .help(session.displayName)
    }
}
