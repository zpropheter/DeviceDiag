import SwiftUI

struct DeclarationsTabView: View {
    let declarations: DeclarationsResult
    let logArchivePath: String?
    /// Threaded through to `LogStreamView` so its "open alongside" dropdown
    /// has the same file catalog the Files tab uses.
    let sysdiagFiles: [SysdiagFileGroup]

    @State private var logStreamKeyPath: String?

    @State private var findText = ""
    @State private var committedFindText = ""
    @State private var showFindBar = false
    @FocusState private var findFieldFocused: Bool

    private var standaloneActivationsAndConfigs: [StandaloneDeclaration] {
        declarations.standalone.filter { $0.section == "activation" || $0.section == "configuration" }
    }
    private var standaloneManagement: [StandaloneDeclaration] {
        declarations.standalone.filter { $0.section == "management" }
    }

    private func blueprintMatches(_ bp: BlueprintDeclaration) -> Bool {
        matchesAny([bp.uuid, bp.actType, bp.cfgType], query: committedFindText)
    }
    private func statusItemMatches(_ item: StatusItem) -> Bool {
        matchesAny([item.keyPath, item.lastValue], query: committedFindText)
    }
    private func standaloneMatches(_ entry: StandaloneDeclaration) -> Bool {
        matchesAny([entry.identifier, entry.declarationType, entry.loadState], query: committedFindText)
    }

    private var filteredBlueprints: [BlueprintDeclaration] {
        declarations.blueprints.filter(blueprintMatches)
    }
    private var filteredStatusItems: [StatusItem] {
        declarations.statusItems.filter(statusItemMatches)
    }
    private func filteredStandalone(_ entries: [StandaloneDeclaration]) -> [StandaloneDeclaration] {
        entries.filter(standaloneMatches)
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 16) {
            if showFindBar {
                FindBarView(placeholder: "Find in declarations", text: $findText,
                            isFocused: $findFieldFocused) {
                    showFindBar = false
                    findText = ""
                }
            }

            if let error = declarations.error {
                CardView { EmptyStateView(text: "⚠️ \(error)") }
            }

            if !declarations.conduit.lastReceived.isEmpty {
                CardView {
                    HStack(spacing: 24) {
                        Text("Last MDM sync: ").foregroundStyle(.secondary) + Text(declarations.conduit.lastReceived).bold()
                        if declarations.conduit.consecutiveErrors > 0 {
                            Text("⚠️ Consecutive sync errors: \(declarations.conduit.consecutiveErrors)").foregroundStyle(.orange)
                        } else {
                            Text("✓ No sync errors").foregroundStyle(.green)
                        }
                    }
                    .font(.caption)
                    .padding(12)
                }
            }

            blueprintsCard

            if !declarations.statusItems.isEmpty {
                statusItemsCard
            }

            if !standaloneActivationsAndConfigs.isEmpty {
                standaloneCard(title: "⚙️ System Configurations", entries: standaloneActivationsAndConfigs)
            }
            if !standaloneManagement.isEmpty {
                standaloneCard(title: "🔧 Management Declarations", entries: standaloneManagement)
            }
        }
        .environment(\.findQuery, committedFindText)
        .background(FindShortcut { showFindBar = true; findFieldFocused = true })
        .task(id: findText) {
            try? await Task.sleep(nanoseconds: 150_000_000)
            if !Task.isCancelled { committedFindText = findText }
        }
        .sheet(isPresented: Binding(
            get: { logStreamKeyPath != nil },
            set: { if !$0 { logStreamKeyPath = nil } }
        )) {
            if let logArchivePath, !logArchivePath.isEmpty, let keyPath = logStreamKeyPath {
                LogStreamView(archivePath: logArchivePath, keyPath: keyPath, sysdiagFiles: sysdiagFiles)
            }
        }
    }

    private var blueprintsCard: some View {
        let blueprints = filteredBlueprints
        return CardView {
            VStack(alignment: .leading, spacing: 0) {
                HStack {
                    Text("🔷 Blueprint Declarations").font(.system(size: 14, weight: .semibold))
                    if declarations.blueprints.isEmpty {
                        Badge(text: "None", color: .secondary)
                    } else {
                        Badge(text: "\(declarations.blueprints.count)")
                        let issueCount = declarations.blueprints.filter { bp in
                            bp.activationGroups.contains { !$0.ok } || bp.configGroups.contains { !$0.ok }
                        }.count
                        if issueCount > 0 {
                            Badge(text: "\(issueCount) with issues", color: .orange)
                        }
                    }
                }
                .padding(.horizontal, 16).padding(.vertical, 10)
                .frame(maxWidth: .infinity, alignment: .leading)
                .background(Color.secondary.opacity(0.06))
                Divider()

                if declarations.blueprints.isEmpty {
                    EmptyStateView(text: "No Blueprint declarations found.")
                } else if blueprints.isEmpty {
                    EmptyStateView(text: "No blueprints match \"\(committedFindText)\".")
                } else {
                    HStack(alignment: .top) {
                        Text("Blueprint UUID").frame(width: 260, alignment: .leading)
                        Text("Configuration Type").frame(width: 160, alignment: .leading)
                        Text("Activations").frame(maxWidth: .infinity, alignment: .leading)
                        Text("Configurations").frame(maxWidth: .infinity, alignment: .leading)
                    }
                    .font(.system(size: 10, weight: .semibold))
                    .foregroundStyle(.secondary)
                    .padding(.horizontal, 16).padding(.vertical, 7)
                    .background(Color.secondary.opacity(0.06))
                    Divider()

                    VStack(spacing: 0) {
                        ForEach(blueprints) { bp in
                            BlueprintRow(bp: bp, isLast: bp.id == blueprints.last?.id)
                        }
                    }
                }
            }
        }
    }

    private var statusItemsCard: some View {
        let items = filteredStatusItems
        // needsSync == true means the key path still needs to sync (not yet
        // synced); needsSync == false means it's already up to date.
        let needsSyncCount = declarations.statusItems.filter { $0.needsSync }.count
        return CardView {
            VStack(alignment: .leading, spacing: 0) {
                HStack {
                    Text("📡 Status Key Paths").font(.system(size: 14, weight: .semibold))
                    Badge(text: "\(declarations.statusItems.count)")
                    if needsSyncCount > 0 {
                        Badge(text: "\(needsSyncCount) needs sync", color: .orange)
                    } else {
                        Badge(text: "All synced", color: .green)
                    }
                }
                .padding(.horizontal, 16).padding(.vertical, 10)
                .frame(maxWidth: .infinity, alignment: .leading)
                .background(Color.secondary.opacity(0.06))
                Text("* Value inferred from static sysdiagnose files, not directly from the MDM reporting channel.")
                    .font(.caption2).foregroundStyle(.secondary)
                    .padding(.horizontal, 16).padding(.top, 6).padding(.bottom, 6)

                if items.isEmpty {
                    EmptyStateView(text: "No status key paths match \"\(committedFindText)\".")
                } else {
                    HStack(alignment: .top) {
                        Text("Key Path").frame(width: 260, alignment: .leading)
                        Text("Sync").frame(width: 40, alignment: .leading)
                        Text("Last Value").frame(maxWidth: .infinity, alignment: .leading)
                        Text("Log Stream").frame(width: 90, alignment: .leading)
                    }
                    .font(.system(size: 10, weight: .semibold))
                    .foregroundStyle(.secondary)
                    .padding(.horizontal, 16).padding(.vertical, 7)
                    .background(Color.secondary.opacity(0.06))
                    Divider()

                    VStack(spacing: 0) {
                        ForEach(items) { item in
                            StatusItemRow(item: item, isLast: item.id == items.last?.id,
                                          logArchivePath: logArchivePath) {
                                logStreamKeyPath = item.keyPath
                            }
                        }
                    }
                }
            }
        }
    }

    private func standaloneCard(title: String, entries: [StandaloneDeclaration]) -> some View {
        let filtered = filteredStandalone(entries)
        return CardView {
            VStack(alignment: .leading, spacing: 0) {
                HStack {
                    Text(title).font(.system(size: 14, weight: .semibold))
                    Badge(text: "\(entries.count)", color: .secondary)
                }
                .padding(.horizontal, 16).padding(.vertical, 10)
                .frame(maxWidth: .infinity, alignment: .leading)
                .background(Color.secondary.opacity(0.06))
                Divider()

                if filtered.isEmpty {
                    EmptyStateView(text: "No entries match \"\(committedFindText)\".")
                } else {
                    VStack(spacing: 0) {
                        ForEach(filtered) { entry in
                            StandaloneDeclarationRow(entry: entry, isLast: entry.id == filtered.last?.id)
                        }
                    }
                }
            }
        }
    }
}

/// Extracted as standalone Views (rather than inline multi-statement ForEach
/// closures) so each row's type is concrete for ForEach's overload resolution.

private struct BlueprintRow: View {
    let bp: BlueprintDeclaration
    let isLast: Bool
    @Environment(\.findQuery) private var findQuery

    var body: some View {
        VStack(spacing: 0) {
            HStack(alignment: .top) {
                HighlightedText(text: bp.uuid, query: findQuery)
                    .font(.system(size: 11, design: .monospaced))
                    .frame(width: 260, alignment: .leading)
                HighlightedText(text: bp.cfgType.isEmpty ? (bp.actType.isEmpty ? "—" : bp.actType) : bp.cfgType, query: findQuery)
                    .font(.system(size: 11, design: .monospaced))
                    .frame(width: 160, alignment: .leading)
                statusGroupColumn(groups: bp.activationGroups)
                    .frame(maxWidth: .infinity, alignment: .leading)
                statusGroupColumn(groups: bp.configGroups)
                    .frame(maxWidth: .infinity, alignment: .leading)
            }
            .padding(.horizontal, 16).padding(.vertical, 10)
            if !isLast {
                Divider()
            }
        }
    }

    private func statusGroupColumn(groups: [DeclarationStatusGroup]) -> some View {
        VStack(alignment: .leading, spacing: 3) {
            if groups.isEmpty {
                Text("—").font(.caption).foregroundStyle(.secondary)
            }
            ForEach(groups) { g in
                HStack(spacing: 4) {
                    if g.ok {
                        Text("✓").foregroundStyle(.green).font(.caption).bold()
                    } else if g.active == 1 {
                        Text("⚠ " + (g.valid == "unknown" ? "status pending" : (g.reasons.isEmpty ? "not valid" : g.reasons.joined(separator: ", "))))
                            .foregroundStyle(.orange).font(.caption)
                    } else {
                        Text("✕ " + (g.reasons.isEmpty ? "inactive" : g.reasons.joined(separator: ", ")))
                            .foregroundStyle(.red).font(.caption)
                    }
                    if g.count > 1 {
                        Badge(text: "×\(g.count)", color: .secondary)
                    }
                }
            }
        }
    }
}

private struct StatusItemRow: View {
    let item: StatusItem
    let isLast: Bool
    let logArchivePath: String?
    let onOpenLogStream: () -> Void
    @Environment(\.findQuery) private var findQuery

    var body: some View {
        VStack(spacing: 0) {
            HStack(alignment: .top) {
                HighlightedText(text: item.keyPath, query: findQuery)
                    .font(.system(size: 11, design: .monospaced))
                    .frame(width: 260, alignment: .leading)
                Text(item.needsSync ? "✕" : "✓")
                    .foregroundStyle(item.needsSync ? Color.red : Color.green)
                    .frame(width: 40, alignment: .leading)
                    .help("\(item.needsSync ? "Needs sync" : "Synced") — raw parsed value: \(item.rawNeedsSyncDebug)")
                HighlightedText(text: item.lastValue.isEmpty ? "—" : item.lastValue, query: findQuery)
                    .font(.system(size: 11, design: .monospaced))
                    .frame(maxWidth: .infinity, alignment: .leading)
                Group {
                    if let logArchivePath, !logArchivePath.isEmpty {
                        Button("Open", action: onOpenLogStream)
                            .buttonStyle(.bordered)
                            .controlSize(.small)
                    } else {
                        Text("—").foregroundStyle(.secondary)
                    }
                }
                .frame(width: 90, alignment: .leading)
            }
            .padding(.horizontal, 16).padding(.vertical, 7)
            if !isLast {
                Divider().padding(.leading, 16)
            }
        }
    }
}

private struct StandaloneDeclarationRow: View {
    let entry: StandaloneDeclaration
    let isLast: Bool
    @Environment(\.findQuery) private var findQuery

    var body: some View {
        VStack(spacing: 0) {
            HStack {
                HighlightedText(text: entry.identifier, query: findQuery)
                    .font(.system(size: 11, design: .monospaced))
                    .frame(maxWidth: .infinity, alignment: .leading)
                Text(entry.declarationType).font(.system(size: 11, design: .monospaced)).foregroundStyle(.secondary)
                if !entry.loadState.isEmpty {
                    Badge(text: entry.loadState, color: entry.loadState == "loaded" ? .green : .secondary)
                }
                Text(entry.active == 1 ? "✓ Active" : "✕ Inactive")
                    .font(.caption)
                    .foregroundStyle(entry.active == 1 ? .green : .red)
            }
            .padding(.horizontal, 16).padding(.vertical, 7)
            if !isLast {
                Divider().padding(.leading, 16)
            }
        }
    }
}
