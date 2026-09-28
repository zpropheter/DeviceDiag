import SwiftUI

struct SettingsAttributionTabView: View {
    let attribution: SettingsAttributionResult
    @State private var activeSource: String = "all"
    @State private var searchText: String = ""
    @FocusState private var searchFieldFocused: Bool

    private var filteredEntries: [SettingsAttributionEntry] {
        attribution.entries.filter { entry in
            let sourceMatch = activeSource == "all" || entry.source == activeSource
            let searchMatch = matchesAny([entry.key, entry.value], query: searchText)
            return sourceMatch && searchMatch
        }
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 16) {
            if let error = attribution.error {
                CardView { EmptyStateView(text: "⚠️ \(error)") }
            } else {
                summaryCard
                filterToolbar
                tableCard
            }
        }
        .environment(\.findQuery, searchText)
        // This tab already has a persistent search field in the toolbar
        // rather than a pop-up find bar — Cmd+F just jumps focus to it.
        .background(FindShortcut { searchFieldFocused = true })
    }

    private var summaryCard: some View {
        CardView(title: "🗂 Managed Settings Attribution") {
            HStack(spacing: 32) {
                VStack(spacing: 4) {
                    Text("\(attribution.total)").font(.system(size: 28, weight: .bold))
                    Text("Total Restrictions").font(.caption).foregroundStyle(.secondary)
                }
                Divider().frame(height: 40)
                HStack(spacing: 20) {
                    HStack(spacing: 6) { Badge(text: "\(attribution.profileCount)", color: .orange); Text("from Configuration Profiles").font(.caption) }
                    HStack(spacing: 6) { Badge(text: "\(attribution.declarationCount)", color: .blue); Text("from DDM Declarations").font(.caption) }
                    HStack(spacing: 6) { Badge(text: "\(attribution.defaultCount)", color: .secondary); Text("Device Defaults").font(.caption) }
                }
                Spacer()
                Text("Profile keys are set by an installed configuration profile with a Restrictions payload. Declaration keys are applied by a confirmed DDM declaration. Everything else — including a key with no active managed source, such as one an already-removed profile used to set — shows as Default.")
                    .font(.caption2)
                    .foregroundStyle(.secondary)
                    .frame(maxWidth: 320, alignment: .leading)
            }
            .padding(16)
        }
    }

    private var filterToolbar: some View {
        CardView {
            HStack(spacing: 10) {
                Text("Filter:").font(.caption).foregroundStyle(.secondary)
                filterPill(label: "All (\(attribution.total))", key: "all")
                if attribution.profileCount > 0 { filterPill(label: "Profile (\(attribution.profileCount))", key: "profile") }
                if attribution.declarationCount > 0 { filterPill(label: "Declaration (\(attribution.declarationCount))", key: "declaration") }
                if attribution.defaultCount > 0 { filterPill(label: "Default (\(attribution.defaultCount))", key: "default") }
                Spacer()
                TextField("Search keys…", text: $searchText)
                    .textFieldStyle(.roundedBorder)
                    .font(.system(.caption, design: .monospaced))
                    .frame(width: 200)
                    .focused($searchFieldFocused)
            }
            .padding(12)
        }
    }

    private func filterPill(label: String, key: String) -> some View {
        Button {
            activeSource = key
        } label: {
            Text(label)
                .font(.caption)
                .padding(.horizontal, 12).padding(.vertical, 4)
                .background(activeSource == key ? Color.accentColor : Color.clear)
                .foregroundStyle(activeSource == key ? Color.white : Color.primary)
                .overlay(Capsule().strokeBorder(activeSource == key ? Color.accentColor : Color.secondary.opacity(0.3)))
                .clipShape(Capsule())
        }
        .buttonStyle(.plain)
    }

    private var tableCard: some View {
        CardView {
            if filteredEntries.isEmpty {
                EmptyStateView(text: "No matching keys.")
            } else {
                VStack(spacing: 0) {
                    HStack {
                        Text("Restriction Key").font(.caption).foregroundStyle(.secondary).frame(width: 320, alignment: .leading)
                        Text("Value").font(.caption).foregroundStyle(.secondary).frame(width: 70, alignment: .center)
                        Text("Source").font(.caption).foregroundStyle(.secondary).frame(width: 110, alignment: .leading)
                        Text("Detail").font(.caption).foregroundStyle(.secondary)
                        Spacer()
                    }
                    .padding(.horizontal, 16).padding(.vertical, 8)
                    .background(Color.secondary.opacity(0.06))
                    Divider()

                    ForEach(filteredEntries) { entry in
                        SettingsAttributionRow(entry: entry, isLast: entry.id == filteredEntries.last?.id)
                    }
                }
            }
        }
    }

}

/// Extracted as a standalone View so its type is concrete for ForEach.
private struct SettingsAttributionRow: View {
    let entry: SettingsAttributionEntry
    let isLast: Bool
    @Environment(\.findQuery) private var findQuery

    var body: some View {
        VStack(spacing: 0) {
            HStack(alignment: .top) {
                HighlightedText(text: entry.key, query: findQuery)
                    .font(.system(size: 11, design: .monospaced))
                    .frame(width: 320, alignment: .leading)
                valueView.frame(width: 70, alignment: .center)
                sourceBadge.frame(width: 110, alignment: .leading)
                detailView
                Spacer()
            }
            .padding(.horizontal, 16).padding(.vertical, 6)
            if !isLast {
                Divider().padding(.leading, 16)
            }
        }
    }

    @ViewBuilder
    private var valueView: some View {
        if entry.value == "true" { Badge(text: "true", color: .green) }
        else if entry.value == "false" { Badge(text: "false", color: .secondary) }
        else if entry.value == "—" { Text("—").foregroundStyle(.secondary).font(.caption) }
        else { HighlightedText(text: entry.value, query: findQuery).font(.system(size: 11, design: .monospaced)) }
    }

    @ViewBuilder
    private var sourceBadge: some View {
        switch entry.source {
        case "profile": Badge(text: "Profile", color: entry.implicit ? .secondary : .orange)
        case "declaration": Badge(text: "Declaration", color: .blue)
        default: Badge(text: "Default", color: .secondary)
        }
    }

    @ViewBuilder
    private var detailView: some View {
        switch entry.source {
        case "profile":
            if entry.implicit {
                Text("\(entry.profileName ?? "") (implicit MDM baseline)")
                    .font(.caption2).foregroundStyle(.secondary)
                    .help("iOS enforces this restriction automatically for any managed device. The attributed profile has no Restrictions payload.")
            } else {
                Text(entry.profileName ?? "").font(.caption2).foregroundStyle(.secondary)
            }
        case "declaration":
            Text("Set \(entry.timestamp ?? "")").font(.caption2).foregroundStyle(.secondary)
        default:
            Text("—").font(.caption2).foregroundStyle(.secondary)
        }
    }
}
