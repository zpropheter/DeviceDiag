import SwiftUI

struct ConfigProfilesTabView: View {
    let profiles: ConfigProfilesResult
    let isMobile: Bool

    @State private var findText = ""
    // Filtering/highlighting runs off this debounced copy rather than
    // `findText` directly — scanning every payload's full plist text on every
    // keystroke was the main source of the lag reported with large profile
    // sets, so the expensive work only happens once typing pauses.
    @State private var committedFindText = ""
    @State private var showFindBar = false
    @FocusState private var findFieldFocused: Bool
    @State private var expandedPayloadIDs: Set<UUID> = []

    private func payloadMatches(_ payload: ConfigProfilePayload) -> Bool {
        guard !committedFindText.isEmpty else { return false }
        return matchesAny([payload.displayName, payload.domain, payload.payloadData], query: committedFindText)
    }

    private func profileMatches(_ profile: ConfigProfileEntry) -> Bool {
        guard !committedFindText.isEmpty else { return true }
        if matchesAny([profile.name, profile.org, profile.identifier, profile.uuid, profile.description], query: committedFindText) {
            return true
        }
        return profile.payloads.contains { payloadMatches($0) }
    }

    private var filteredProfiles: [ConfigProfileEntry] {
        committedFindText.isEmpty ? profiles.profiles : profiles.profiles.filter(profileMatches)
    }

    /// Groups by scope ("Device", then "User", then "Provisioning") when the
    /// parser found scope-grouped SPX output; falls back to one unlabeled
    /// group (today's behavior) when it didn't — e.g. mobile profiles, or
    /// macOS SPX that wasn't scope-grouped in the first place.
    private var scopedGroups: [(scope: String, profiles: [ConfigProfileEntry])] {
        guard filteredProfiles.contains(where: { !$0.scope.isEmpty }) else {
            return [("", filteredProfiles)]
        }
        let known = ["Device", "User", "Provisioning"]
        var groups: [(scope: String, profiles: [ConfigProfileEntry])] = []
        for scope in known {
            let matches = filteredProfiles.filter { $0.scope == scope }
            if !matches.isEmpty { groups.append((scope, matches)) }
        }
        let other = filteredProfiles.filter { !known.contains($0.scope) }
        if !other.isEmpty { groups.append(("", other)) }
        return groups
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 16) {
            if showFindBar {
                FindBarView(placeholder: "Find in profiles & payload values", text: $findText,
                            matchCount: committedFindText.isEmpty ? nil : filteredProfiles.count,
                            isFocused: $findFieldFocused) {
                    showFindBar = false
                    findText = ""
                }
            }
            if let error = profiles.error {
                CardView { EmptyStateView(text: "⚠️ \(error)") }
            }
            if profiles.profiles.isEmpty {
                CardView { EmptyStateView(text: "No configuration profiles found.") }
            } else if filteredProfiles.isEmpty {
                CardView { EmptyStateView(text: "No profiles or payload values match \"\(committedFindText)\".") }
            } else {
                // A sysdiagnose with dozens of profiles (each with its own
                // header/metadata bands and a disclosure row per payload)
                // was building and laying out the entire tree synchronously
                // every time this tab was navigated to — since it isn't kept
                // mounted like Troubleshooting is, that meant a multi-second
                // freeze on every single visit, not just the first. A plain
                // `VStack` has no way around that; `LazyVStack` only builds
                // cards actually near the visible scroll area, and it can
                // do that here because this whole tab already sits inside
                // ResultsView's own `ScrollView`.
                LazyVStack(alignment: .leading, spacing: 16) {
                    ForEach(scopedGroups, id: \.scope) { group in
                        VStack(alignment: .leading, spacing: 10) {
                            if !group.scope.isEmpty {
                                Text("\(group.scope) Profiles")
                                    .font(.system(size: 12, weight: .semibold))
                                    .foregroundStyle(.secondary)
                            }
                            ForEach(group.profiles) { profile in
                                profileCard(profile)
                            }
                        }
                    }
                }
            }
        }
        .environment(\.findQuery, committedFindText)
        .background(FindShortcut { showFindBar = true; findFieldFocused = true })
        .task(id: findText) {
            try? await Task.sleep(nanoseconds: 200_000_000)
            guard !Task.isCancelled else { return }
            committedFindText = findText
            guard !findText.isEmpty else { return }
            // Auto-expand any payload whose plist content matches, even if it
            // was previously collapsed, so the match is immediately visible.
            for profile in profiles.profiles {
                for payload in profile.payloads where payloadMatches(payload) {
                    expandedPayloadIDs.insert(payload.id)
                }
            }
        }
    }

    private func scopeColor(_ scope: String) -> Color {
        switch scope {
        case "Device": return .blue
        case "User": return .purple
        case "Provisioning": return .orange
        default: return .secondary
        }
    }

    private func profileCard(_ profile: ConfigProfileEntry) -> some View {
        CardView {
            VStack(alignment: .leading, spacing: 0) {
                // Header band
                HStack(alignment: .top) {
                    HighlightedText(
                        text: profile.name.isEmpty ? (profile.identifier.isEmpty ? (profile.uuid.isEmpty ? "Unknown Profile" : profile.uuid) : profile.identifier) : profile.name,
                        query: committedFindText
                    )
                    .font(.system(size: 14, weight: .semibold))
                    if !isMobile {
                        if !profile.scope.isEmpty {
                            Badge(text: profile.scope, color: scopeColor(profile.scope))
                        }
                        // Provisioning profiles don't have an MDM install
                        // source, verification state, or removal-disallowed
                        // concept — those badges only apply to real MDM
                        // config profiles.
                        if profile.scope != "Provisioning" {
                            if profile.source == "MDM" {
                                Badge(text: "MDM")
                            } else if !profile.source.isEmpty {
                                Badge(text: profile.source, color: .secondary)
                            }
                            Badge(text: profile.verified ? "verified" : "unverified", color: profile.verified ? .green : .orange)
                            if profile.removalDisallowed {
                                Text("🔒").help("Removal disallowed")
                            }
                        }
                    }
                    if profile.scope != "Provisioning" {
                        Badge(text: "\(profile.payloads.count) payload\(profile.payloads.count == 1 ? "" : "s")", color: .secondary)
                    }
                    Spacer()
                }
                .padding(.horizontal, 16).padding(.vertical, 10)
                .frame(maxWidth: .infinity, alignment: .leading)
                .background(Color.secondary.opacity(0.08))

                // Metadata band
                VStack(alignment: .leading, spacing: 4) {
                    HStack(spacing: 16) {
                        if !profile.org.isEmpty {
                            HStack(spacing: 3) {
                                Text(profile.scope == "Provisioning" ? "Team:" : "Org:").font(.caption2).foregroundStyle(.secondary)
                                HighlightedText(text: profile.org, query: committedFindText).font(.caption2).foregroundStyle(.secondary)
                            }
                        }
                        if !profile.installDate.isEmpty {
                            Text("\(profile.scope == "Provisioning" ? "Expires" : "Installed"): \(profile.installDate)").font(.caption2).foregroundStyle(.secondary)
                        }
                        if !profile.identifier.isEmpty {
                            HighlightedText(text: profile.identifier, query: committedFindText)
                                .font(.system(size: 10, design: .monospaced)).foregroundStyle(.secondary)
                        }
                        if isMobile, !profile.uuid.isEmpty, profile.uuid != profile.identifier {
                            HighlightedText(text: profile.uuid, query: committedFindText)
                                .font(.system(size: 10, design: .monospaced)).foregroundStyle(.secondary)
                        }
                    }
                    if isMobile, !profile.description.isEmpty {
                        HighlightedText(text: profile.description, query: committedFindText)
                            .font(.caption2).italic().foregroundStyle(.secondary)
                    }
                }
                .padding(.horizontal, 16).padding(.vertical, 8)
                .frame(maxWidth: .infinity, alignment: .leading)
                .background(Color.secondary.opacity(0.03))

                // Provisioning profiles aren't payload-based at all — there's
                // nothing meaningful to show below the metadata band, so skip
                // straight past the payload section rather than displaying a
                // misleading "no payloads found".
                if profile.scope != "Provisioning" {
                    Divider()

                    if profile.payloads.isEmpty {
                        Text("No payloads found in this profile.")
                            .font(.caption).foregroundStyle(.secondary)
                            .padding(16)
                    } else {
                        VStack(spacing: 0) {
                            ForEach(profile.payloads.indices, id: \.self) { idx in
                                let payload = profile.payloads[idx]
                                PayloadDisclosureRow(
                                    payload: payload,
                                    isLast: idx == profile.payloads.indices.last,
                                    rowTint: idx.isMultiple(of: 2) ? Color.secondary.opacity(0.045) : Color.clear,
                                    isMatch: payloadMatches(payload),
                                    isExpanded: Binding(
                                        get: { expandedPayloadIDs.contains(payload.id) },
                                        set: { newValue in
                                            if newValue { expandedPayloadIDs.insert(payload.id) }
                                            else { expandedPayloadIDs.remove(payload.id) }
                                        }
                                    )
                                )
                            }
                        }
                    }
                }
            }
        }
    }
}

private struct PayloadDisclosureRow: View {
    let payload: ConfigProfilePayload
    let isLast: Bool
    let rowTint: Color
    let isMatch: Bool
    @Binding var isExpanded: Bool
    @Environment(\.findQuery) private var findQuery

    var body: some View {
        VStack(spacing: 0) {
            DisclosureGroup(isExpanded: $isExpanded) {
                if payload.payloadData.isEmpty {
                    Text("No payload data").font(.caption).foregroundStyle(.secondary).padding(.vertical, 6)
                } else {
                    ScrollView {
                        HighlightedText(text: payload.payloadData, query: findQuery)
                            .font(.system(size: 11, design: .monospaced))
                            .frame(maxWidth: .infinity, alignment: .leading)
                            .padding(10)
                    }
                    .frame(maxHeight: 320)
                    .background(Color.secondary.opacity(0.10))
                    .clipShape(RoundedRectangle(cornerRadius: 6))
                    .padding(.top, 4)
                }
            } label: {
                HStack {
                    HighlightedText(text: payload.displayName, query: findQuery).font(.system(size: 13, weight: .medium))
                    HighlightedText(text: payload.domain, query: findQuery)
                        .font(.system(size: 10, design: .monospaced))
                        .foregroundStyle(.secondary)
                        .padding(.horizontal, 6).padding(.vertical, 1)
                        .background(Color.secondary.opacity(0.10))
                        .overlay(RoundedRectangle(cornerRadius: 4).strokeBorder(Color.secondary.opacity(0.3)))
                        .clipShape(RoundedRectangle(cornerRadius: 4))
                    if isMatch {
                        Image(systemName: "checkmark.circle.fill")
                            .foregroundStyle(Color.accentColor)
                            .font(.caption2)
                            .help("Matches your search")
                    }
                }
            }
            .padding(.horizontal, 16).padding(.vertical, 8)
            .background(isMatch ? Color.accentColor.opacity(0.10) : rowTint)
            if !isLast {
                Divider()
            }
        }
    }
}
