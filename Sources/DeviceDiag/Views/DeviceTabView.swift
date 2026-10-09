import SwiftUI

struct DeviceTabView: View {
    let result: AnalysisResult

    @State private var findText = ""
    @State private var committedFindText = ""
    @State private var showFindBar = false
    @FocusState private var findFieldFocused: Bool

    var body: some View {
        VStack(alignment: .leading, spacing: 16) {
            if showFindBar {
                FindBarView(placeholder: "Find on this page", text: $findText,
                            isFocused: $findFieldFocused) {
                    showFindBar = false
                    findText = ""
                }
            }
            if result.isMobile {
                mobileDeviceCard
                enrollmentCard
                if !result.mobileManagedApps.isEmpty {
                    managedAppsCard
                }
            } else {
                // The FileVault card is deliberately narrow and sits beside
                // the Device Information table rather than below it — that
                // table doesn't need the full window width, and stacking
                // them instead just pushes everything else further down the
                // page for no benefit.
                if result.fileVault.found {
                    HStack(alignment: .top, spacing: 16) {
                        macDeviceCard
                        fileVaultCard
                            .frame(width: 320)
                    }
                } else {
                    macDeviceCard
                }
                if !result.managedSettings.isEmpty {
                    managedSettingsCard
                }
            }
        }
        .environment(\.findQuery, committedFindText)
        .background(FindShortcut { showFindBar = true; findFieldFocused = true })
        .task(id: findText) {
            try? await Task.sleep(nanoseconds: 150_000_000)
            if !Task.isCancelled { committedFindText = findText }
        }
    }

    // MARK: macOS

    private var macDeviceCard: some View {
        CardView(title: "💻 Device Information") {
            VStack(spacing: 0) {
                InfoRow(label: "Serial Number", value: result.deviceInfo.serialNumber)
                Divider().padding(.leading, 16)
                InfoRow(label: "Operating System Version", value: result.deviceInfo.osVersion, monospaced: false)
                Divider().padding(.leading, 16)
                InfoRow(label: "Build Number", value: result.deviceInfo.buildNumber)
                Divider().padding(.leading, 16)
                InfoRow(label: "Model Identifier", value: result.deviceInfo.modelIdentifier)
                Divider().padding(.leading, 16)
                InfoRow(label: "Hostname", value: result.deviceInfo.hostname)
            }
        }
        // `CardView`'s title bar is `.frame(maxWidth: .infinity)` so a
        // card's header spans its own full width — the right call for
        // every other card in this app, which are meant to stretch, but it
        // also means this one greedily claims whatever width the
        // surrounding `HStack` offers even though its actual content (a
        // 190pt label column plus one line of value text) never needs
        // more than this. Uncapped, that greediness was squeezing the
        // FileVault card next to it — which does need its full 320pt —
        // out of room far sooner than the window's actual width justified.
        .frame(maxWidth: 480, alignment: .leading)
    }

    private var managedSettingsCard: some View {
        CardView(title: "🔧 Managed Settings") {
            VStack(alignment: .leading, spacing: 0) {
                if !result.managedSettings.managedNotifications.isEmpty {
                    listRow(label: "Managed Notifications", items: result.managedSettings.managedNotifications)
                }
                if !result.managedSettings.pppcIdentifiers.isEmpty {
                    Divider().padding(.leading, 16)
                    listRow(label: "PPPC Installed for", items: result.managedSettings.pppcIdentifiers)
                }
                if !result.managedSettings.managedLoginItems.isEmpty {
                    Divider().padding(.leading, 16)
                    listRow(label: "Managed Login Items", items: result.managedSettings.managedLoginItems, monospaced: false)
                }
            }
        }
    }

    /// One row of the FileVault card's "Enrolled unlock methods" list — a
    /// local user, the personal/institutional recovery key, or the MDM
    /// bootstrap token, each with its own enrolled/not-enrolled state.
    private struct FileVaultMethodRow: Identifiable {
        let id = UUID()
        let icon: String
        let label: String
        let enrolled: Bool
    }

    private var fileVaultMethodRows: [FileVaultMethodRow] {
        let fv = result.fileVault
        var rows: [FileVaultMethodRow] = fv.enrolledUsers.map {
            FileVaultMethodRow(icon: "person.fill", label: $0, enrolled: true)
        }
        rows += fv.adminUsersNotEnrolled.map {
            FileVaultMethodRow(icon: "person.fill", label: $0, enrolled: false)
        }
        rows.append(FileVaultMethodRow(icon: "key.fill", label: "Personal recovery key", enrolled: fv.hasPersonalRecoveryKey))
        if fv.hasInstitutionalRecoveryKey {
            rows.append(FileVaultMethodRow(icon: "building.2.fill", label: "Institutional recovery key", enrolled: true))
        }
        rows.append(FileVaultMethodRow(icon: "shield.lefthalf.filled", label: "MDM bootstrap token", enrolled: fv.hasBootstrapToken))
        return rows
    }

    private var fileVaultCard: some View {
        let fv = result.fileVault
        return CardView {
            VStack(alignment: .leading, spacing: 0) {
                HStack {
                    Text("🔒 FileVault").font(.system(size: 14, weight: .semibold))
                    Spacer()
                    Badge(text: fv.enabled ? "Enabled" : "Disabled", color: fv.enabled ? .green : .secondary)
                }
                .padding(.horizontal, 16).padding(.vertical, 10)
                .frame(maxWidth: .infinity, alignment: .leading)
                .background(Color.secondary.opacity(0.06))
                Divider()

                VStack(alignment: .leading, spacing: 12) {
                    if fv.missingBootstrapToken {
                        fileVaultWarningRow(
                            text: "No MDM bootstrap token enrolled",
                            detail: "Blocks unattended FileVault operations and kernel extension approvals."
                        )
                    }
                    if fv.hasNoRecoveryMechanism {
                        fileVaultWarningRow(
                            text: "No recovery key enrolled",
                            detail: "If an enrolled user forgets their password, this volume may be unrecoverable."
                        )
                    }
                    if !fv.adminUsersNotEnrolled.isEmpty {
                        fileVaultWarningRow(
                            text: "Admin not enrolled: \(fv.adminUsersNotEnrolled.joined(separator: ", "))",
                            detail: "This admin account can't unlock the disk at boot."
                        )
                    }

                    VStack(alignment: .leading, spacing: 5) {
                        Text("Enrolled unlock methods")
                            .font(.system(size: 11)).foregroundStyle(.secondary)
                        ForEach(fileVaultMethodRows) { row in
                            HStack(spacing: 8) {
                                Image(systemName: row.icon)
                                    .font(.system(size: 11))
                                    .foregroundStyle(.secondary)
                                    .frame(width: 16)
                                Text(row.label)
                                    .font(.system(size: 12))
                                    .lineLimit(1)
                                Spacer(minLength: 4)
                                Image(systemName: row.enrolled ? "checkmark.circle.fill" : "xmark.circle.fill")
                                    .font(.system(size: 12))
                                    .foregroundStyle(row.enrolled ? Color.green : Color.red.opacity(0.75))
                            }
                        }
                    }

                    if !fv.nearLockoutSlots.isEmpty {
                        VStack(alignment: .leading, spacing: 5) {
                            Text("Unlock attempts")
                                .font(.system(size: 11)).foregroundStyle(.secondary)
                            ForEach(fv.nearLockoutSlots) { slot in
                                HStack(spacing: 8) {
                                    Image(systemName: "exclamationmark.triangle.fill")
                                        .font(.system(size: 11))
                                        .foregroundStyle(.orange)
                                        .frame(width: 16)
                                    Text(slot.label)
                                        .font(.system(size: 12))
                                        .lineLimit(1)
                                    Spacer(minLength: 4)
                                    Text("\(slot.failedAttempts) of \(slot.maxAttempts) failed")
                                        .font(.system(size: 11, weight: .medium))
                                        .foregroundStyle(.orange)
                                }
                            }
                        }
                    }
                }
                .padding(16)
            }
        }
    }

    private func fileVaultWarningRow(text: String, detail: String) -> some View {
        HStack(spacing: 6) {
            Image(systemName: "exclamationmark.triangle.fill")
                .font(.system(size: 11))
                .foregroundStyle(.orange)
            Text(text)
                .font(.system(size: 12))
                .foregroundStyle(.orange)
                .lineLimit(2)
            Image(systemName: "info.circle")
                .font(.system(size: 11))
                .foregroundStyle(.secondary)
                .help(detail)
            Spacer(minLength: 0)
        }
    }

    private func listRow(label: String, items: [String], monospaced: Bool = true) -> some View {
        HStack(alignment: .top) {
            Text(label)
                .font(.system(size: 12))
                .foregroundStyle(.secondary)
                .frame(width: 190, alignment: .leading)
            VStack(alignment: .leading, spacing: 2) {
                ForEach(items, id: \.self) { item in
                    ListRowItem(item: item, monospaced: monospaced)
                }
            }
            Spacer(minLength: 0)
        }
        .padding(.horizontal, 16)
        .padding(.vertical, 8)
    }

    // MARK: Mobile

    private var mobileDeviceCard: some View {
        let md = result.mobileDeviceInfo
        return CardView(title: "📱 Device Information") {
            VStack(spacing: 0) {
                InfoRow(label: "Operating System Version",
                        value: md.osVersion != "Not found" ? "\(md.marketingName) (\(md.osVersion))" : md.marketingName,
                        monospaced: false)
                rowDivider
                InfoRow(label: "Build Number", value: md.buildNumber)
                rowDivider
                InfoRow(label: "OS Family", value: md.osFamily, monospaced: false)
                rowDivider
                InfoRow(label: "Serial Number", value: md.serialNumber)
                rowDivider
                InfoRow(label: "UDID", value: md.udid)
                rowDivider
                InfoRow(label: "Model Identifier", value: md.modelIdentifier)
                rowDivider
                InfoRow(label: "Model Number", value: md.modelNumber)
                rowDivider
                InfoRow(label: "Device Class", value: md.deviceClass.isEmpty ? "—" : md.deviceClass, monospaced: false)
                rowDivider
                boolRow(label: "Supervised", value: md.isSupervised, trueColor: .green, falseText: "No")
                rowDivider
                boolRow(label: "Return to Service", value: md.isRTS, trueColor: .blue, trueText: "Enabled", falseText: "Disabled")
            }
        }
    }

    private var enrollmentCard: some View {
        let me = result.mobileEnrollment
        return CardView(title: "🔗 Enrollment Information") {
            if me.mdmProfileID.isEmpty && me.serverURL.isEmpty && me.topic.isEmpty {
                EmptyStateView(text: "MDM.plist not found — enrollment details unavailable.")
            } else {
                VStack(spacing: 0) {
                    if !me.mdmProfileID.isEmpty {
                        InfoRow(label: "MDM Profile Identifier", value: me.mdmProfileID)
                        rowDivider
                    }
                    if !me.serverURL.isEmpty {
                        InfoRow(label: "MDM Server URL", value: me.serverURL)
                        rowDivider
                    }
                    boolRow(label: "Automated Device Enrollment (ADE)", value: me.isADE, trueColor: .green, falseText: "No")
                    if !me.topic.isEmpty {
                        rowDivider
                        InfoRow(label: "APNs Topic", value: me.topic)
                    }
                }
            }
        }
    }

    private var managedAppsCard: some View {
        CardView {
            VStack(alignment: .leading, spacing: 0) {
                HStack {
                    Text("📦 Managed Apps").font(.system(size: 14, weight: .semibold))
                    Badge(text: "\(result.mobileManagedApps.count)")
                }
                .padding(.horizontal, 16).padding(.vertical, 10)
                .frame(maxWidth: .infinity, alignment: .leading)
                .background(Color.secondary.opacity(0.06))
                Divider()

                VStack(alignment: .leading, spacing: 0) {
                    HStack {
                        Text("Bundle ID").frame(width: 260, alignment: .leading)
                        Text("State").frame(width: 130, alignment: .leading)
                        Text("Flags").frame(maxWidth: .infinity, alignment: .leading)
                        Text("Removable").frame(width: 80, alignment: .leading)
                    }
                    .font(.caption).foregroundStyle(.secondary)
                    .padding(.horizontal, 16).padding(.vertical, 8)
                    Divider()

                    ForEach(result.mobileManagedApps) { app in
                        ManagedAppRow(app: app, isLast: app.id == result.mobileManagedApps.last?.id,
                                      stateColor: appStateColor(app.stateRaw))
                    }
                }
                .padding(.vertical, 8)
            }
        }
    }

    private func appStateColor(_ raw: Int) -> Color {
        if [4, 7, 8].contains(raw) { return .green }
        if [1, 2, 3, 5, 6, 9].contains(raw) { return .orange }
        return .secondary
    }

    private var rowDivider: some View { Divider().padding(.leading, 16) }

    private func boolRow(label: String, value: Bool?, trueColor: Color, trueText: String = "Yes", falseText: String) -> some View {
        HStack {
            Text(label).font(.system(size: 12)).foregroundStyle(.secondary).frame(width: 190, alignment: .leading)
            if let value {
                Badge(text: value ? trueText : falseText, color: value ? trueColor : .secondary)
            } else {
                Text("Unknown").font(.system(size: 12)).foregroundStyle(.secondary)
            }
            Spacer(minLength: 0)
        }
        .padding(.horizontal, 16).padding(.vertical, 7)
    }
}

/// Extracted as a standalone View (rather than an inline ForEach closure body)
/// so its type is concrete and doesn't force SwiftUI to infer the row's View
/// type jointly with ForEach's overload resolution.
private struct ManagedAppRow: View {
    let app: ManagedApp
    let isLast: Bool
    let stateColor: Color
    @Environment(\.findQuery) private var findQuery

    var body: some View {
        VStack(spacing: 0) {
            HStack {
                HighlightedText(text: app.bundleID, query: findQuery)
                    .font(.system(size: 12, design: .monospaced))
                    .frame(width: 260, alignment: .leading)
                Badge(text: app.state, color: stateColor)
                    .frame(width: 130, alignment: .leading)
                HighlightedText(text: app.flags, query: findQuery)
                    .font(.caption).foregroundStyle(.secondary)
                    .frame(maxWidth: .infinity, alignment: .leading)
                Text(app.removable ? "Yes" : "No")
                    .font(.caption)
                    .foregroundStyle(app.removable ? Color.secondary : Color.orange)
                    .frame(width: 80, alignment: .leading)
            }
            .padding(.horizontal, 16).padding(.vertical, 6)
            if !isLast {
                Divider().padding(.leading, 16)
            }
        }
    }
}

private struct ListRowItem: View {
    let item: String
    let monospaced: Bool
    @Environment(\.findQuery) private var findQuery

    var body: some View {
        HighlightedText(text: item, query: findQuery)
            .font(monospaced ? .system(size: 12, design: .monospaced) : .system(size: 12))
    }
}
