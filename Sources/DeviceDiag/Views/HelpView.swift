import SwiftUI

/// Content shown in the Help window, opened from the Help menu (see
/// `DeviceDiagApp`'s `CommandGroup(replacing: .help)`). Kept in-app
/// rather than pointing at `USER_GUIDE.md` from the repo, since that file
/// isn't bundled into the built `.app` and wouldn't exist on a machine this
/// was installed on via Jamf Pro — this is the shippable equivalent, kept in
/// sync with the app's actual current behavior rather than the repo's docs.
private struct HelpSection: Identifiable {
    let id: String
    let title: String
    let icon: String
    /// Each entry is one paragraph or bullet. `**bold**` renders as bold —
    /// these go through `LocalizedStringKey` specifically so that works even
    /// though the strings are stored in this array rather than typed as
    /// literals directly into `Text(...)`.
    let paragraphs: [String]
}

private let helpSections: [HelpSection] = [
    HelpSection(
        id: "start",
        title: "Getting Started",
        icon: "play.circle",
        paragraphs: [
            "DeviceDiag turns a raw Apple sysdiagnose archive into a structured, readable report: device identity, MDM/Declarative Device Management state, installed configuration profiles, and quick access to the files and logs that matter most for troubleshooting.",
            "Drop a **.tar.gz**/**.tgz** sysdiagnose archive — or an already-extracted folder — onto the drop zone, click it to choose one, or type/paste a path directly and press Return.",
            "Analysis usually takes 30–60 seconds; large log archives can take longer. A progress overlay shows while it's running.",
            "Both macOS and iOS/iPadOS sysdiagnoses are supported — DeviceDiag detects which one it's looking at automatically and shows the relevant tabs.",
        ]
    ),
    HelpSection(
        id: "multi",
        title: "Multiple Sysdiagnoses",
        icon: "sidebar.left",
        paragraphs: [
            "Once more than one sysdiagnose is open, a sidebar appears on the left listing every open one as its own tab — handy for comparing two devices, or a before/after of the same device.",
            "Open another sysdiagnose with the **+** button at the top of the sidebar, by dragging a file or folder directly onto the sidebar, or with **⌘N**. Dropping several files at once opens a tab for each of them, not just the first.",
            "Opening the exact same file or folder that's already open switches you to that existing tab rather than analyzing it a second time.",
            "Hover a tab in the sidebar and click the **×** to close it. Closing the last open tab returns you to a fresh, blank upload screen rather than leaving the sidebar empty.",
            "The button at the bottom of the sidebar collapses it to a narrow icon-only strip — handy for reclaiming width when you're focused on one report. Hover an icon for that tab's name; click the same button again to expand it back.",
            "**Sync Tabs**, at the bottom of the sidebar once more than one sysdiagnose is open, keeps you on the same report section — say, Config Profiles — when you switch which sysdiagnose is selected, instead of always landing back on Device. Turn it off if you'd rather each sysdiagnose open independently on Device every time.",
        ]
    ),
    HelpSection(
        id: "device",
        title: "Device Tab",
        icon: "desktopcomputer",
        paragraphs: [
            "Basic device identity — the exact fields shown depend on the platform.",
            "**macOS**: Serial Number, OS Version, Build Number, Model Identifier, Hostname, plus a Managed Settings card (managed notifications, PPPC grants, managed login items) when that data is present.",
            "A **FileVault** card sits beside the Device Information table when the archive has `psm` (Password Slot Manager) output: enabled/disabled status, which local users/personal recovery key/institutional recovery key/MDM bootstrap token are enrolled to unlock the disk, and any credential whose failed-unlock-attempt count has crossed half its max-unlock-attempts. A short orange line calls out a missing MDM bootstrap token (on an MDM-managed Mac), no recovery key enrolled at all, or an admin account that isn't enrolled — hover the **ⓘ** next to any of them for why it matters.",
            "**iOS/iPadOS**: OS Version (with marketing name), Build Number, OS Family, Serial Number, UDID, Model Identifier/Number, Device Class, and Supervised/Return-to-Service badges, plus MDM enrollment info and a managed-apps list.",
            "**⌘F** opens a find bar that filters and highlights matches on this tab.",
        ]
    ),
    HelpSection(
        id: "declarations",
        title: "Declarations Tab",
        icon: "checkmark.seal",
        paragraphs: [
            "MDM Declarative Device Management (DDM) state — only shown when `rmd_inspect_system.txt` was found and parsed.",
            "A sync-summary strip shows the last MDM sync time and any consecutive sync errors. **Blueprint Declarations** groups activation/configuration status by Blueprint UUID; **Status Key Paths** lists every subscribed status key path, whether it needs sync, and its last known value.",
            "Click **Open** on a Status Key Path row to see that key path's raw unified-log activity in a separate Log Stream window. Hover a sync status icon for a tooltip showing the raw underlying value.",
            "In that Log Stream window, click any entry to pin it as a moment in time, then use **Open File Alongside…** to open another file from the sysdiagnose in a split pane, scrolled to whichever of its own lines is closest to that same moment — e.g. pin a declaration error at 8:01 AM and open install.log alongside it to see what was happening there at the same time.",
            "**⌘F** filters blueprints, status items, and standalone declarations together.",
        ]
    ),
    HelpSection(
        id: "profiles",
        title: "Config Profiles Tab",
        icon: "lock.doc",
        paragraphs: [
            "Every installed configuration profile, one card each.",
            "On macOS, profiles are grouped into **Device**, **User**, and **Provisioning** sections when the underlying data is scoped that way — each card shows a colored badge for its scope, plus an MDM-vs-other-source badge, verified/unverified state, a removal-disallowed lock icon, and a payload count (provisioning profiles show team/UUID/expiration instead, since they're not payload-based).",
            "Each payload is a collapsible row — click to expand its full raw payload data in a scrollable monospaced box.",
            "**⌘F** filters whole profiles by name/org/identifier/description or any payload's content, and auto-expands any payload that matches so you don't have to open rows one at a time.",
        ]
    ),
    HelpSection(
        id: "networking",
        title: "Networking Tab",
        icon: "wifi",
        paragraphs: [
            "A network health report built from the same files a sysdiagnose already collects: interface errors/drops, TCP retransmits, routing, DNS, proxy config, Wi-Fi signal quality, and the ping/DNS/curl connectivity probes macOS runs automatically during capture. Only shown when those files were found.",
            "**Summary of Findings** at the top calls out anything worth a second look — 🔴 failing, 🟡 warning, 🟢 OK, ℹ️ informational — sorted worst-first. Everything below it is the full detail those findings were drawn from: interfaces, error/drop rates, TCP stack health, routing table, DNS resolvers, proxy settings, reachability checks, Wi-Fi signal (including a computed SNR), and the active connectivity test results.",
            "Loss/error rates are judged against a general rule of thumb, not a strict standard: below 0.1% is negligible, 0.1–1% is acceptable for most traffic, 1–5% starts to affect real-time traffic (calls/video), and above 5% is a real problem.",
            "**Historical Wi-Fi Events** decodes the device's own Wi-Fi debug capture log, when the sysdiagnose has one — a rolling log of auth/deauth/reassociation failures that covers days, not just the moment this sysdiagnose was captured. Useful for spotting a pattern (e.g. repeated DNS-failure reassociations) that a single point-in-time snapshot wouldn't show.",
            "**Wi-Fi Signal & Link** has a second \"Environment Checks\" column when there's something worth flagging: current channel congestion always shows, and conflict-related checks (conflicting country code, hidden networks found, conflicting PHY mode/security) only show up when actually detected — a clean sysdiagnose won't clutter this with a wall of \"no conflict found\" rows.",
            "Every file this report reads from is also individually browsable in the **Files** tab's **Networking** group.",
            "**VPN & Proxy (Configured Services)** shows any configured VPN (name, provider, On-Demand state) and any network service with a real proxy type turned on — read from SystemConfiguration's own preferences file rather than a live snapshot, which is what makes it available on iOS/iPadOS too, unlike the DNS/proxy/reachability sections above (those need `scutil`, which only exists on macOS). Only appears when there's actually something configured.",
            "On iOS/iPadOS, interfaces, error/drop rates, TCP stack health, and the routing table populate the same way they do on macOS — sysdiagnose captures the identical tool output there, just under a different folder.",
            "**⌘F** filters findings and every table's rows together and highlights matches.",
        ]
    ),
    HelpSection(
        id: "settings",
        title: "Settings Tab (iOS/iPadOS)",
        icon: "gearshape",
        paragraphs: [
            "Only shown for mobile analyses. Every managed restriction key and where it came from — a profile, a DDM declaration, or an implicit device default.",
            "A summary card totals the count and breaks it down by source; filter pills (All / Profile / Declaration / Default) plus a search field narrow the table below.",
            "This tab already has its own search field, so **⌘F** just moves your cursor into it rather than opening a separate find bar.",
        ]
    ),
    HelpSection(
        id: "troubleshooting",
        title: "Troubleshooting Tab",
        icon: "magnifyingglass",
        paragraphs: [
            "The **Category** list adjusts to the sysdiagnose's own platform — categories and processes/subsystems that only make sense on macOS (Gatekeeper, XProtect, System Extensions, Jamf Connect, Jamf Remote Assist, and others) don't show up at all for an iOS/iPadOS sysdiagnose, and shared categories like MDM/enrollment automatically switch to iOS's own process and subsystem names (e.g. `mdmd` and `com.apple.ManagedConfiguration` instead of macOS's `mdmclient` and `com.apple.ManagedClient`) so filtering never silently returns nothing because of a macOS-only value.",
            "Runs `log show` queries against the archive's unified log. Pick a **Category** (App Installation, Jamf Connect/Pro/Self Service/Remote Assist, Enrollment/ADE, Networking, Security & Gatekeeper, Software Updates, System Extensions, or Custom) — for any of the predefined categories, **Filters** opens a checkbox dropdown listing every process, subsystem, and keyword its topics actually filter on, each labeled with which topic it came from in parentheses. Check as many as you like — everything checked, across every type and every topic, is OR'd together, so checking more only ever shows you more, never fewer, results (mixing a category's own filters with a hand-typed addition of your own is safe for exactly this reason — a custom `loginwindow` process checked alongside Jamf Connect's filters shows you both, rather than requiring one log line to somehow match both at once). A text field at the bottom of the dropdown lets you add your own process, subsystem, or keyword that isn't already listed. Nothing runs while you're picking — **Done** just closes the dropdown and keeps whatever's checked. **Custom** (the category) is separate — it skips the dropdown and lets you type one raw subsystem or process name directly.",
            "**Levels** narrows results to specific severities — Debug, Info, Default, Error, and/or Fault. It's an exact multi-select, not a threshold: checking Error and Fault shows only those two, not anything less severe in between. Leave nothing checked to see every level, same as before this existed.",
            "**Timeframe** is a number plus a Minutes/Days unit — leave the number blank to query all time. Nothing runs until you click **Run**, to the right of the timeframe fields, so checking boxes or typing a timeframe never fires a query by itself. **Show Query** reveals the exact `log show` command that last ran, including the combined predicate built from whatever was checked.",
            "Results load in pages — scroll to the bottom and click **Load More** to reveal more. **Export** always saves the *complete* result set to a file, not just what's currently loaded on screen.",
            "Each result line is one whole log entry (timestamp, process, and message together), selected and copied as a single unit rather than a string you'd drag-select part of. Click a line to select just that one — it also pins it as a moment in time — then use **Open File Alongside…** to open another file from the sysdiagnose in a split pane, scrolled to whichever of its own lines is closest to that same moment.",
            "To select several lines at once, **Shift-click** another line to select everything in between, or **Cmd-click** to add/remove individual lines — the same convention as a Finder or Mail list. Copy the selection with the **Copy N Lines** button in the status bar (**Clear Selection** next to it drops the selection without copying), or by **right-clicking** any selected line and choosing **Copy** — right-clicking a line outside the current selection copies just that one line instead.",
            "This is the one tab that resizes with the window — make the window bigger or full-screen it for more room to read long log lines. Switching to another report tab and back preserves everything here — your category/topic, results, and any pinned moment/companion file.",
            "The query bar above the results — Category, Filters, Levels, Timeframe, Run, and (once you have results) Show Query/Export/Open File Alongside — reflows onto a second row as a whole once the window gets too narrow for all of it on one line, rather than shrinking or scrolling piece by piece, so nothing ends up cut off at the edge.",
            "**⌘F** filters the loaded and unloaded log lines together and highlights matches.",
        ]
    ),
    HelpSection(
        id: "files",
        title: "Files Tab",
        icon: "folder",
        paragraphs: [
            "Quick access to every notable file DeviceDiag recognizes in the archive, grouped into cards (OS & Software, Device & Hardware, MDM & Management, Storage & Security, Logs & Diagnostics, Networking, Processes & Performance) laid out in two columns, balanced by each card's actual size rather than paired purely by position. Only groups with at least one file actually present show up. The Networking group is the file set the Networking tab's report is built from — shown as two folder rows, **network-info** and **WiFi**, each opening straight to that folder in Finder.",
            "Click **Open** to view a file. Text-ish files (`.txt`, `.log`, `.plist`, `.json`, `.csv`) open in a fast built-in viewer — plists are pretty-printed automatically. Anything else opens in its normal macOS app (the `.logarchive` opens in Console).",
            "Entries representing more than one underlying file (like launchd's per-UID dumps) show a **Reveal (N)** button instead — it selects every file together in one Finder window.",
            "In the built-in viewer, **⌘F** jumps between matches (with surrounding context) rather than filtering the file down to matching lines, since that would lose the context around a hit.",
        ]
    ),
    HelpSection(
        id: "notes",
        title: "Notes Tab",
        icon: "exclamationmark.triangle",
        paragraphs: [
            "Only appears if something came up worth flagging while parsing — a missing expected file, a parse failure, etc. — as a simple list.",
        ]
    ),
    HelpSection(
        id: "shortcuts",
        title: "Keyboard Shortcuts",
        icon: "keyboard",
        paragraphs: [
            "**⌘N** — open another sysdiagnose in a new sidebar tab.",
            "**⌘R** — clear the path field and any error on the upload screen (only while a tab is showing that screen).",
            "**⌘F** — find within the current report tab; behavior varies slightly by tab (filters rows on most, jumps between matches in the file viewer).",
            "**⌘C** — copy any selected text anywhere in a report; text selection is enabled throughout.",
        ]
    ),
    HelpSection(
        id: "diagnostics",
        title: "Diagnostics Log",
        icon: "doc.text.magnifyingglass",
        paragraphs: [
            "DeviceDiag keeps its own log of what it's doing behind the scenes — separate from the sysdiagnose data being analyzed — so a slow or failed archive extraction, a `log show` query that silently timed out, or a caught error has somewhere to show up that doesn't vanish the moment an error banner is dismissed.",
            "Useful when a particular sysdiagnose intermittently hangs or comes back with less than expected, especially a large one where a `log show` query against the `.logarchive` can time out.",
            "Choose **Help ▸ Reveal Diagnostics Log** (or the button below) to reveal it in Finder. It lives at `~/Library/Logs/DeviceDiag/DeviceDiag.log` — the same place Console.app's \"Log Reports\" section looks — and also mirrors every entry to the unified log under the `com.devicediag.app` subsystem if you'd rather filter it live in Console.app while reproducing something.",
        ]
    ),
    HelpSection(
        id: "tips",
        title: "Tips",
        icon: "lightbulb",
        paragraphs: [
            "**Start Over**, top-right of a report, resets just that one tab back to the upload screen — it doesn't close the tab or touch any other open sysdiagnose.",
            "Dropping the same file that's already open (via the sidebar, Dock icon, or Open With) always switches to the existing tab instead of duplicating it. That check runs per file even when dropping several at once.",
            "Values ending in an asterisk (`*`) on the Declarations tab are best-effort, inferred from static files rather than a live log entry — treat them as a fallback, not a guarantee.",
        ]
    ),
]

/// The Help window's content — a section list on the left, the selected
/// section's text on the right. Opened via `openWindow(id: "help")` from the
/// Help menu.
struct HelpView: View {
    // `List(_:selection:)` only offers optional- or set-based selection
    // bindings, even for a strictly single-selection sidebar like this one.
    @State private var selectedID: String? = helpSections.first?.id

    private var selectedSection: HelpSection {
        helpSections.first { $0.id == selectedID } ?? helpSections[0]
    }

    var body: some View {
        HStack(spacing: 0) {
            List(helpSections, selection: $selectedID) { section in
                Label(section.title, systemImage: section.icon)
                    .tag(section.id)
            }
            .listStyle(.sidebar)
            .frame(width: 200)

            Divider()

            ScrollView {
                VStack(alignment: .leading, spacing: 14) {
                    Text(selectedSection.title)
                        .font(.title2.bold())
                    ForEach(Array(selectedSection.paragraphs.enumerated()), id: \.offset) { _, paragraph in
                        Text(LocalizedStringKey(paragraph))
                            .font(.system(size: 13))
                            .lineSpacing(3)
                            .fixedSize(horizontal: false, vertical: true)
                    }
                    if selectedSection.id == "diagnostics" {
                        Button {
                            DiagnosticsLog.reveal()
                        } label: {
                            Label("Reveal Diagnostics Log in Finder", systemImage: "folder")
                        }
                    }
                }
                .padding(24)
                .frame(maxWidth: 560, alignment: .leading)
                .frame(maxWidth: .infinity, alignment: .leading)
            }
            .textSelection(.enabled)
        }
        .frame(minWidth: 720, minHeight: 480)
    }
}
