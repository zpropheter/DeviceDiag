# DeviceDiag — Page-by-Page Guide

A tour of every screen: what's on it, where to find things, and what's
clickable. Screenshots aren't in here yet — drop PNGs into a `screenshots/`
folder next to this file and swap them in for the `> [screenshot: ...]`
placeholders below (suggested filenames are already in the placeholders).

For how the app works under the hood, see `ARCHITECTURE.md`. All of this is
also available inside the app itself — **Help ▸ DeviceDiag Help** (⌘?) opens
a searchable-by-eye version of this same tour in its own window, kept in
sync with the app's current behavior.

## Sidebar — multiple sysdiagnoses

> [screenshot: screenshots/sidebar.png]

Hidden until there's something to switch between. As soon as a second
sysdiagnose is open (or the first one has finished analyzing), a sidebar
appears on the left listing every open sysdiagnose as its own row/tab —
useful for comparing two devices, or a before/after of the same device.

- Open another one with the **+** button at the top of the sidebar, by
  dragging a file or folder onto the sidebar, or with **⌘N**. Dropping
  several files at once opens a tab for each of them.
- Opening the exact same file or folder that's already open in another tab
  switches you to that tab instead of analyzing it again.
- Hover a row and click the **×** to close that tab. Closing the last tab
  returns to a fresh, blank upload screen rather than leaving the sidebar
  empty.
- The button at the bottom collapses the sidebar to a narrow icon-only
  strip, freeing up width for the report — hover an icon for that tab's
  name, click the button again to expand it back.
- **Sync Tabs**, also at the bottom (once more than one sysdiagnose is
  open), keeps you on the same report section — say, Config Profiles — when
  you switch which sysdiagnose is selected in the sidebar, instead of
  always landing back on Device. Turn it off to have each sysdiagnose open
  independently on Device every time.

## Upload screen

> [screenshot: screenshots/upload.png]

The landing screen, shown until an analysis has run.

- A dashed drop zone — drag a `.tar.gz` sysdiagnose archive (or an
  already-extracted folder) onto it, or click it to open a file/folder
  picker.
- Below that, a text field where you can type or paste a path directly and
  press Return (or click **Analyze**).
- If the last analysis failed, a red error banner appears above the drop
  zone (bad path, extraction failure, etc.).
- While an analysis is running, a full-screen overlay shows a spinner and a
  note that log-archive parsing can take 30–60 seconds on a large archive.
- **Cmd+R** clears the path field and any error banner (only active on this
  screen).

Both `.tar.gz`/`.tgz` archives and already-extracted folders are accepted —
you don't need to unzip anything first.

## Results screen — top bar and tabs

> [screenshot: screenshots/results-overview.png]

Once an analysis completes, the whole window switches to the results view:

- **Top bar**: "DeviceDiag", the archive's filename (truncated in the
  middle if long), the analysis timestamp, and a **↺ Start Over** button
  that resets just this one tab back to the Upload screen — it doesn't
  close the tab or touch any other open sysdiagnose.
- **Tab bar**: a row of tabs, each with an emoji + label. Only tabs with
  actual data appear — for example, **Settings** only shows up for
  iOS/iPadOS analyses, and **Notes** only shows up if something worth
  flagging came up while parsing (missing files, parse warnings).

Tab order is always: Device → Declarations → Config Profiles → Networking →
Settings (iOS only) → Troubleshooting → Files → Notes.

Text everywhere in the results view is selectable — you can click-drag and
copy anything (a value, a whole card, a log line) with Cmd+C like any
normal document.

## Device tab

> [screenshot: screenshots/device-tab.png]

Basic device identity — content differs by platform:

- **macOS**: Serial Number, OS Version, Build Number, Model Identifier,
  Hostname. If the archive has managed-settings data, a second card lists
  Managed Notifications, PPPC-installed-for apps, and Managed Login Items.
- **FileVault card** (macOS, next to Device Information): shown when the
  archive has `psm` (Password Slot Manager) output — `psm_status.txt`,
  `psm_list.txt`, `psm_stderr.txt`. Shows enabled/disabled status and every
  enrolled unlock method (local users, personal recovery key, institutional
  recovery key, MDM bootstrap token) with a check or an X. An orange line
  above the list calls out a missing MDM bootstrap token on an
  MDM-managed Mac, no recovery key enrolled at all, or an admin account
  that isn't enrolled and can't unlock the disk at boot — hover the **ⓘ**
  next to any of them for the detail. A separate "Unlock attempts" section
  only appears when a credential's combined failed-unlock-attempt count has
  crossed 50% of its max-unlock-attempts — a live lockout risk, not just
  history, since that counter resets on a successful unlock.
- **iOS/iPadOS**: OS Version (with marketing name, e.g. "18.1 (Sonoma)"),
  Build Number, OS Family, Serial Number, UDID, Model Identifier/Number,
  Device Class, and Supervised/Return-to-Service badges. A second card
  shows MDM enrollment info (MDM Profile Identifier, Server URL, ADE badge,
  APNs Topic) — or a note if no `MDM.plist` was found. A third card lists
  managed apps (Bundle ID, State, Flags, Removable) if any are present.

**Cmd+F** opens a find bar that highlights and filters matches on this tab.

## Declarations tab

> [screenshot: screenshots/declarations-tab.png]

MDM Declarative Device Management (DDM) state — only shown if
`rmd_inspect_system.txt` was found and parsed.

- A sync-summary strip at the top shows the last MDM sync time and whether
  there have been consecutive sync errors.
- **Blueprint Declarations** table: one row per Blueprint UUID, with
  columns for Blueprint UUID, Configuration Type, Activations, and
  Configurations. Each Activations/Configurations cell shows a ✓/⚠/✕
  status plus a count; a `×N` badge appears when duplicate status groups
  are collapsed. The card header shows a count and, if any blueprint has a
  problem, an orange "N with issues" badge.
- **Status Key Paths** table: every subscribed MDM status key path, whether
  it needs sync, when it last synced, and its last known value (values
  ending in `*` are inferred from static files rather than a live log
  entry). Click **Open** on a row to view that key path's raw log activity
  in a separate Log Stream window (only enabled if a log archive was
  found).
- **System Configurations** / **Management Declarations** cards: any
  activation/configuration/management declarations that aren't tied to a
  specific Blueprint.

Hover over a sync status icon for a tooltip with the raw underlying value
(useful if a sync status looks wrong and you want to see exactly why).
**Cmd+F** filters blueprints, status items, and standalone declarations
together.

## Config Profiles tab

> [screenshot: screenshots/config-profiles-tab.png]

Every installed configuration profile, one card each — only shown if
profile data was found.

- On macOS, profiles are grouped into **Device**, **User**, and
  **Provisioning** sections when the underlying data is scoped that way
  (newer macOS versions report profiles this way; older ones may not, in
  which case profiles show ungrouped as before). Each card's header shows a
  colored scope badge, the profile name, identifier/UUID, an
  MDM-vs-other-source badge, a verified/unverified badge, a lock icon if
  removal is disallowed, and a payload count — provisioning profiles show
  Team/UUID/Expiration instead of a payload count, since they aren't
  payload-based.
- Below that: organization, install date, and (iOS) description.
- Each payload is a collapsible row — click to expand and see its full raw
  payload data in a scrollable monospaced box.

**Cmd+F** filters whole profiles by name/org/identifier/description or any
payload's content, and auto-expands any payload that matches your search
so you don't have to open rows one at a time to find a hit.

## Networking tab

> [screenshot: screenshots/networking-tab.png]

A network health report built from the same files a sysdiagnose already
collects — only shown when those files were found. Interface errors/drops,
TCP retransmits, routing, DNS, proxy config, Wi-Fi signal quality, and the
ping/DNS/curl connectivity probes macOS runs automatically as part of every
sysdiagnose capture.

- **Summary of Findings** at the top calls out anything worth a second
  look — 🔴 failing, 🟡 warning, 🟢 OK, ℹ️ informational — sorted
  worst-first.
- Below that, the full detail those findings were drawn from: an
  **Interfaces** table, per-interface **error/drop rates** (with the rate
  each error/drop represents as a % of that interface's lifetime packet
  count), **TCP/IP stack health**, the **routing** table, **DNS** resolver
  configuration and reachability, **proxy** settings, **SCNetworkReachability**
  checks, **Wi-Fi signal** (including a computed SNR from RSSI/noise), and
  the **active connectivity test** results with any ping packet loss.
- A **VPN & Proxy (Configured Services)** card, when there's anything to
  show: any VPN service configured on the device (name, provider, whether
  On-Demand is enabled) and any network service with an actual proxy type
  turned on. This is read straight from SystemConfiguration's own
  `preferences.plist` rather than a live `scutil` snapshot, which is what
  makes it available on iOS/iPadOS too — `scutil` isn't a binary that
  exists there, so the DNS/proxy/SCNetworkReachability sections above are
  macOS-only, but this card isn't.
- On iOS/iPadOS, the Interfaces, error/drop rates, TCP/IP stack health, and
  routing sections above are populated too — sysdiagnose captures the exact
  same `ifconfig`/`netstat`/`route` output there, just under a different
  folder.
- Loss/error rates are judged against a general rule of thumb, not a strict
  standard: below 0.1% is negligible, 0.1–1% is acceptable for most
  traffic, 1–5% starts to affect real-time traffic (calls/video), and above
  5% is a real problem.
- Every file this report reads from is also individually browsable in the
  Files tab's **Networking** group.

**Cmd+F** filters findings and every table's rows together and highlights matches.

## Settings tab (iOS/iPadOS only)

> [screenshot: screenshots/settings-tab.png]

Only shown for mobile analyses. Shows every managed restriction key and
where it came from.

- A summary card at the top: total restriction count, and a breakdown of
  how many came from a profile, a DDM declaration, or an implicit device
  default.
- Filter pills (All / Profile / Declaration / Default) narrow the table
  below, plus a persistent search field.
- The table itself: Restriction Key, its value, a colored source badge, and
  a detail column (e.g. the timestamp a declaration was set, or which
  profile a restriction came from).
- Profile and Declaration are only used when there's real evidence behind
  them — a profile has to resolve to an actual installed profile stub, and
  a declaration only counts if the device genuinely has DDM declaration
  data. A key with no currently active managed source — including one an
  already-removed profile used to set — shows as Default rather than
  guessing.

Unlike other tabs, **Cmd+F** here doesn't open a pop-up find bar — it just
moves your cursor into the existing search field, since this tab already
has one.

## Troubleshooting tab

> [screenshot: screenshots/troubleshooting-tab.png]

Runs predefined `log show` queries against the archive's unified log.

- The category and filter lists adjust to the sysdiagnose's platform automatically. A macOS-only category (Jamf Connect, Jamf Remote Assist, System and Kernel Extensions, and the Gatekeeper/XProtect filters under Security & Gatekeeper) simply doesn't appear on an iOS/iPadOS sysdiagnose, since there's nothing on iOS for those to match. Categories that exist on both platforms show iOS's own process/subsystem names automatically — MDM- and enrollment-related filters switch to `mdmd` and `com.apple.ManagedConfiguration` instead of macOS's `mdmclient` and `com.apple.ManagedClient`, and Setup Assistant's filter switches to `Setup` (its iOS process name) instead of macOS's `Setup Assistant`.
- Pick a **Category** (App Installation, Jamf Connect/Pro/Self
  Service/Remote Assist, Enrollment/ADE, Networking, Security & Gatekeeper,
  Software Updates, System Extensions, or Custom).
- For any predefined category, **Filters** opens a checkbox dropdown listing
  the actual processes, subsystems, and keywords its topics filter on —
  each one labeled with which topic(s) it came from in parentheses, e.g.
  `com.apple.commerce (App Store / StoreKit installs)`. Check as many as
  you want: everything checked, across every type (process/subsystem/
  keyword) and every topic, is OR'd together — checking more boxes only
  ever shows you more, never fewer, results. That's what makes it safe to
  mix a category's own topics with a hand-typed addition of your own (a
  process or subsystem that isn't already listed, via the text field at
  the bottom of the dropdown) to look at unrelated things side by side —
  e.g. checking Jamf Connect's own filters plus a custom `loginwindow`
  process shows you both, rather than requiring a single log line to
  somehow match both at once (which real log lines essentially never do,
  and used to mean that combination silently returned nothing). Nothing
  runs while you're picking — **Done** just closes the dropdown and keeps
  whatever's checked for when you're ready to run it.
- **Custom** category is separate from all of the above — it skips the
  dropdown and lets you type one raw subsystem or process name directly.
- **Levels** narrows results to specific severities — Debug, Info, Default,
  Error, and/or Fault (the five values `log show` itself recognizes; there's
  no separate "Warning" level). It's an exact multi-select, not a threshold:
  checking Error and Fault shows only those two, not anything less severe
  along the way. Leave nothing checked to see every level.
- **Timeframe** is a number plus a Minutes/Days unit — leave the number
  blank to query all time.
- Nothing actually queries the log until you click **Run**, to the right of
  the timeframe fields — checking boxes, adding a custom filter, or typing
  a timeframe never fires a query on its own, so there's no risk of
  kicking one off by accident while you're still picking filters.
- **Show Query** reveals the exact `log show` command that last ran,
  including the combined predicate built from whatever was checked.
- Results load in pages of 2000 lines to keep a noisy log responsive —
  scroll to the bottom and click **Load More** to reveal more.
- **Export** always saves the *complete* result set to a file, not just
  whatever's currently loaded on screen.
- Each result line is one whole log entry — timestamp, process, and
  message together — selected and copied as a single unit rather than as
  a string you'd drag-select part of. Click a line to select just that
  one; it also pins it as a moment in time, so **Open File Alongside…** in
  the toolbar can open another file from the sysdiagnose in a split pane,
  scrolled to whichever of its own lines is closest to that same moment —
  e.g. pin an error at 8:01 AM and open `install.log` alongside it to see
  what else was happening then. The menu only lists files worth
  correlating a moment against — `install.log` and `system.log` — rather
  than every text-ish file in the archive, since most of the rest (process
  lists, disk inventories, hardware dumps) are a single snapshot with no
  per-line timestamps to land on.
- To select several lines at once, click one then **Shift-click** another
  to select every line in between (or **Cmd-click** to add/remove
  individual lines one at a time) — same convention as a Finder or Mail
  list. Copy them either with the **Copy N Lines** button that appears in
  the status bar once anything's selected (**Clear Selection** next to it
  drops the selection without copying), or by **right-clicking** any
  selected line and choosing **Copy** — right-clicking a line that isn't
  part of the current selection copies just that one line instead.
  Whatever you copy pastes as plain text, one entry per line, just like
  the original log.
- This is the one tab that resizes with the window — make the window
  bigger or full-screen it for more room to read long log lines. Switching
  to another report tab and back preserves everything here (category/
  filters, results, and any pinned moment/companion file).
- The query bar (Category, Filters, Levels, Timeframe, Run, and — once you
  have results — Show Query/Export/Open File Alongside) drops onto a second
  row as a whole once the window is too narrow to fit all of it on one
  line, rather than shrinking or scrolling piece by piece, so nothing gets
  cut off at the edge.

**Cmd+F** filters the loaded and unloaded log lines together and highlights matches.

## Files tab

> [screenshot: screenshots/files-tab.png]

Quick access to every notable file DeviceDiag recognizes in the archive,
grouped into cards (OS & Software, Device & Hardware, MDM & Management,
Storage & Security, Logs & Diagnostics, Networking, Processes &
Performance). Only groups with at least one file actually present in the
archive show up. The Networking group is the file set the Networking tab's
report is built from — shown as two folder rows, **network-info** and
**WiFi** (the two folders those files all actually live in), each of which
opens straight to that folder in Finder rather than listing every file
inside it one row at a time.

Cards are laid out in two columns, balanced by each card's actual size
rather than paired purely by position — a card with a lot of files in it
no longer stretches whatever happens to land next to it and leaves a gap
above the next card in that same column.

- Click **Open** on a file to view it. Text-ish files (`.txt`, `.log`,
  `.plist`, `.json`, `.csv`) open in a fast built-in viewer rather than
  whatever app macOS has registered as the default handler — plists are
  automatically pretty-printed. Anything else (directories, the
  `.logarchive` bundle, unrecognized extensions) opens in its normal macOS
  app via Finder/NSWorkspace instead (the `.logarchive` opens in
  Console.app).
- Entries that represent more than one underlying file (like the launchd
  state dumps) show a folder icon and an **Reveal (N)** button instead of
  Open — clicking it selects all of them together in one Finder window.

**Cmd+F** filters files across every card by name or description.

### In-app file viewer

> [screenshot: screenshots/file-viewer.png]

Opened from the Files tab for text-ish files. Shows the file's contents in
a fast, monospaced, line-numbered-feeling view (capped at 4000 lines, with
a note if the file was truncated). **Reveal in Finder** jumps to the
original file; **Done** closes the viewer.

Unlike every other tab, **Cmd+F** here doesn't filter the file down to
matching lines — it jumps between matches instead (first match, then next/
previous via the chevron buttons or Enter), so you see each hit in its
surrounding context rather than losing the rest of the file. The current
match's line is tinted orange; every match on screen is highlighted yellow.

## Log Stream window

> [screenshot: screenshots/log-stream.png]

Opened by clicking **Open** on a Status Key Path row in the Declarations
tab. Shows the last 24 hours of raw unified-log activity for that specific
MDM status key path, newest first, with Fault rows tinted red, Error rows
tinted orange, and Debug rows tinted blue (the unified log has no separate
"warning" level, despite the term showing up informally elsewhere — see the
Troubleshooting tab's own Levels selector). Click an entry to pin it as a
moment in time, then
use **Open File Alongside…** to open another sysdiagnose file in a split
pane, scrolled to whichever of its own lines is closest to that same
moment — the same feature as the Troubleshooting tab's companion pane.
**Cmd+F** filters by message or process; press Return or click **Done** to
close the window.

## Notes tab

> [screenshot: screenshots/notes-tab.png]

Only shows up if something came up worth flagging while parsing the
archive — missing expected files, a file that couldn't be parsed, etc. A
simple bulleted list; **Cmd+F** filters it like any other tab.

## Diagnostics Log

Separate from the sysdiagnose data itself — a log of what DeviceDiag *is
doing*, kept around for when something intermittently hangs or comes back
thinner than expected on a large archive (a `log show` query timing out,
a slow/failed `tar` extraction, etc.).

Choose **Help ▸ Reveal Diagnostics Log** (or the button on the Help
window's own "Diagnostics Log" page) to open it in Finder. It's a plain
text file at `~/Library/Logs/DeviceDiag/DeviceDiag.log`, and every entry
also mirrors to the unified log under the `com.devicediag.app` subsystem
if you'd rather filter it live in Console.app while reproducing something.
