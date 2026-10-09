# DeviceDiag — Support Team Guide

DeviceDiag analyzes Apple sysdiagnose archives (macOS and iOS/iPadOS) and turns
them into a structured, readable report: device identity, MDM declarative
management state, installed configuration profiles, iOS settings attribution,
predefined unified-log troubleshooting queries, and quick access to the most
useful files in the archive. It's a native macOS rewrite of the original
Sysdiagnose Analyzer web tool, with the same parsing logic.

## Using it

1. Open a sysdiagnose the easy way: double-click the `.tar.gz`/`.tgz`
   archive in Finder (if DeviceDiag is set as its default app), or
   right-click it and choose **Open With ▸ DeviceDiag**. Both launch
   DeviceDiag (or bring it forward if it's already running) and start
   analyzing immediately — no need to open the app first. Selecting several
   archives at once and opening them together opens one tab per archive.
2. Otherwise: drag the archive or an already-extracted sysdiagnose folder
   onto the drop zone, click it to choose a file/folder, or type a path
   directly and press Return / click Analyze.
3. Wait for parsing (log archive parsing can take 30–60 seconds on large
   archives).
4. Work through the tabs: Device, Declarations, Config Profiles,
   Networking, Settings (iOS only), Troubleshooting, Files, Notes.

If DeviceDiag doesn't show up in "Open With" right after installing it,
open any sysdiagnose archive's Get Info panel, set DeviceDiag under "Open
with", and click "Change All…" — that registers it with macOS immediately
instead of waiting for the next automatic scan.

Full in-app documentation is available any time from **Help ▸ DeviceDiag
Help** (⌘?) — a page-by-page tour that opens in its own window and can
stay open alongside a report.

### Working with more than one sysdiagnose at once

Opening a second sysdiagnose (by any method above) adds a sidebar on the
left listing every open one — click a row to switch to it, hover and click
the **×** to close it, or drag another file/folder directly onto the
sidebar to add one. Opening the exact same file that's already open
switches to that tab instead of duplicating it. The button at the bottom of
the sidebar collapses it to icon-only to save space; **Sync Tabs**, next to
it, keeps every sysdiagnose on the same report section when you switch
between them (e.g. everyone stays on Config Profiles), and can be turned
off if you'd rather each one always open to Device.

### Keyboard shortcuts

| Shortcut | Where | What it does |
|---|---|---|
| **⌘F** | Any tab, and the Log Stream sheet | Opens a find bar and highlights matches within that tab — in Config Profiles this also searches inside payload values and auto-expands any collapsed payload that matches. |
| **⌘R** | Upload screen | Clears the current path/error so you can immediately try a different file after dragging in the wrong one. |
| **⌘N** | Anywhere | Opens another sysdiagnose in a new sidebar tab, without touching whatever's already open. |
| **⌘?** | Anywhere | Opens the in-app Help window. |

### Status Key Paths sync indicator

The green check / red X in Declarations → Status Key Paths reflects whether
that key path still needs to sync to the MDM server (red = needs sync,
green = already synced). Hover the icon to see the raw parsed value behind
it if something looks off.

### FileVault card (Device tab)

Shown beside the Device Information table when the archive has `psm`
(Password Slot Manager) output — enabled/disabled status, every enrolled
unlock method (local users, personal/institutional recovery key, MDM
bootstrap token), and a warning line for a missing bootstrap token on an
MDM-managed Mac, no recovery key at all, or an admin account that can't
unlock the disk at boot. A credential whose failed-unlock-attempt count has
crossed half its max-unlock-attempts shows up in its own "Unlock attempts"
section — useful for a user who says FileVault "just won't unlock" anymore.

### Networking tab

Only shows up when the archive has network-info/Wi-Fi files. A findings
summary (🔴/🟡/🟢/ℹ️, worst first) plus the full detail behind it — interface
errors/drops, TCP retransmit stats, routing, DNS, proxy config, Wi-Fi
signal (with a computed SNR), a Historical Wi-Fi Events table decoded from
the device's own Wi-Fi debug capture log (when one's present — it covers
auth/deauth/reassociation failures going back days, further than a single
sysdiagnose), and the ping/DNS/curl connectivity probes macOS runs during
every sysdiagnose capture. The exact files it's built from are also
individually browsable under Files ▸ Networking.

### Log stream

Click **Open** next to a Status Key Path (when a log archive is available in
the sysdiagnose) to see the actual log lines for that key path, in a
separate sheet with its own find bar. Click any entry there — or any result
line in the Troubleshooting tab — to pin it as a moment in time, then use
**Open File Alongside…** to open another file from the sysdiagnose in a
split pane, scrolled to whichever of its own lines is closest to that same
moment. Useful for correlating an error at a specific time with what else
was happening in, say, `install.log` at that exact moment.

### Diagnostics log

DeviceDiag keeps its own log of what it's doing — separate from the
sysdiagnose data being analyzed — so an intermittent hang or a report that
comes back thinner than expected on a large sysdiagnose has something to
point to afterward. Choose **Help ▸ Reveal Diagnostics Log** to open it in
Finder; it lives at `~/Library/Logs/DeviceDiag/DeviceDiag.log` (plain text,
capped at 5 MB, oldest entries trimmed first) and also mirrors to the
unified log under subsystem `com.devicediag.app` for live viewing in
Console.app. It records: every `tar`/`log show` command run, how long each
took, and whether it succeeded, timed out, or failed; each analysis's start/
finish and elapsed time; and any error that surfaced as an error banner.

If someone reports an intermittent snag on a large sysdiagnose, ask them to
grab this file (or just the tail around when it happened) along with the
sysdiagnose filename — it'll usually show directly whether a `log show`
query timed out, `tar` extraction failed, or something else.

## Known differences from the original web tool

- The UI is a native SwiftUI redesign of the same tab structure, not a
  literal port of the HTML — native controls (disclosure groups, save
  panels, sheets) replace the original's dropdowns and `<details>` elements.
- No built-in auto-update yet; new versions come through Jamf Pro like any
  other app update.

## Reporting a problem

If a report looks wrong or the app crashes/hangs, please note:

- The sysdiagnose filename (or attach it, if you can share it) — this is by
  far the most useful thing for reproducing an issue.
- Which tab/field looked wrong, and what you expected instead.
- macOS version and whether the device is Apple Silicon or Intel.
- The diagnostics log (see above) if the issue was a hang, timeout, or
  something silently coming back empty.

Send that to the DeviceDiag maintainer (Zach Propheter) rather than filing
against the original Python tool — they're now two separate codebases.
