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
   analyzing immediately — no need to open the app first.
2. Otherwise: drag the archive or an already-extracted sysdiagnose folder
   onto the drop zone, click it to choose a file/folder, or type a path
   directly and press Return / click Analyze.
3. Wait for parsing (log archive parsing can take 30–60 seconds on large
   archives).
4. Work through the tabs: Device, Declarations, Config Profiles, Settings
   (iOS only), Troubleshooting, Files, Notes.

If DeviceDiag doesn't show up in "Open With" right after installing it,
open any sysdiagnose archive's Get Info panel, set DeviceDiag under "Open
with", and click "Change All…" — that registers it with macOS immediately
instead of waiting for the next automatic scan.

### Keyboard shortcuts

| Shortcut | Where | What it does |
|---|---|---|
| **⌘F** | Any tab, and the Log Stream sheet | Opens a find bar and highlights matches within that tab — in Config Profiles this also searches inside payload values and auto-expands any collapsed payload that matches. |
| **⌘R** | Upload screen | Clears the current path/error so you can immediately try a different file after dragging in the wrong one. |
| **⌘N** | Anywhere once a report is loaded | Starts over — discards the current report and returns to the upload screen. |

### Status Key Paths sync indicator

The green check / red X in Declarations → Status Key Paths reflects whether
that key path still needs to sync to the MDM server (red = needs sync,
green = already synced). Hover the icon to see the raw parsed value behind
it if something looks off.

### Log stream

Click **Open** next to a Status Key Path (when a log archive is available in
the sysdiagnose) to see the actual log lines for that key path, in a
separate sheet with its own find bar.


## Reporting a problem

If a report looks wrong or the app crashes/hangs, please note:

- The sysdiagnose filename (or attach it, if you can share it) — this is by
  far the most useful thing for reproducing an issue.
- Which tab/field looked wrong, and what you expected instead.
- macOS version and whether the device is Apple Silicon or Intel (Intel is not supported).

