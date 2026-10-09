# DeviceDiag

A native macOS app for analyzing Apple sysdiagnose archives (macOS and iOS/iPadOS).

Drop in a `.tar.gz` sysdiagnose archive or an already-extracted folder and get a
structured report: device identity, MDM declarative-management state, installed
configuration profiles, iOS settings attribution, predefined unified-log
troubleshooting queries, and quick access to the most useful files in the archive.

## Requirements

- macOS 15 (Sequoia) or later
- Xcode 16 or later
- No third-party dependencies — pure SwiftUI + Foundation + AppKit

## Opening the project

This is a Swift Package (not a `.xcodeproj`), which Xcode opens and runs natively:

```bash
open "Package.swift"
```

Xcode will resolve the package, create a `DeviceDiag` scheme automatically, and you
can hit **Run** (⌘R) to launch the app.

## Documentation

- **`USER_GUIDE.md`** — a page-by-page tour of the app: what's on each tab,
  where to find things, what's clickable.
- **`ARCHITECTURE.md`** — the technical reference: data flow, what each
  file does, the data model, and the design decisions that aren't obvious
  from the code alone. Read this first if you're picking the project back
  up after time away, or rebuilding a piece of it from scratch.
- **`SUPPORT_GUIDE.md`** — end-user-facing documentation for support staff
  using the built app.
- **`JLG_COMPARISON.md`** — a comparison of what Jamf Log Grabber collects
  against what's actually available in a sysdiagnose, with notes on what
  could still be ported into DeviceDiag.

## What it does

Every parser handles a specific slice of a sysdiagnose archive — device
identity, MDM declarations, configuration profiles, network health,
settings attribution, predefined unified-log queries, and file inventory —
see `ARCHITECTURE.md` for the full breakdown. The UI is a tabbed report
(Device → Declarations → Config Profiles → Networking → Settings [iOS] →
Troubleshooting → Files → Notes) built entirely from native SwiftUI
controls: pickers, disclosure groups, save panels, drag-and-drop.

## Status

Builds and runs. It's been through several rounds of real-device testing and
bug fixes: a `Process`/`Pipe` deadlock that caused hangs on large log
archives, a Status Key Paths sync-status display inversion (verified against
a real uploaded sysdiagnose), clickable log streams, Cmd+F search in
Troubleshooting/Config Profiles/Log Stream, and Cmd+R (reset the upload
form)/Cmd+N (open another sysdiagnose in a new tab) shortcuts. More recent
additions: a collapsible sidebar for working with several open sysdiagnoses
at once (with drag-and-drop, multi-file drop, dedup, and a "Sync Tabs"
option), a "open another file at this same moment" companion pane in the
Troubleshooting tab and Log Stream window, and an in-app Help window (⌘?).
See `SUPPORT_GUIDE.md` for end-user documentation.

## Deploying to a fleet

This is still a plain SwiftPM package (no `.xcodeproj`), which is fine for
development in Xcode but not for distribution. `Packaging/` has what you
need to turn it into a real, signable, notarizable, `.pkg`-installable app
for Jamf Pro — `build_app.sh` for a signed release build,
`build_unsigned_installer.sh` for a quick unsigned build to hand another
developer for testing. See `ARCHITECTURE.md`'s Packaging section for what
each script does and why the entitlements file is intentionally empty.

Still open: your actual Developer ID signing identity, and a decision on
update cadence (there's no in-app auto-updater — new versions go out as new
Jamf Pro package pushes).

Also worth knowing: `Packaging/Info.plist` registers DeviceDiag as an
"Open With" option for `.tar.gz`/`.tgz` files in Finder, so a built copy can
open sysdiagnose archives via double-click or Dock drop, not just
drag-and-drop into the app. This only takes effect in a *built* `.app`, not
`swift run`/Xcode's debug launch.
