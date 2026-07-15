#  <img src="https://i.imgur.com/nxHBsAE.png" width="50" height="50" /> DeviceDiag
 
A native macOS app for analyzing Apple sysdiagnose archives (macOS and iOS/iPadOS).

Drop in a `.tar.gz` sysdiagnose archive or an already-extracted folder and get a
structured report: device identity, MDM declarative-management state, installed
configuration profiles, iOS settings attribution, predefined unified-log
troubleshooting queries, and quick access to the most useful files in the archive.

## Requirements

- macOS 15 (Sequoia) or later
- Xcode 16 or later
- No third-party dependencies — pure SwiftUI + Foundation + AppKit

## Installing
Run the installer .pkg file and when prompted by Gatekeeper, allow the app to run. Signing coming soon.

## Documentation

- **`USER_GUIDE.md`** — a page-by-page tour of the app: what's on each tab,
  where to find things, what's clickable.
- **`SUPPORT_GUIDE.md`** — end-user-facing documentation for support staff
  using the built app.
- **`ARCHITECTURE.md`** — the technical reference: data flow, what each
  file does, the data model, and the design decisions that aren't obvious
  from the code alone.

## What it does

Every parser handles a specific slice of a sysdiagnose archive — device
identity, MDM declarations, configuration profiles, settings attribution,
predefined unified-log queries, and file inventory — see `ARCHITECTURE.md`
for the full breakdown. The UI is a tabbed report (Device → Declarations →
Config Profiles → Settings [iOS] → Troubleshooting → Files → Notes) built
entirely from native SwiftUI controls: pickers, disclosure groups, save
panels, drag-and-drop.

## Deploying to a fleet

The package is not yet signed as we await a deveoper cert from Apple. Until then, you can use the installer and override Gatekeeper.
