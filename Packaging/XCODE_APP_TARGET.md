# Real Xcode App target vs. the build script

You may want an actual `.xcodeproj` App target instead of (or alongside)
`build_app.sh` — mainly to get Xcode's Signing & Capabilities UI and the
Product > Archive / Organizer distribution flow. This doc explains what's
here instead, and why, plus how to create the real one yourself.

## Why there's no hand-written `.xcodeproj` in this repo

An Xcode project file (`project.pbxproj`) is a plist full of cross-referenced
UUIDs — every file reference, group, build phase, target, and package
dependency links to another object by ID, and Xcode is unforgiving about
inconsistencies. This environment has no Xcode to open and verify one
actually parses and builds, so hand-writing one here would mean shipping you
something with a real chance of showing up as "the project ... cannot be
opened because it is damaged" with no way for me to have caught that first.

`build_app.sh` sidesteps the whole problem: `swift build -c release` plus a
few `mkdir`/`cp` commands to assemble `Contents/MacOS`, `Contents/Resources`,
and `Contents/Info.plist` is plain, inspectable shell, and it's a
well-established pattern for shipping pure-SwiftPM macOS apps without an
Xcode project at all. It gets you a real, signable, notarizable, packageable
`.app` — everything the fleet deployment actually needs.

## When you'd still want a real Xcode App target

- You want to manage signing/capabilities through Xcode's UI instead of
  hand-typed `codesign` invocations.
- You want Product > Archive → Organizer → "Distribute App" to drive
  signing + notarization submission for you.
- You plan to add an asset catalog (multiple icon sizes, dark-mode icon
  variants) or other App-target-only project settings.

## Creating one (reliable, ~5 minutes, via Xcode's GUI)

1. **File > New > Project > macOS > App.** Product Name: `DeviceDiag`.
   Interface: SwiftUI. Bundle Identifier: match `Packaging/Info.plist`
   (`com.boaz.devicediag`, or your real one). Uncheck "Include Tests" if you
   don't want them. Save it as its own folder, e.g. `DeviceDiag-Xcode/`.
2. Delete the two files Xcode auto-generates (`DeviceDiagApp.swift`,
   `ContentView.swift`) — this repo's `Sources/DeviceDiag` already has the
   real `@main` entry point and all views.
3. Drag `Sources/DeviceDiag` from this repo into the new project's file
   list. Leave "Copy items if needed" **unchecked** if you want to keep
   editing the single source of truth in this repo (Xcode will reference the
   files in place); check it if you'd rather fork an independent copy.
4. Select the new target > **General** tab: confirm bundle ID, version, and
   minimum deployment target (15.0). Drag an icon set into the
   `Assets.xcassets` AppIcon slot if you have one.
5. **Signing & Capabilities** tab: pick your Team, confirm the Developer ID
   Application cert (or "Automatically manage signing"), and confirm **App
   Sandbox is off** — required, since the app shells out to `/usr/bin/tar`,
   `/usr/bin/log`, and `/usr/bin/plutil` via `Process`, which App Sandbox
   blocks.
6. **Product > Archive**, then **Distribute App > Developer ID** (or Direct
   Distribution) to sign, notarize, and export in one flow.

Either path — this script or a real Xcode project — produces the same kind
of signed, notarizable `.app`. Pick whichever you'd rather maintain
long-term; they're not mutually exclusive if you want the script for CI and
a project for local Xcode convenience.
