# DeviceDiag — Technical Architecture

This is how data flows through the app, what each file is responsible for, and the design decisions that aren't
obvious just from reading the code. For a page-by-page tour of the UI, see
`USER_GUIDE.md`. For setup/build instructions, see `README.md`.

## Project layout

```
Package.swift                     — SwiftPM manifest (swift-tools 6.0, macOS 15+, Swift 5 language mode)
Sources/DeviceDiag/
  DeviceDiagApp.swift              — @main entry point, AppDelegate, window, Cmd+N
  AppState.swift                   — the only app-level state: result / isAnalyzing / errorMessage
  Models/
    AnalysisModels.swift           — every data structure the app passes around
  Parsing/
    PlistValue.swift               — dynamically-typed plist tree all parsers normalize into
    AsciiPlistParser.swift         — hand-written parser for Apple's ASCII/NeXTSTEP plist format
    FileLocating.swift             — root discovery, recursive file search, plist loading helpers
    DeviceInfoParser.swift         — macOS device identity + shared regex helpers
    StaticStatusValuesParser.swift — best-effort MDM status key-path values from static files
    DeclarationsParser.swift       — rmd_inspect_system.txt → Blueprint/DDM declaration state
    ConfigProfilesParser.swift     — macOS SPConfigurationProfileDataType.spx + managed-settings extraction
    MobileParsers.swift            — iOS/iPadOS device, enrollment, managed apps, profiles, platform detection
    SettingsAttributionParser.swift — iOS restriction-key attribution (profile/DDM/default)
    FileInventory.swift            — static per-platform file catalog + presence check for the Files tab
    MarketingNames.swift           — OS version → marketing name lookup tables
  Services/
    AnalysisEngine.swift           — orchestrates extraction + every parser into an AnalysisResult
    LogArchiveService.swift        — wraps `/usr/bin/log show`; predefined Troubleshooting catalog
    FileOpener.swift               — NSWorkspace open/reveal + NSSavePanel log export
    FileTextLoader.swift           — fast in-app text loader for the Files tab viewer
  Views/
    UploadView.swift, ResultsView.swift, DeviceTabView.swift,
    DeclarationsTabView.swift, ConfigProfilesTabView.swift,
    SettingsAttributionTabView.swift, TroubleshootingTabView.swift,
    FilesTabView.swift, NotesTabView.swift, LogStreamView.swift,
    FileViewerView.swift, FindSupport.swift
Packaging/                        — Info.plist, entitlements, build scripts, icon
```

## Data flow: drop a file → see a report

1. **Launch.** `DeviceDiagApp` (`@main`) installs an `AppDelegate` via
   `@NSApplicationDelegateAdaptor` to catch files macOS hands the app
   directly (double-click, "Open With," Dock drop), creates an `AppState`
   as a `@StateObject`, and shows `RootView`, which is just:
   `if let result = appState.result { ResultsView(result: result) } else { UploadView() }`.

2. **Getting a path into the pipeline.** Three entry points all converge on
   the same call:
   - `UploadView`: drag-and-drop, an `NSOpenPanel`, or a typed path — all call `appState.analyze(path:)`.
   - File-open events: `AppDelegate.application(_:open:)` sets `openedFilePath`; `DeviceDiagApp`'s `.onAppear`/`.onChange` call `appState.startOver()` then `appState.analyze(path:)`. (Both hooks exist because `.onChange` alone misses a cold launch — the delegate can fire before SwiftUI subscribes to the `@Published` value.)
   - Cmd+N (app-level menu command, wired to `appState.startOver()`, works whether or not a report is currently showing).

3. **`AppState.analyze(path:)`** (`@MainActor`) validates the path, calls
   `AnalysisEngine.cleanup(result)` to delete any previous temp directories,
   sets `isAnalyzing = true`, and runs `AnalysisEngine.analyze(inputPath:)`
   inside `Task.detached(priority: .userInitiated)` — off the main actor, so
   a large `log show` or `tar` extraction doesn't freeze the UI — then hops
   back with `await MainActor.run` to set `result` or `errorMessage`.

4. **`AnalysisEngine.analyze(inputPath:)`** is the whole pipeline:
   - Expand `~`, confirm the path exists (`AnalysisError.pathNotFound` otherwise).
   - If it's a `.tar.gz`/`.tgz` (regex `\.tar\d*\.gz$|\.tgz$`), extract via `/usr/bin/tar xzf` into a temp dir (`devicediag_<UUID>` under the system temp directory), draining stderr on a background queue concurrently with the process so a large archive can't fill the pipe buffer and deadlock. Non-zero exit → `AnalysisError.extractionFailed`. The temp dir is tracked so it can be deleted later.
   - `FileLocating.findSysdiagnoseRoot` descends into the single sysdiagnose-named subfolder if the extracted/given directory has exactly one.
   - `FileLocating.findLogarchive` locates the `.logarchive` bundle.
   - `PlatformDetector.isMobile(root:)` decides macOS vs iOS/iPadOS.
   - `FileInventory.gather(root:isMobile:)` builds the Files tab's data.
   - `DeclarationsParser.parse(root:logArchive:)` always runs (shared across platforms).
   - Branches on platform: macOS runs `DeviceInfoParser`, `ConfigProfilesParser`, `ManagedSettingsExtractor`; mobile runs `MobileDeviceInfoParser`, `MobileEnrollmentParser`, `MobileManagedAppsParser`, `MobileProfilesParser`, `SettingsAttributionParser`.
   - Assembles an `AnalysisResult`, including `notes: [String]` — warnings accumulated along the way for missing files or parse failures (these surface as the Notes tab).

5. **Rendering.** Setting `appState.result` flips `RootView` to `ResultsView(result:)`. `ResultsView.availableTabs` filters the fixed tab order (Device → Declarations → Config Profiles → Settings [mobile only] → Troubleshooting → Files → Notes) down to whichever sub-results actually have data, and `contentView`'s `switch selectedTab` instantiates the matching tab view with just the slice of `AnalysisResult` it needs.

## Parsing layer

Every parser is a stateless `enum` with one `static func parse(...)` — no
shared parser state, no classes. They all normalize whatever they read
(binary/XML plist, ASCII/NeXTSTEP plist, or JSON) into one of two things:
the shared `PlistValue` tree, or a typed struct from `AnalysisModels.swift`.

| File | Purpose | Reads |
|---|---|---|
| `PlistValue.swift` | Shared dynamically-typed plist tree (`indirect enum`, cases `.string/.int/.bool/.double/.date/.data/.dict/.array/.null`) with typed accessors, a `subscript(key:)`, `stringified`, and two truthiness checks (`isTruthyActive` strict, `isLenientlyTruthy` lenient) for normalizing how MDM state gets treated as "active" across inconsistent plist encodings (string `"1"` vs. integer `1`, etc.). `PlistValue.from(any:)` bridges `PropertyListSerialization`'s `Any` output into this tree. | N/A — pure data model |
| `AsciiPlistParser.swift` | Recursive-descent parser for Apple's legacy ASCII/NeXTSTEP plist syntax (`{ key = val; }`, `(a, b)`, quoted/bare tokens, `//` and `/* */` comments) — needed because `PropertyListSerialization` can't parse this format, and several sysdiagnose files use it. Coerces bare `"1"`/`"0"` to `PlistValue.int` specifically to preserve truthy checks. | Any string handed to it |
| `FileLocating.swift` | Shared filesystem helpers every other parser depends on: sysdiagnose root detection, recursive filename search (exact, prefix, "prefer path containing X"), and plist loading — binary/XML via `PropertyListSerialization`, ASCII via `AsciiPlistParser`, with a `plutil`-then-ASCII-fallback path for `rmd_inspect_system.txt`. | Generic |
| `DeviceInfoParser.swift` | macOS device identity, plus the shared `regexFirstMatch`/`regexAllMatches` helpers used across parsers. | `sw_vers.txt`, `hardware_overview.txt`/`SPHardwareDataType.txt`, `hostname.txt`, `IODeviceTree.txt` |
| `StaticStatusValuesParser.swift` | Best-effort MDM status key-path values (suffixed `" *"`) purely from static files, as a fallback when the logarchive doesn't have a fresher value. | `sw_vers.txt`, `IODeviceTree.txt`, `remotectl_dumpstate.txt`, `SPHardwareDataType.spx`, `disks.txt`, `install.log` |
| `DeclarationsParser.swift` | Parses DDM state: groups activation/configuration declarations by Blueprint UUID (regex `Blueprint_([0-9a-fA-F-]{36})_`), collects standalone (non-blueprint) declarations, subscribed status key paths, and conduit/sync metadata. Cross-references the logarchive to fill in `StatusItem.lastValue`. | `rmd_inspect_system.txt` |
| `ConfigProfilesParser.swift` | Normalizes macOS configuration profiles into `ConfigProfileEntry`/`ConfigProfilePayload`. Also hosts `ManagedSettingsExtractor`, which scans payloads for three specific managed-settings domains (`com.apple.notificationsettings`, `com.apple.TCC.configuration-profile-policy`, `com.apple.servicemanagement`). | `SPConfigurationProfileDataType.spx` |
| `MobileParsers.swift` | iOS/iPadOS equivalent, bundled: `PlatformDetector.isMobile`, `MobileDeviceInfoParser`, `MobileEnrollmentParser`, `MobileManagedAppsParser`, `MobileProfilesParser` (profiles live as loose `profile-*.stub` files rather than one `.spx`). | `SystemVersion.plist`, `remotectl_dumpstate.txt`, `IODeviceTree.txt`, `CloudConfigurationDetails.plist`, `MDM.plist`, `MDMAppManagement.plist`, `PayloadManifest.plist` + `profile-*.stub` |
| `SettingsAttributionParser.swift` | iOS-only: attributes each managed `restrictedBool` key to a profile, a DDM declaration, or an implicit device default, using `MCSettingsEvents.plist` timestamps and profile stub contents to disambiguate. | `UserSettings.plist`, `MCSettingsEvents.plist`, `profile-*.stub` |
| `FileInventory.swift` | Static per-platform catalog (`macOSGroups`/`iosGroups`) of known sysdiagnose files grouped by category, checked for presence in the given archive. Wildcard entries (`"launchctl-*"`) collapse multiple matching files into one "collection" row with `groupedPaths`. | Checks presence of every cataloged filename |
| `MarketingNames.swift` | Static OS-version → marketing-name tables (macOS, and iOS/iPadOS by device class). | N/A |

## Services layer

| File | Purpose |
|---|---|
| `AnalysisEngine.swift` | The orchestrator described above; also defines `AnalysisError` (`.pathNotFound`, `.extractionFailed`, `.processingError`). |
| `LogArchiveService.swift` | All `/usr/bin/log` interaction. `TroubleshootCatalog` is the static predicate catalog behind the Troubleshooting tab's category/topic pickers. `LogArchiveService.runLog` drains stdout/stderr on a background queue with a `DispatchSemaphore` while the process runs, to avoid the same pipe-deadlock risk as `tar` extraction. Exposes `readLogarchive`, `readStatusItemLogs`, `parseSoftwareUpdateStatusValues`, `runTroubleshootQuery`, `readLogStream`. |
| `FileOpener.swift` | `FileOpener.open`/`revealMultiple` wrap `NSWorkspace` (open one file in its default app, or reveal several pre-selected together in one Finder window — used for grouped launchd dumps). `LogExportService.export` shows an `NSSavePanel` and writes exported log lines to disk. |
| `FileTextLoader.swift` | Fast, dependency-free text loader for the Files tab's in-app viewer. Caps rendered lines at 4000; pretty-prints `.plist` as XML via `PropertyListSerialization`. Returns `Result<Loaded, LoadError>` (a wrapper type, since plain `String` doesn't conform to `Error`). |

## Data model (`AnalysisModels.swift`)

Everything is a plain `struct`; anything shown in a `List`/`ForEach` conforms
to `Identifiable` via `let id = UUID()`.

- **macOS**: `DeviceInfo` (serial, OS version, build, model, hostname), `ManagedSettings` (managed notifications/PPPC/login items).
- **Config profiles (shared)**: `ConfigProfilePayload`, `ConfigProfileEntry` (name, org, source, install date, removal-disallowed, verified, identifier, uuid, description, payloads), `ConfigProfilesResult` (found/error/profiles).
- **MDM declarations**: `DeclarationStatusGroup` (ok/count/active/valid/reasons), `BlueprintDeclaration` (uuid, actType, cfgType, activation/config groups), `StandaloneDeclaration` (section, identifier, type, load state, active count), `StatusItem` (keyPath, needsSync, lastReceivedDate, lastValue, rawNeedsSyncDebug for tooltip debugging), `ConduitInfo` (last received/processed, consecutive errors), `DeclarationsResult` (found/error/blueprints/standalone/conduit/statusItems).
- **Mobile**: `MobileDeviceInfo`, `MobileEnrollmentInfo`, `ManagedApp` (bundleID/state/flags/removable).
- **Settings attribution (iOS only)**: `SettingsAttributionEntry` (key, value, source: profile/declaration/default, profile name, implicit flag, timestamp), `SettingsAttributionResult` (found/error/counts/entries).
- **Files**: `SysdiagFileEntry` (name, description, path, found, groupedPaths for collection entries), `SysdiagFileGroup` (group name + files).
- **Troubleshooting**: `LogTopicDefinition` (extra args, predicate), `LogEntry` (timestamp, process, subsystem, message, level).
- **Top-level `AnalysisResult`**: name, analyzedAt, isMobile; the macOS block; the mobile block; shared fields (`sysdiagFiles`, `declarations`, `configProfiles`, `logArchivePath`, `notes`); plus `rootURL` and `tempDirectories` (deleted on the next analysis or `startOver()`).

## App state (`AppState.swift`)

`@MainActor final class AppState: ObservableObject` has exactly three
`@Published` properties — `result: AnalysisResult?`, `isAnalyzing: Bool`,
`errorMessage: String?` — and no explicit state-machine enum. Navigation is
derived purely from whether `result` is nil, and everything (the current
report, any pending temp directories) is held in memory for the life of the
process — there's no persistence between launches by design.

## App wiring (`DeviceDiagApp.swift`)

`AppDelegate` implements `application(_:open:)` for file-open events (if
macOS hands multiple URLs at once, only the last is kept — opening a
sysdiagnose is inherently a single-file operation). The `WindowGroup` is
sized `minWidth: 980, minHeight: 680` with `.windowResizability(.contentSize)`.
The only app-level menu command is Cmd+N (`CommandGroup(replacing: .newItem)`),
wired directly to `appState.startOver()`. Cmd+R (reset the upload form) and
Cmd+F (per-tab find) are both registered locally inside the relevant views,
not here.

## Notable patterns (read these before touching the code)

- **Custom ASCII plist parser.** Some sysdiagnose files (`rmd_inspect_system.txt`,
  embedded profile payload text) use Apple's legacy NeXTSTEP plist syntax,
  which `PropertyListSerialization` rejects outright. `AsciiPlistParser` is a
  from-scratch recursive-descent parser for it — this is the single most
  "don't reinvent this" piece of the app if porting elsewhere.
- **One dynamic plist model for everything.** `PlistValue` is deliberately
  the *only* shape parser code deals with, regardless of whether the source
  was XML/binary plist, ASCII plist, or JSON — this is what lets parser code
  stay format-agnostic.
- **Cmd+F is environment-key-based, not prop-drilled.** `FindSupport.swift`
  defines a custom `EnvironmentKey` (`findQuery`) so leaf views can call
  `HighlightedText(text:query:)` without every intermediate view threading a
  query string through its initializer. `FindShortcut` is a zero-opacity
  button that exists purely to register the hidden Cmd+F shortcut per tab.
- **Search is always debounced via `.task(id:)`.** Every tab keeps a raw
  `findText` and a `committedFindText` synced through
  `.task(id: findText) { try? await Task.sleep(...); committedFindText = findText }`
  — 150ms on most tabs, 200ms on Config Profiles (which rescans full payload
  text and auto-expands matches, so it's more expensive per keystroke). This
  is what fixed the original "Cmd+F feels slow" bug — cancel-and-restart is
  automatic because `.task(id:)` restarts whenever `id` changes.
- **The Files tab's file viewer intentionally jumps rather than filters.**
  Every other tab's Cmd+F filters content down to matching rows. The
  in-file viewer (`FileViewerView`) instead highlights every match and
  jumps between them (first match → next → previous), because collapsing a
  raw file down to only matching lines throws away the surrounding context
  that's usually the point of opening the file.
- **`Process`/`Pipe` deadlock avoidance, twice.** Both `tar` extraction
  (`AnalysisEngine`) and `log show` (`LogArchiveService.runLog`) explicitly
  drain stdout/stderr on a background queue *while the process runs*,
  because macOS pipes have a small kernel buffer (~64KB) and a naive
  "wait then read" pattern hangs forever once a large-output child process
  fills it. Any new `Process`-based feature needs the same treatment.
- **Row views are pulled out as standalone `struct: View`s**, not inline
  `ForEach` closures, specifically to keep each row's type concrete —
  inline multi-statement closures inside `ForEach` can make the type
  checker slow or ambiguous.
- **The in-app file viewer exists because `NSWorkspace.shared.open` isn't
  reliable for this use case** — a cold Xcode launch to view a `.plist`, or
  a heavy editor choking on a multi-megabyte `.txt` dump, is what made
  "Open" feel hung. `FileTextLoader` + `FileViewerView` read and render the
  file directly instead, capped at 4000 lines, reusing the same
  `LazyVStack`-of-lines pattern already proven fast for Troubleshooting
  output.
- **Text selection is one modifier, not per-`Text`.** `.textSelection(.enabled)`
  applied once at `ResultsView`'s root cascades to every descendant `Text`,
  which is why copy/paste works everywhere without auditing every view.
- **Grouped file entries reveal, they don't copy.** `SysdiagFileEntry.groupedPaths`
  plus `FileOpener.revealMultiple` let one row (e.g. "Launchd Files")
  represent several underlying files and select them all together in one
  Finder window via `NSWorkspace.shared.activateFileViewerSelecting`, rather
  than physically copying files into a synthesized folder (which would need
  its own temp-dir cleanup tracking).

## Packaging

- **`Package.swift`**: SwiftPM manifest, `swift-tools-version: 6.0`, `.macOS(.v15)`, one executable target, Swift 5 language mode.
- **`Packaging/Info.plist`**: bundle ID `com.boaz.devicediag`, version `1.0`/build `1`, min OS `15.0`, category Utilities, icon `AppIcon.icns`. Declares `CFBundleDocumentTypes` for `.tar.gz`/`.tgz` at `LSHandlerRank: Alternate` (offers DeviceDiag in "Open With" without stealing the system default tar/gzip handler) — this exists because `AnalysisEngine` only extracts `.tar.gz`/`.tgz`, never `.zip`.
- **`Packaging/DeviceDiag.entitlements`**: intentionally an empty `<dict>`. The app cannot be sandboxed — it shells out to `tar`, `log`, and `plutil` via `Process`, which App Sandbox blocks. Hardened Runtime is enabled at sign time instead (`codesign --options runtime`), not via this file.
- **`Packaging/build_app.sh`**: the real distribution path. Builds arm64-only release (`swift build -c release`; multi-arch needs Xcode's XCBuild backend, which isn't reliably available outside Xcode itself), assembles `dist/DeviceDiag.app`, and prints — but does not run — the signing/notarization/pkg commands (`codesign` with a Developer ID identity and `--options runtime`, `notarytool submit --wait`, `stapler staple`, `pkgbuild --sign` for a signed installer). Use this for anything that goes out via Jamf Pro.
- **`Packaging/build_unsigned_installer.sh`**: internal-testing-only path. Same build, but ad-hoc signs (`codesign --sign -`, no cert — required just to launch on Apple Silicon, does not satisfy Gatekeeper) and produces an unsigned `.pkg`, with tester instructions for bypassing Gatekeeper's first-launch block. Don't use this path for anything beyond handing a build to another developer to try.

Run either script as your normal user — neither `swift build`, ad-hoc
`codesign -s -`, nor unsigned `pkgbuild` needs root, and running with `sudo`
risks leaving root-owned files in `dist/` that cause permission errors on
later (non-sudo) rebuilds.

## If you're starting over from scratch

Build in roughly this order, since later layers depend on earlier ones:

1. `PlistValue` + `AsciiPlistParser` + `FileLocating` — nothing else can be written until these exist.
2. `AnalysisModels.swift` — get the data shapes right before writing parsers against them.
3. One parser at a time, verified against a real sysdiagnose archive rather than assumptions about its contents (extract one, grep for the exact paths/keys a parser expects, confirm the format matches before trusting the output).
4. `AnalysisEngine` to wire the parsers together, then `AppState` to drive it from the UI.
5. `UploadView`/`ResultsView` shell, then one tab view at a time — build `FindSupport.swift` (the Cmd+F infrastructure) before or alongside the first tab that needs it, since every subsequent tab reuses it verbatim.
6. Packaging last, once the app itself is stable.
