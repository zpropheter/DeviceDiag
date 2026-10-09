# DeviceDiag — Technical Architecture

This is the "rebuild it from scratch" reference: how data flows through the
app, what each file is responsible for, and the design decisions that aren't
obvious just from reading the code. For a page-by-page tour of the UI, see
`USER_GUIDE.md`. For setup/build instructions, see `README.md`.

## Project layout

```
Package.swift                     — SwiftPM manifest (swift-tools 6.0, macOS 15+, Swift 5 language mode)
Sources/DeviceDiag/
  DeviceDiagApp.swift              — @main entry point, AppDelegate, main+help windows, Cmd+N/Cmd+?
  AppState.swift                   — session list + which one's selected + cross-session UI prefs
  Models/
    AnalysisModels.swift           — every data structure the app passes around
  Parsing/
    PlistValue.swift               — dynamically-typed plist tree all parsers normalize into
    AsciiPlistParser.swift         — hand-written parser for Apple's ASCII/NeXTSTEP plist format
    FileLocating.swift             — root discovery, recursive file search, plist loading helpers
    DeviceInfoParser.swift         — macOS device identity + shared regex helpers
    StaticStatusValuesParser.swift — best-effort MDM status key-path values from static files
    DeclarationsParser.swift       — rmd_inspect_system.txt → Blueprint/DDM declaration state
    ConfigProfilesParser.swift     — macOS SPConfigurationProfileDataType.spx (Device/User/Provisioning scope-aware) + managed-settings extraction
    NetworkReportParser.swift      — network health report (port of sysdiag_netcheck.py): interfaces, TCP stats, routing, DNS, proxy, Wi-Fi, connectivity probes, VPN/proxy services (both platforms)
    FileVaultParser.swift          — FileVault/APFS key-slot state from psm_status/list/stderr.txt: enrolled unlock methods, missing-bootstrap-token/no-recovery-key/admin-not-enrolled flags, near-lockout slots
    MobileParsers.swift            — iOS/iPadOS device, enrollment, managed apps, profiles, platform detection
    SettingsAttributionParser.swift — iOS restriction-key attribution (profile/DDM/default)
    FileInventory.swift            — static per-platform file catalog + presence check + shared "viewable candidates" helper
    MarketingNames.swift           — OS version → marketing name lookup tables
  Services/
    AnalysisEngine.swift           — orchestrates extraction + every parser into an AnalysisResult
    LogArchiveService.swift        — wraps `/usr/bin/log show`; predefined Troubleshooting catalog
    FileOpener.swift               — NSWorkspace open/reveal + NSSavePanel log export
    FileTextLoader.swift           — fast in-app text loader for the Files tab viewer (`load`, capped) and companion-file panes (`loadAllLines`, uncapped)
    TimestampLineMatcher.swift     — extracts/parses timestamps from log lines to drive the "open file alongside" companion pane
    DiagnosticsLog.swift           — the app's own persistent log (~/Library/Logs/DeviceDiag/DeviceDiag.log) + mirrored os.Logger output
  Views/
    SessionSidebarView.swift, UploadView.swift, ResultsView.swift, DeviceTabView.swift,
    DeclarationsTabView.swift, ConfigProfilesTabView.swift, NetworkingTabView.swift,
    SettingsAttributionTabView.swift, TroubleshootingTabView.swift,
    FilesTabView.swift, NotesTabView.swift, LogStreamView.swift,
    FileViewerView.swift, FindSupport.swift, HelpView.swift
Packaging/                        — Info.plist, entitlements, build scripts, icon
```

## Data flow: drop a file → see a report

1. **Launch.** `DeviceDiagApp` (`@main`) installs an `AppDelegate` via
   `@NSApplicationDelegateAdaptor` to catch files macOS hands the app
   directly (double-click, "Open With," Dock drop), creates an `AppState`
   as a `@StateObject`, and shows `RootView` inside a singular `Window`
   (not `WindowGroup` — see App wiring below). `RootView` is the sidebar (if
   `appState.shouldShowSidebar`) plus whichever session is selected, showing
   that session's own `UploadView` or `ResultsView`.

2. **Getting a path into the pipeline.** Every entry point ends up calling
   either `AppState.analyze(path:in:)` (analyze into one specific,
   already-existing session) or `AppState.openDropped(paths:primarySessionID:)`
   (open one or more new sessions from a batch of dropped/opened files):
   - `UploadView`: drag-and-drop, an `NSOpenPanel`, or a typed path all call
     `appState.analyze(path:in: sessionID)` for that view's own session;
     multi-file drops go through `openDropped(paths:primarySessionID:)`
     instead, so the first path fills this (still-blank) tab and any extra
     paths each get their own new tab.
   - File-open events (double-click, "Open With," Dock drop):
     `AppDelegate.application(_:open:)` collects every URL macOS hands over
     into `openedFilePaths: [String]`; `DeviceDiagApp`'s `.onAppear`/
     `.onChange` both call `openPendingFilesIfAny()`, which drains that array
     into `appState.openDropped(paths:)` — one new tab per file. (Both hooks
     exist because `.onChange` alone misses a cold launch — the delegate can
     fire before SwiftUI subscribes to the `@Published` value.)
   - Cmd+N / the sidebar's **+** button (`appState.newTab()` — always adds a
     fresh blank tab and selects it, never touches any existing tab).

3. **`AppState.analyze(path:in:)`** (`@MainActor`) looks up the session by
   `id`, validates the path, and — before doing anything else — checks every
   *other* session's `sourcePath` for an exact match; if one exists, it
   switches to that session instead (deleting this one first if it was still
   a pristine, untouched blank tab) rather than running a duplicate analysis.
   Otherwise it calls `AnalysisEngine.cleanup(result)` on this session's own
   previous result (if any), sets `isAnalyzing = true`, and runs
   `AnalysisEngine.analyze(inputPath:)` inside
   `Task.detached(priority: .userInitiated)` — off the main actor, so a
   large `log show` or `tar` extraction doesn't freeze the UI — then hops
   back with `await MainActor.run`, re-checks the session still exists (it
   may have been closed while the task was running), and sets that
   session's `result` or `errorMessage`.

4. **`AnalysisEngine.analyze(inputPath:)`** is the whole pipeline (unchanged
   by the multi-session work — it's a pure function from a path to an
   `AnalysisResult`, with no awareness of sessions at all):
   - Expand `~`, confirm the path exists (`AnalysisError.pathNotFound` otherwise).
   - If it's a `.tar.gz`/`.tgz` (regex `\.tar\d*\.gz$|\.tgz$`), extract via `/usr/bin/tar xzf` into a temp dir (`devicediag_<UUID>` under the system temp directory), draining stderr on a background queue concurrently with the process so a large archive can't fill the pipe buffer and deadlock. Non-zero exit → `AnalysisError.extractionFailed`. The temp dir is tracked so it can be deleted later.
   - `FileLocating.findSysdiagnoseRoot` descends into the single sysdiagnose-named subfolder if the extracted/given directory has exactly one.
   - `FileLocating.findLogarchive` locates the `.logarchive` bundle.
   - `PlatformDetector.isMobile(root:)` decides macOS vs iOS/iPadOS.
   - `FileInventory.gather(root:isMobile:)` builds the Files tab's data.
   - `DeclarationsParser.parse(root:logArchive:)` always runs (shared across platforms).
   - Branches on platform: macOS runs `DeviceInfoParser`, `ConfigProfilesParser`, `ManagedSettingsExtractor`, then `FileVaultParser` (passed an `isMDMManaged` flag derived from whether any config profile's source contains "MDM" or a DDM declaration was found); mobile runs `MobileDeviceInfoParser`, `MobileEnrollmentParser`, `MobileManagedAppsParser`, `MobileProfilesParser`, `SettingsAttributionParser`.
   - Assembles an `AnalysisResult`, including `notes: [String]` — warnings accumulated along the way for missing files or parse failures (these surface as the Notes tab).

5. **Rendering.** Each session independently flips between `UploadView` and
   `ResultsView` based on whether its own `result` is nil. `.id(session.id)`
   on both branches in `RootView` is what makes switching the sidebar's
   selection swap in a genuinely different view instance (with its own
   fresh `@State`) rather than SwiftUI updating the same view in place.
   Inside `ResultsView`, `availableTabs` filters the fixed tab order (Device
   → Declarations → Config Profiles → Networking → Settings [mobile only] →
   Troubleshooting → Files → Notes) down to whichever sub-results actually
   have data. `TroubleshootingTabView` is the one exception to "instantiate
   whichever tab is selected": it stays permanently mounted in a `ZStack`
   alongside the switch-based content for every other tab, with only its
   `.opacity`/`.allowsHitTesting` toggled by `selectedTab` — see the Views
   layer section below for why.

## Parsing layer

Every parser is a stateless `enum` with one `static func parse(...)` — no
shared parser state, no classes. They all normalize whatever they read
(binary/XML plist, ASCII/NeXTSTEP plist, or JSON) into one of two things:
the shared `PlistValue` tree, or a typed struct from `AnalysisModels.swift`.

| File | Purpose | Reads |
|---|---|---|
| `PlistValue.swift` | Shared dynamically-typed plist tree (`indirect enum`, cases `.string/.int/.bool/.double/.date/.data/.dict/.array/.null`) with typed accessors, a `subscript(key:)`, `stringified`, and two truthiness checks (`isTruthyActive` strict, `isLenientlyTruthy` lenient) for normalizing how MDM state gets treated as "active" across inconsistent plist encodings (string `"1"` vs. integer `1`, etc.). `PlistValue.from(any:)` bridges `PropertyListSerialization`'s `Any` output into this tree. | N/A — pure data model |
| `AsciiPlistParser.swift` | Recursive-descent parser for Apple's legacy ASCII/NeXTSTEP plist syntax (`{ key = val; }`, `(a, b)`, quoted/bare tokens, `//` and `/* */` comments) — needed because `PropertyListSerialization` can't parse this format, and several sysdiagnose files use it. Coerces bare `"1"`/`"0"` to `PlistValue.int` specifically to preserve truthy checks. | Any string handed to it |
| `FileLocating.swift` | Shared filesystem helpers every other parser depends on: sysdiagnose root detection, recursive filename search (exact, prefix, path-suffix, "prefer path containing X"), and plist loading — binary/XML via `PropertyListSerialization`, ASCII via `AsciiPlistParser`, with a `plutil`-then-ASCII-fallback path for `rmd_inspect_system.txt`. `findPathSuffix(root:suffix:)` disambiguates filenames that aren't unique on their own (e.g. `ifconfig.txt` under both `network-info/` and `WiFi/`) by matching a longer root-relative suffix instead of a bare name. | Generic |
| `NetworkReportParser.swift` | Port of `sysdiag_netcheck.py`. Degrades section-by-section rather than all-or-nothing — a missing individual source file just yields an empty result for that one section rather than failing the whole report. Regex ports use `NSRegularExpression` options (`.dotMatchesLineSeparators` for Python's `re.DOTALL`, `.anchorsMatchLines` for `re.MULTILINE`) via the shared `regexFirstMatch`/`regexAllMatches`/`regexMatchGroups`/`regexAllMatchGroups` helpers (`DeviceInfoParser.swift`). Validated against real sysdiagnoses (both platforms) rather than assumptions, same as every parser here. iOS has no `network-info/` folder at all — `ifconfig.txt`/`netstat.txt`/`route-info.txt` are the identical tool output, just captured under `logs/Networking/` instead, so `text(_:)`'s helper tries both platforms' suffixes in turn; DNS/proxy/reachability/interface-advisory sections stay macOS-only since they come from `scutil`, which doesn't exist as a binary on iOS. `parseNetworkServices` is a separate, genuinely cross-platform addition: it reads SystemConfiguration's own `preferences.plist` (`NetworkServices` dict, the same file `scutil` itself reads from) to surface configured VPN services and per-service enabled proxy settings — this is what gives iOS a VPN/Proxy view at all despite missing `scutil`, and it's a bonus on macOS too since it's a different, config-level source than the live `scutil --proxy` snapshot. | `network-info/*.txt`/`logs/Networking/*.txt`, `WiFi/*.txt`, `preferences.plist` (see `wantedSuffixes`) |
| `FileVaultParser.swift` | Decodes `/usr/bin/psm status`/`psm list`/stderr output — `psm`'s own APFS/FileVault key-slot bookkeeping, not covered by `disks.txt` (which only reports whether the volume is encrypted, not which credentials can unlock it). All three source files carry raw ANSI color escapes that get stripped before parsing. Slots are grouped into their own blocks (split on `psm_status.txt`'s `---*---*---*---` separator) and keyed by each slot's own `user:` UUID, so a slot's `info:` descriptor — an OD-record username, "personal recovery key", "institutional recovery key", or "mdm boostrap token" (sic — that's the actual typo in Apple's own output) — is matched against that same slot rather than searched for anywhere in the file; the same UUID keying then lets `psm_stderr.txt`'s per-slot `failed-unlock-attempts[console,other]`/`max-unlock-attempts` counters (split on its own `-=-=-=-=-=-=-` banner) resolve back to a human-readable label. `isMDMManaged` is passed in from `AnalysisEngine` (an MDM-sourced config profile or a DDM declaration) rather than inferred here, since a missing bootstrap token only means something on a Mac that's actually MDM-managed. | `psm_status.txt`, `psm_list.txt`, `psm_stderr.txt` |
| `DeviceInfoParser.swift` | macOS device identity, plus the shared `regexFirstMatch`/`regexAllMatches` helpers used across parsers. | `sw_vers.txt`, `hardware_overview.txt`/`SPHardwareDataType.txt`, `hostname.txt`, `IODeviceTree.txt` |
| `StaticStatusValuesParser.swift` | Best-effort MDM status key-path values (suffixed `" *"`) purely from static files, as a fallback when the logarchive doesn't have a fresher value. | `sw_vers.txt`, `IODeviceTree.txt`, `remotectl_dumpstate.txt`, `SPHardwareDataType.spx`, `disks.txt`, `install.log` |
| `DeclarationsParser.swift` | Parses DDM state: groups activation/configuration declarations by Blueprint UUID (regex `Blueprint_([0-9a-fA-F-]{36})_`), collects standalone (non-blueprint) declarations, subscribed status key paths, and conduit/sync metadata. Cross-references the logarchive to fill in `StatusItem.lastValue`. | `rmd_inspect_system.txt` |
| `ConfigProfilesParser.swift` | Normalizes macOS configuration profiles into `ConfigProfileEntry`/`ConfigProfilePayload`. Structurally classifies each entry by scope (`collectProfiles(from:scope:into:)`, `looksLikeProfile(_:)`, `scopeLabel(fromGroupName:)`) rather than assuming a fixed array depth — newer macOS versions group `SPConfigurationProfileDataType` output into Device/User/Provisioning sections instead of one flat list, and provisioning-profile leaves have neither `_items` nor MDM keys, so they need their own detection path. Also hosts `ManagedSettingsExtractor`, which scans payloads for three specific managed-settings domains (`com.apple.notificationsettings`, `com.apple.TCC.configuration-profile-policy`, `com.apple.servicemanagement`). | `SPConfigurationProfileDataType.spx` |
| `MobileParsers.swift` | iOS/iPadOS equivalent, bundled: `PlatformDetector.isMobile`, `MobileDeviceInfoParser`, `MobileEnrollmentParser`, `MobileManagedAppsParser`, `MobileProfilesParser` (profiles live as loose `profile-*.stub` files rather than one `.spx`). | `SystemVersion.plist`, `remotectl_dumpstate.txt`, `IODeviceTree.txt`, `CloudConfigurationDetails.plist`, `MDM.plist`, `MDMAppManagement.plist`, `PayloadManifest.plist` + `profile-*.stub` |
| `SettingsAttributionParser.swift` | iOS-only: attributes each managed `restrictedBool` key to a profile, a DDM declaration, or an implicit device default. `MCSettingsEvents.plist`'s `Restrictions.restrictedBool` bucket is a last-touch audit trail for every key regardless of who wrote it — an entry whose selected sub-value's `event` is `"remove"` isn't currently in effect and is skipped (falls through to default) rather than counted as an active profile/declaration source. A UUID-shaped `process` only becomes a "profile" attribution if it resolves to a real `profile-*.stub` (an unmatched UUID, including Apple's own internal placeholder IDs, is left unattributed rather than given a fabricated name); a non-UUID `process` only becomes a "declaration" attribution if the device actually has real DDM declaration data (`hasDeclarations`, passed in from `AnalysisEngine`'s already-parsed `DeclarationsResult`) AND the process isn't one of a denylisted set of internal OS/MCF actors (`MCMigrator`, `MCRestrictionManagerWriter`, SpringBoard, `dmd`, etc.) that write to this same audit trail but never represent a declaration. Without those checks, every unmanaged device showed dozens of keys mislabeled "Declaration"/"Profile" purely from OS-internal bookkeeping and long-removed profiles. | `UserSettings.plist`, `MCSettingsEvents.plist`, `profile-*.stub` |
| `FileInventory.swift` | Static per-platform catalog (`macOSGroups`/`iosGroups`) of known sysdiagnose files grouped by category, checked for presence in the given archive. Wildcard entries (`"launchctl-*"`) collapse multiple matching files into one "collection" row with `groupedPaths`; plain-filename entries also record `isDirectory` (true only for an actual browsable folder like `network-info`/`WiFi`, not a bundle like `system_logs.logarchive`, which keeps its own path extension) so the Files tab can show a folder icon on the right rows. `viewableCandidates(from:)` filters that same catalog down to files worth offering as a companion pane's timestamp-correlation target: found, single underlying path, extension in `FileTextLoader.viewableExtensions`, AND on the explicit `companionCandidateNames` allowlist (`install.log`, `system.log` — most other cataloged files are single point-in-time snapshots with no per-line timestamps to land on, so they're excluded even if otherwise viewable) — shared by the Troubleshooting tab's and Log Stream's "Open File Alongside…" pickers so both list identical candidates. | Checks presence of every cataloged filename |
| `MarketingNames.swift` | Static OS-version → marketing-name tables (macOS, and iOS/iPadOS by device class). | N/A |

## Services layer

| File | Purpose |
|---|---|
| `AnalysisEngine.swift` | The orchestrator described above; also defines `AnalysisError` (`.pathNotFound`, `.extractionFailed`, `.processingError`). |
| `LogArchiveService.swift` | All `/usr/bin/log` interaction. `TroubleshootCatalog` is the static predicate catalog behind the Troubleshooting tab's category picker; `TroubleshootCatalog.terms(in:)` regexes each topic's predicate string apart into atomic `field <op> "value"` comparisons (`LogFilterTerm`), and `filterOptions(for:isMobile:)` dedupes those across a category's topics (with topic names attached for the UI's "(Topic)" labels) into what the checkbox filter dropdown actually displays. Every topic carries a `LogTopicDefinition.platform` (`.both`/`.macOSOnly`/`.differs(ios:)`, in `AnalysisModels.swift`) resolved via `resolvedPredicate(isMobile:)` — `sortedCategories(isMobile:)`/`sortedTopics(for:isMobile:)`/`filterOptions(for:isMobile:)` all filter out anything that resolves to `nil` for the sysdiagnose's actual platform, so a macOS-only category (Jamf Connect, Jamf Remote Assist, System and Kernel Extensions, Gatekeeper/XProtect) never shows up on iOS, and a shared category (MDM/enrollment, Setup Assistant) swaps in iOS's own process/subsystem names (`mdmd`, `com.apple.ManagedConfiguration`, `Setup`) instead of macOS's. `LogLevel` (debug/info/default/error/fault — `log show`'s own `messageType` predicate values; there's no "warning" level) backs a separate, orthogonal severity multi-select; `levelPredicateClause(for:)` ORs whatever's checked into a `messageType == x OR ...` clause, exact rather than threshold-based (checking Error and Fault matches only those two). `combinedPredicate(for:)` rebuilds a `log show` predicate from whatever's checked — OR within a field, and OR across fields too, so checking anything only ever widens the result. This used to AND across fields instead, on the theory that it'd reconstruct a topic's own multi-field predicate (e.g. "Daemon Elevation"'s subsystem-AND-category), but that AND applied indiscriminately to every checked field regardless of whether the terms actually came from the same topic — checking a category's topics plus an unrelated custom addition in a different field (e.g. "Jamf Connect" plus a custom `process == "loginwindow"`) produced an impossible-to-satisfy AND and silently returned nothing, for every category, since they all share this one function. The original per-topic AND/OR structure is intentionally not preserved either way, so admins can recombine facets across topics rather than being stuck with one topic's fixed query; a topic that genuinely needs its own narrower AND is still reachable via "Custom". `LogArchiveService.runLog` drains stdout/stderr on a background queue with a `DispatchSemaphore` while the process runs, to avoid the same pipe-deadlock risk as `tar` extraction. Exposes `readLogarchive`, `readStatusItemLogs`, `parseSoftwareUpdateStatusValues`, `runTroubleshootQuery` (the "Custom" category's single free-text query), `runTroubleshootFilterQuery` (the checkbox-picker query), `readLogStream`. `readLogarchive` (used by the Log Stream window and `readStatusItemLogs`, not the Troubleshooting tab — that tab renders `log show`'s raw text output directly and never re-parses `messageType`) maps `--style ndjson`'s numeric `messageType` field back to a level string via `levelMap`, which mirrors the same five real values `LogLevel` above does (`os_log_type_t`: 0/1/2/16/17 → default/info/debug/error/fault) — this table previously had 16/17 swapped and an invented, unreachable 18 → "warning" entry; `LogStreamView`'s per-row tint switch consumed that same wrong data. |
| `FileOpener.swift` | `FileOpener.open`/`revealMultiple` wrap `NSWorkspace` (open one file in its default app, or reveal several pre-selected together in one Finder window — used for grouped launchd dumps). `LogExportService.export` shows an `NSSavePanel` and writes exported log lines to disk. |
| `FileTextLoader.swift` | Fast, dependency-free text loader. `load` (Files tab viewer) caps rendered lines at 4000 and pretty-prints `.plist` as XML via `PropertyListSerialization`; `loadAllLines` (companion-file panes) is uncapped, since a timestamp match could be anywhere in the file. Returns `Result<Loaded/[String], LoadError>` (a wrapper type, since plain `String` doesn't conform to `Error`). Also exposes the shared `viewableExtensions` set both loaders and `FileInventory.viewableCandidates` agree on. |
| `TimestampLineMatcher.swift` | Precompiled `NSRegularExpression`/`DateFormatter` pairs for the "open file alongside" companion pane: `leadingISOTimestamp(in:)` extracts a `log show` result line's own leading ISO timestamp (used by the Troubleshooting tab to pin an anchor); `nearestLine(to:in:)` scans an arbitrary sysdiagnose text file line-by-line trying an ISO pattern first, then a syslog-style `MMM d HH:mm:ss` pattern (which has no year, so it borrows the target's year, rolling back one if that lands implausibly far in the future — the Dec/Jan boundary case), returning whichever line's timestamp is closest to the target. |
| `DiagnosticsLog.swift` | The app's own log of its own behavior — not to be confused with `LogArchiveService`, which reads logs *out of* the sysdiagnose being analyzed. `info`/`error` write a timestamped line to a serial-queue-guarded `FileHandle` at `fileURL` (`~/Library/Logs/DeviceDiag/DeviceDiag.log`, trimmed to its newest half once it passes 5 MB) and mirror to an `os.Logger` under subsystem `com.devicediag.app` for live Console.app filtering. `reveal()` calls `NSWorkspace.activateFileViewerSelecting` — wired to the Help menu's **Reveal Diagnostics Log** command and a button on the Help window's own "Diagnostics Log" page. Called from `AnalysisEngine.analyze` (start/finish timing, extraction start/success/failure), `LogArchiveService.runLog` (every `log show` invocation, its elapsed time, and timeouts specifically — the highest-value hook, since a silent timeout was previously indistinguishable from "no results"), `AppState.analyze`'s catch block, and `WiFiHistoryParser.extract`. |

## Data model (`AnalysisModels.swift`)

Everything is a plain `struct`; anything shown in a `List`/`ForEach` conforms
to `Identifiable` via `let id = UUID()`.

- **macOS**: `DeviceInfo` (serial, OS version, build, model, hostname), `ManagedSettings` (managed notifications/PPPC/login items), `FileVaultResult` (enabled, enrolled users, admin-not-enrolled list, personal/institutional recovery key + bootstrap token flags, `isMDMManaged`, `nearLockoutSlots: [FileVaultUnlockAttempt]`; `missingBootstrapToken`/`hasNoRecoveryMechanism` are computed).
- **Config profiles (shared)**: `ConfigProfilePayload`, `ConfigProfileEntry` (name, org, source, install date, removal-disallowed, verified, identifier, uuid, description, payloads), `ConfigProfilesResult` (found/error/profiles).
- **Network report**: `NetworkInterfaceEntry`, `InterfaceCounterEntry`, `TCPStackStats`, `RouteEntry`, `DNSResolverEntry`, `ReachabilityCheckEntry`, `WiFiStatusInfo`, `ConnectivityTestEntry`, `PingLossEntry`, `NetworkFinding` (severity/category/message), `NetworkReportResult` (found/error/hostname + one array or struct per section above).
- **MDM declarations**: `DeclarationStatusGroup` (ok/count/active/valid/reasons), `BlueprintDeclaration` (uuid, actType, cfgType, activation/config groups), `StandaloneDeclaration` (section, identifier, type, load state, active count), `StatusItem` (keyPath, needsSync, lastReceivedDate, lastValue, rawNeedsSyncDebug for tooltip debugging), `ConduitInfo` (last received/processed, consecutive errors), `DeclarationsResult` (found/error/blueprints/standalone/conduit/statusItems).
- **Mobile**: `MobileDeviceInfo`, `MobileEnrollmentInfo`, `ManagedApp` (bundleID/state/flags/removable).
- **Settings attribution (iOS only)**: `SettingsAttributionEntry` (key, value, source: profile/declaration/default, profile name, implicit flag, timestamp), `SettingsAttributionResult` (found/error/counts/entries).
- **Files**: `SysdiagFileEntry` (name, description, path, found, groupedPaths for collection entries), `SysdiagFileGroup` (group name + files).
- **Troubleshooting**: `LogTopicDefinition` (extra args, predicate, `platform: LogTopicPlatform` + `resolvedPredicate(isMobile:)` — see the `LogArchiveService.swift` row above), `LogEntry` (timestamp, process, subsystem, message, level), `LogFilterTerm` (field: process/subsystem/keyword, op: `==`/`CONTAINS`/`BEGINSWITH`, value — the unit the checkbox filter picker checks/unchecks), `CatalogFilterOption` (a `LogFilterTerm` plus which topic(s) it came from, for display), `LogLevel` (the separate Debug/Info/Default/Error/Fault severity multi-select, in `LogArchiveService.swift`).
- **Top-level `AnalysisResult`**: name, analyzedAt, isMobile; the macOS block; the mobile block; shared fields (`sysdiagFiles`, `declarations`, `configProfiles`, `logArchivePath`, `notes`); plus `rootURL` and `tempDirectories` (deleted on the next analysis or `startOver()`).

## App state (`AppState.swift`)

`AnalysisSession` is one open sysdiagnose's own state — `id: UUID`,
`result: AnalysisResult?`, `isAnalyzing: Bool`, `errorMessage: String?`, and
`sourcePath: String?` (the expanded input path it was/is being analyzed
from, used purely for the dedup check). `displayName` falls back to "New
Analysis" until `result` exists.

`@MainActor final class AppState: ObservableObject` holds a list of these
instead of a single result, so more than one sysdiagnose can be open (and
compared) at once:

- `sessions: [AnalysisSession]`, `selectedSessionID: UUID?` — the sidebar's
  data source and current selection. `selectedSession` is the derived
  lookup; `shouldShowSidebar` is `sessions.count > 1 || sessions.contains { $0.result != nil }`
  (a single still-blank tab has nothing to switch between, so the sidebar
  stays hidden until there's a real reason to show it).
- `linkedReportTab: ResultsTab` / `linkReportTab: Bool` — the "Sync Tabs"
  feature. `ResultsView` writes the former on every tab change when the
  latter is on, and reads it back in `.onAppear` when a different session
  becomes selected.
- `sidebarCollapsed: Bool` — purely a layout toggle `RootView` reads to pick
  the sidebar's frame width; `SessionSidebarView` reads it too, to decide
  between its full row layout and the icon-only collapsed one.
- `newTab()` / `openInNewTab(path:)` / `closeTab(_:)` / `startOver(_:)` /
  `clearError(_:)` all take or generate a session `id` and mutate just that
  one entry in `sessions`. `closeTab` reopens a fresh blank tab if that was
  the last one, so the sidebar (once shown) is never left empty.
- `analyze(path:in:)` is `openInNewTab`'s and `UploadView`'s shared engine
  call — see the dedup/threading details in the Data Flow section above.
- `openDropped(paths:primarySessionID:)` is the multi-file-drop entry point
  every drop target funnels through (sidebar, the blank upload screen, Dock/
  "Open With"): if `primarySessionID` names a still-blank tab, the first
  path analyzes directly into it; every other path (and the first, if
  there's no such tab) gets `openInNewTab`.
- `cleanupAll()` walks every session's temp directories on quit — with a
  single global result, starting a new analysis was always the moment the
  previous temp dir got deleted, but with several tabs open there may be no
  "next analysis" to trigger that, so `AppDelegate.applicationWillTerminate`
  calls this directly as the backstop.

Navigation is derived purely from whether each session's `result` is nil;
there's still no persistence between launches by design, and no
app-level state machine enum.

## App wiring (`DeviceDiagApp.swift`)

`AppDelegate` implements `application(_:open:)` for file-open events,
collecting every URL macOS hands over into `openedFilePaths: [String]` (not
just the last one — see Data Flow above) and calling
`NSApp.activate(ignoringOtherApps: true)` so a Dock drop while the window is
behind something else surfaces it. It also holds a `weak var appState`
(set once from `DeviceDiagApp`'s `.onAppear`) purely so
`applicationWillTerminate` can call `appState.cleanupAll()`.

The main scene is a singular `Window("DeviceDiag", id: "main")`, not a
`WindowGroup` — a `WindowGroup` lets macOS spin up an entirely new window
per "open a document" event for an app that declares
`CFBundleDocumentTypes` (like this one), which is exactly the "drag onto the
Dock icon opens a second, redundant window" bug this app doesn't want:
every open sysdiagnose already lives in one window's sidebar. `Window`
guarantees there's only ever one, and file-open events reuse it. It's sized
`minWidth: 980, minHeight: 680` with `.windowResizability(.contentSize)`. A
second, separate `Window("DeviceDiag Help", id: "help")` hosts `HelpView` —
a small standalone window rather than a sheet, so it can stay open and
readable side-by-side with a report instead of blocking interaction with it.

App-level menu commands: Cmd+N (`CommandGroup(replacing: .newItem)`) calls
`appState.newTab()`; Cmd+? (`CommandGroup(replacing: .help)`) calls
`openWindow(id: "help")`; the same group's **Reveal Diagnostics Log** item
calls `DiagnosticsLog.reveal()`. Cmd+R (reset the upload form) and Cmd+F
(per-tab find) are both registered locally inside the relevant views, not
here.

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
- **No logging existed anywhere until `DiagnosticsLog`.** Before it, a slow/
  failed `tar` extraction or a `log show` query that silently hit its
  timeout only ever showed up (if at all) as a transient error banner that
  vanished the moment it was dismissed or the next analysis started —
  nothing was left to look at afterward. `DiagnosticsLog.info`/`.error` are
  the one place any new long-running or `Process`-based feature should log
  its start, duration, and failure mode; see the Services layer table above
  for exactly which calls exist today.
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
- **`.id(session.id)` is what makes tab switching actually swap state.**
  `RootView` gives each session's `UploadView`/`ResultsView` a `.id()` tied
  to that session's `UUID`. Without it, SwiftUI sees the same view at the
  same spot in the tree across a sidebar selection change and just updates
  it in place — every `@State` (typed path, selected report tab, search
  text, scroll position) would leak from whichever session was showing
  before into whichever one you just switched to.
- **A row you want fully clickable needs a `Button`, not `onTapGesture`
  layered on top of `Text`.** The companion-pane row (Troubleshooting/Log
  Stream) originally used `.contentShape(Rectangle()).onTapGesture { }` on
  top of a `Text`/`HStack` of `Text`s — on macOS, `Text` installs its own
  click handling (cursor tracking, and text-selection click-and-drag when
  `.textSelection(.enabled)` is active, which it is here via the
  `ResultsView` root) that wins over an ancestor's `onTapGesture` for clicks
  that land on actual glyphs, leaving only the row's padding reliably
  clickable. A plain-style `Button` wrapping the row's content installs one
  click recognizer for its whole frame that takes priority over what's in
  its label, fixing that — but a `Button` is an *exclusive* gesture, so it
  also disables the row's underlying text selection/copy. The fix that kept
  both: drop the `Button`, keep `.textSelection(.enabled)`, and attach the
  tap as `.simultaneousGesture(TapGesture().onEnded { ... })` instead of
  `.onTapGesture`/`.gesture` — a simultaneous gesture doesn't claim
  exclusive priority, so the native click-drag-to-select/copy behavior and
  the custom "pin this line" action both fire from the same click.
- **A tab that needs to survive being switched away from must stay
  mounted, not just be re-shown.** `ResultsView`'s `contentView` used to be
  a single `switch selectedTab` — every tab was a fresh instance each time
  it became selected, so a tab with real accumulated state (Troubleshooting:
  filters, query results, the pinned timestamp, the companion file pane)
  lost all of it the moment you switched away and back, since the switch's
  previous branch was torn down entirely. The fix was a `ZStack`: every
  *other* tab still comes from a `switch` that's only mounted while
  selected (they don't hold onto anything worth preserving), but
  `TroubleshootingTabView` is instantiated unconditionally alongside it,
  with only `.opacity`/`.allowsHitTesting`/`.accessibilityHidden` toggling
  based on `selectedTab` — visibility changes, identity doesn't, so its
  `@State` is never torn down.
- **Multi-file drop funnels through one `AppState` method.** Three separate
  drop targets (`SessionSidebarView`, `UploadView`'s drop zone, and
  `AppDelegate.application(_:open:)` for Dock/"Open With") each collect
  every dropped/opened URL — using a `DispatchGroup` + index-keyed
  dictionary behind a lock for the two SwiftUI `onDrop` sites, since each
  `NSItemProvider.loadObject` call is independently async and order needs
  preserving — then hand the whole batch to
  `AppState.openDropped(paths:primarySessionID:)` rather than each
  reimplementing "open one path" in a loop.
- **Grouped file entries reveal, they don't copy.** `SysdiagFileEntry.groupedPaths`
  plus `FileOpener.revealMultiple` let one row (e.g. "Launchd Files")
  represent several underlying files and select them all together in one
  Finder window via `NSWorkspace.shared.activateFileViewerSelecting`, rather
  than physically copying files into a synthesized folder (which would need
  its own temp-dir cleanup tracking).
- **Only a vertical `ScrollView` clips, it doesn't reflow.** `ResultsView`'s
  wrapper around every non-Troubleshooting tab used to scroll vertically
  only; several tabs' tables (Networking, Device, Config Profiles) lay
  their columns out with fixed `.frame(width:)`s that add up to more than
  what's actually available once the window is resized narrower than
  full-screen, and a fixed-width `HStack` doesn't shrink its children to
  fit — it just overflows, which a vertical-only `ScrollView` clips at the
  trailing edge instead of leaving reachable. Fixed by scrolling that axis
  too (`ScrollView([.vertical, .horizontal])`) rather than trying to reflow
  every fixed-width table, which would've meant auditing every column in
  every tab individually.
- **`ViewThatFits` for a breakpoint, not a `ScrollView`, for a toolbar with
  too many controls.** `TroubleshootingTabView`'s toolbar
  (category/filters/levels/timeframe/run/export/open-alongside — more
  controls in one row than anywhere else in the app) hits the same
  overflow-once-resized-below-full-screen problem as the tab tables above,
  but scrolling it (the first fix) read as controls randomly disappearing
  off the edge rather than a deliberate layout, and only ever shrank one
  control's worth of space at a time as the window narrowed instead of
  reflowing cleanly. `ViewThatFits(in: .horizontal)` fixes this properly:
  given two full candidate layouts — the normal single row, and a two-row
  split (`queryControls` on top, `resultActions` below, both `@ViewBuilder`
  vars shared between the two candidates so there's only one copy of each
  control) — it measures both and picks whichever actually fits, so the
  toolbar snaps to two rows at one clean breakpoint instead of degrading
  gradually. This only works measured against a real width constraint from
  the parent — a `ScrollView` offers its content an *unconstrained* width to
  grow into, so wrapping `ViewThatFits` in one (as the toolbar briefly was,
  from the first fix) would make it always see "plenty of room" and never
  pick the narrower candidate at all.
- **A `CardView` title's `maxWidth: .infinity` makes the whole card greedy
  in an `HStack` unless capped.** `CardView`'s title bar is `.frame(maxWidth:
  .infinity, alignment: .leading)` so a card's header spans its own full
  width — correct for every full-width card in the app, but `DeviceTabView`
  also places the Device Information card beside the (fixed 320pt-wide)
  FileVault card in an `HStack`, and uncapped, Device Information's title
  bar claimed however much width the `HStack` offered even though its
  actual content (one 190pt label column plus a line of value text) never
  needed more than about 450pt — squeezing FileVault out of room far
  sooner, on resize, than the window's actual width justified. Fixed with
  an explicit `.frame(maxWidth: 480)` on `macDeviceCard` at the call site
  rather than on `CardView` itself, which would've un-stretched every
  other card's title bar in the app along with it.
- **SwiftUI text selection doesn't merge across sibling `Text` views — so
  Troubleshooting's results don't use it at all.** `.textSelection(.enabled)`
  (applied once at `ResultsView`'s root, still true for every other tab and
  for `FileViewerView`/`LogStreamView`) lets any single `Text` be
  click-drag-selected and copied, but a log viewer that renders one line
  per row is one `Text` *per line* — dragging across several of them never
  merges into one copyable range, so only whichever line the drag started
  in was ever actually copyable. `TroubleshootingTabView`'s result rows
  opt back out of it entirely with `.textSelection(.disabled)`, and treat
  each row as one whole, indivisible log entry (timestamp, process,
  message — the complete line) rather than a string a user might want to
  drag-select part of. An earlier version left `.textSelection(.enabled)`
  in place and layered a plain click on top of it via
  `.simultaneousGesture`, so the click gesture and the native drag-select
  gesture were competing recognizers on the same view — which is almost
  certainly why clicking a line to pin the companion-file anchor
  (`selectLine`) felt unreliable; `.textSelection(.disabled)` removes that
  competition, leaving `.onTapGesture` as the row's only gesture besides
  `.contextMenu`. Selection itself is: click selects one line
  (`selectedLineIndices`), Shift-click extends a contiguous range,
  Cmd-click toggles one line at a time (`NSEvent.modifierFlags`, read
  synchronously inside the tap handler) — the same convention as a Finder
  or Mail list. Copying is two parallel paths to the same
  `copyToPasteboard(_:)`: the status bar's "Copy N Lines" button acts on
  the whole selection (`orderedSelectedLines`), and each row's right-click
  menu (`linesToCopy(rightClicking:)`) acts on the selection too if the
  right-clicked row is part of it, or on just that one row otherwise —
  mirroring how Finder's right-click treats an item outside the current
  selection as a one-off target. Deliberately not bound to ⌘C, since
  there's no longer a native single-line text selection to conflict with,
  but ⌘C isn't a convention used anywhere else for a custom selection like
  this one either.
- **Selection/anchor state here is keyed by index, not text — because two
  log lines with identical text are not the same line.** The first version
  of both this multi-select and the older click-to-pin-anchor feature
  tracked `selectedLineTexts: Set<String>` / `anchorLineText: String?`
  instead, reasoning that `displayedLines`' own indices aren't stable
  across pagination/search re-filtering. That's true, but the fix was
  wrong: clicking one line, or copying a selection, silently matched
  *every other line anywhere in the result that happened to read the
  same* — extremely common in a log (heartbeats, retries, repeated
  errors), and confusing/broken in practice ("clicking one line highlights
  all similar lines"). The actual fix is `DisplayedLine`, a small struct
  pairing each rendered line with its index into the *full, unpaginated*
  `queryResult.lines` array — that index is just as stable as text across
  pagination (which only ever takes a longer prefix of the same array) and
  search (which only changes which elements are shown, never reorders or
  replaces them), while still uniquely identifying the one line clicked.
  `selectedLineIndices: Set<Int>` and `anchorLineIndex: Int?` are keyed by
  that. The one place a *position* (not the stable index) still matters is
  Shift-click's range math, which is deliberately visual — it spans
  whatever's between two rows currently on screen, not a range in the full
  array that might jump over lines search has filtered out.
- **`TroubleshootingTabView` being unconditionally mounted is what made
  reactivating the app — and switching report tabs — slow.** A real,
  reproducible 1-2s hitch on bringing DeviceDiag back to the foreground
  (Time Profiler traced it to `-[NSWindow resignKeyWindow]`'s notification
  cascade — SwiftUI/AppKit updating every live control's active/inactive
  appearance across the *entire* view tree, confirmed by the delay
  vanishing with zero sysdiagnose tabs open) came from `ResultsView`'s
  `TroubleshootingTabView` being mounted at all times (opacity/
  `allowsHitTesting` toggled, not conditionally included) for as long as
  *any* report tab was open, so its full tree — pickers, popovers, and any
  already-run result rows — was always "live" and got walked by that
  update on every window activate/deactivate. A first pass only mounted it
  after the person opened that tab at least once, which helped until they
  actually did — at which point the same always-mounted tree made
  switching between *any* report tabs slow too, since any re-render
  anywhere in `ResultsView` still had to touch it.
  The actual fix was moving Troubleshooting's state off the view entirely.
  `TroubleshootingModel` (an `ObservableObject`, `Models/
  TroubleshootingModel.swift`) holds everything that used to be `@State`
  on `TroubleshootingTabView` — query filters, results, the pinned
  companion-file moment, the multi-line selection — and is owned by
  `AnalysisSession` (`AppState.swift`, one instance per open sysdiagnose)
  rather than by the view. `TroubleshootingTabView` now takes it as an
  `@ObservedObject`, reading/writing through `model.x` everywhere `x` used
  to be local `@State`. Only two things stayed on the view itself:
  `@FocusState` can't live on an `ObservableObject` at all, and
  `lastClickedIndex` (the position of the last click, for Shift-click
  range math) is fine to lose on a remount since it's already meaningless
  across a search re-filter — nothing else needs to survive at that
  granularity. With the state off the view, `ResultsView.body` mounts
  `TroubleshootingTabView` only while `selectedTab == .troubleshoot`,
  exactly like every other report tab — tearing it down when you switch
  away no longer throws anything away, since none of it lived there
  anymore, which is what actually removes the always-live tree causing
  both symptoms. One consequence worth knowing: a query started right
  before switching away now keeps running and lands in `model.queryResult`
  even while the view is unmounted (the `Task.detached` closures capture
  `model`, a class reference owned by the session, not `self`), which
  wasn't previously possible to separate from "the view has to stay
  mounted for anything to survive" at all.

  This fix did **not** resolve the reactivation delay — it was retested
  after landing and the 1-2s hitch was still present even staying on the
  Device tab the whole time, never touching Troubleshooting at all. So the
  always-mounted Troubleshooting tree was at most a contributor, not the
  (sole) cause. Still worth keeping this fix regardless (it's a real
  improvement, and Troubleshooting no longer contributes at all now), but
  the actual root cause is still open — see the note below and task #86.
  Next step is a fresh Time Profiler capture with only the Device tab
  open, to get a real call tree instead of guessing again.

- **Config Profiles rendering inconsistently while scrolling — cards
  appearing/disappearing depending on scroll position — was
  `LazyVStack` fighting the wrong `ScrollView` axis.** Task #68 made the
  profile-card list a `LazyVStack` so a sysdiagnose with dozens of
  profiles didn't have to lay out every card synchronously on every visit
  (see the comment in `ConfigProfilesTabView`). But every non-Troubleshoot
  report tab shares the same wrapping `ScrollView([.vertical, .horizontal])`
  in `ResultsView` (added so Networking/Device's fixed-width table columns
  stay reachable when the window is narrower than their combined width).
  `LazyVStack` decides what to actually build based on what's currently
  visible along the `ScrollView`'s scroll offset — mixing in a `.horizontal`
  axis that Config Profiles' content never actually uses skews that
  calculation, so cards outside the initial viewport render inconsistently
  instead of reliably appearing once scrolled to. Config Profiles has no
  fixed-width columns needing horizontal room in the first place, so
  `ResultsView.body` now gives it its own plain vertical-only `ScrollView`
  instead of routing it through the shared bidirectional one — exactly
  what `LazyVStack` expects.

  Networking got the same vertical-only treatment right after, for a
  related but distinct reason: none of its tables' fixed-width columns
  (see `NetworkingTabView`'s `tableHeader`/row widths) actually add up to
  more than what's available even at the app's smallest window size — the
  forced `minWidth: 1100` was just making the whole tab wider than it
  needed to be, so anyone whose window was narrower than that had to
  scroll sideways to see rows that would've fit fine at their actual
  window width. Device (and its side-by-side Device Information +
  FileVault cards, which genuinely can exceed the smallest window width)
  is the only tab still on the bidirectional `ScrollView` + `minWidth: 1100`
  path (plus Files/Settings/Notes, untouched so far — same fix applies if
  they ever get the same complaint, check their fixed-width columns first).

  Declarations got the same fix next, for a sharper version of the same
  underlying issue: a flexible-width column (`Last Value` in the Status
  Key Paths table, `Activations`/`Configurations` in the Blueprint table)
  holding a long, line-break-free value — a raw NSError description like
  softwareupdate's `failure-reason`, hundreds of characters on its own —
  rendered as one single, arbitrarily long horizontally-scrolling line
  instead of wrapping at the window's edge. `Text` only wraps when its
  container gives it an actual bounded width to wrap *within*; a
  `ScrollView` that includes `.horizontal` never bounds width (offering
  unbounded width to scroll into is what that axis is for), so nothing
  in it ever wraps, no matter how the individual `Text` is configured.
  Moving Declarations onto the same vertical-only `ScrollView` as
  Config Profiles/Networking bounds its width like any normal container,
  so long values now wrap like `Text` normally does instead of forcing a
  horizontal scroll to read them.

- **Declarations tab: "what does this mean?" info popovers for DDM status
  codes and Software Update failure reasons.** `Models/ErrorReferenceCatalogs.swift`
  holds two static reference catalogs aggregated from Jamf's internal
  support documentation (see `LogCommands_QuickWins_Research.md` sections
  9.1/9.2 for sourcing): `DDMErrorCodeCatalog` decodes the `reasons` codes
  (`Error.ActivationFailed`, `Info.Predicate`, `Error.ConfigurationCannotBeApplied`,
  etc.) that show up on a Blueprint's activation/configuration status rows,
  and `SoftwareUpdateErrorCatalog` decodes the raw NSError-style text in
  the `softwareupdate.failure-reason` status key path (`BatteryTooLow`,
  `SUMacControllerError Code=7507`, etc. — the exact string family that
  prompted the text-wrap fix above) into a plain-English category and fix.
  `Views/InfoReferenceButton.swift` is the shared, catalog-agnostic "ⓘ"
  popover: it takes a flat `[InfoReferenceRow]` (already split into
  matched/unmatched by each catalog's `rows(highlighting:)`) and renders
  the matches first, highlighted, with the rest of the reference table
  underneath rather than hiding it — so the admin always sees the full
  table, just reordered around whatever code is actually on that row.
  `DeclarationsTabView`'s `BlueprintRow` wires this up next to a status
  group's reason text (only in the `⚠`/`✕` branches — the `✓ ok` branch has
  no reason code to look up), and `StatusItemRow` wires it up next to
  `lastValue`, gated specifically on `keyPath == "softwareupdate.failure-reason"`
  rather than every `softwareupdate.*` key path, since the decoder table
  is built for that one key path's specific value shape and wouldn't mean
  anything applied to, say, `softwareupdate.beta-enrollment`.

- **`AnalysisEngine` detects archive format by magic bytes, not extension.**
  A sysdiagnose dropped on the app always looked like a `.tar.gz`/`.tgz`
  straight off a Mac — until one named
  `sysdiagnose_20261008_..._macOS_Mac_25G229.targ.zip` came in (date dots
  stripped, `.tar.gz` collapsed to `.targ`, wrapped as `.zip` — almost
  certainly from being zipped for transfer through email/Slack/a ticket).
  The old `isTarGz(path)` regex check only matched `\.tar\d*\.gz$|\.tgz$`,
  so a `.zip`-suffixed file skipped extraction entirely:
  `FileLocating.findSysdiagnoseRoot` returns a non-directory path
  unchanged, so every single parser below it ran against nothing — with no
  thrown error, since nothing in that path actually failed, it just had no
  files to find. The user could see every real sysdiagnose file was there
  by unzipping it themselves in Finder, which is what made this look like
  a folder/sync problem rather than an archive-format one.
  `AnalysisEngine.detectArchiveKind(_:)` now reads a file's first 4 bytes
  and checks for gzip (`1F 8B`) or zip (`PK`) magic before ever looking at
  its name, falling back to the old extension check only if the file
  couldn't be read at all. `extractArchive(_:kind:into:)` generalizes the
  old tar-only extraction (same stderr-draining-to-avoid-deadlock pattern)
  to run `/usr/bin/unzip -q` instead of `tar xzf` for a zip. Because a
  sysdiagnose zipped for transfer sometimes wraps the original `.tar.gz`
  as a single nested file rather than containing the sysdiagnose's files
  directly, `unwrapSingleNestedArchive(_:tempDirs:)` checks for exactly
  that shape right after the outer extraction and, if found, extracts the
  inner archive too before `findSysdiagnoseRoot` ever runs.

## Packaging

- **`Package.swift`**: SwiftPM manifest, `swift-tools-version: 6.0`, `.macOS(.v15)`, one executable target, Swift 5 language mode.
- **`Packaging/Info.plist`**: bundle ID `com.boaz.devicediag`, version `1.0`/build `1`, min OS `15.0`, category Utilities, icon `AppIcon.icns`. Declares `CFBundleDocumentTypes` for `.tar.gz`/`.tgz` at `LSHandlerRank: Alternate` (offers DeviceDiag in "Open With" without stealing the system default tar/gzip handler) — this exists because `AnalysisEngine` only extracts `.tar.gz`/`.tgz`, never `.zip`.
- **`Packaging/DeviceDiag.entitlements`**: intentionally an empty `<dict>`. The app cannot be sandboxed — it shells out to `tar`, `unzip`, `log`, and `plutil` via `Process`, which App Sandbox blocks. Hardened Runtime is enabled at sign time instead (`codesign --options runtime`), not via this file.
- **`Packaging/build_app.sh`**: the real distribution path. Builds arm64-only release (`swift build -c release`; multi-arch needs Xcode's XCBuild backend, which isn't reliably available outside Xcode itself), assembles `dist/DeviceDiag.app`, and prints — but does not run — the signing/notarization/pkg commands (`codesign` with a Developer ID identity and `--options runtime`, `notarytool submit --wait`, `stapler staple`, `pkgbuild --sign` for a signed installer). Use this for anything that goes out via Jamf Pro.
- **`Packaging/build_unsigned_installer.sh`**: internal-testing-only path. Same build, but ad-hoc signs (`codesign --sign -`, no cert — required just to launch on Apple Silicon, does not satisfy Gatekeeper) and produces an unsigned `.pkg`, with tester instructions for bypassing Gatekeeper's first-launch block. Don't use this path for anything beyond handing a build to another developer to try.

Run either script as your normal user — neither `swift build`, ad-hoc
`codesign -s -`, nor unsigned `pkgbuild` needs root, and running with `sudo`
risks leaving root-owned files in `dist/` that cause permission errors on
later (non-sudo) rebuilds.

Both scripts also `xattr -cr` the freshly-assembled `.app` and delete any
`._*` AppleDouble files right before their codesign step. This repo (and so
`dist/`/`.build/`) lives inside a OneDrive-synced folder, and OneDrive's
sync client attaches extended attributes — sometimes AppleDouble sidecar
files too — to files as it syncs them. `codesign` refuses to sign a bundle
carrying either, failing with "resource fork, Finder information, or
similar detritus not allowed," and because both scripts use `set -e`, that
failure silently stopped `build_unsigned_installer.sh` right there — after
assembling `DeviceDiag.app`, before ever reaching `pkgbuild` — which is why
a run could produce only the `.app` with no `.pkg` alongside it. If this
error ever reappears (a fresh OneDrive sync cycle can re-attach the
attributes between the strip step and the codesign call, though this
hasn't been observed in practice), just re-run the script.

## If you're starting over from scratch

Build in roughly this order, since later layers depend on earlier ones:

1. `PlistValue` + `AsciiPlistParser` + `FileLocating` — nothing else can be written until these exist.
2. `AnalysisModels.swift` — get the data shapes right before writing parsers against them.
3. One parser at a time, verified against a real sysdiagnose archive rather than assumptions about its contents (extract one, grep for the exact paths/keys a parser expects, confirm the format matches before trusting the output).
4. `AnalysisEngine` to wire the parsers together, then `AppState` to drive it from the UI.
5. `UploadView`/`ResultsView` shell, then one tab view at a time — build `FindSupport.swift` (the Cmd+F infrastructure) before or alongside the first tab that needs it, since every subsequent tab reuses it verbatim.
6. Packaging last, once the app itself is stable.
