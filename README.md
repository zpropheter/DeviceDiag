# Sysdiagnose Analyzer

A local Flask web application for Apple support staff to analyze sysdiagnose archives from **macOS and iOS/iPadOS** devices. Drop in a `.tar.gz` or an extracted sysdiagnose folder and get a structured, tabbed report across device identity, MDM declarations, configuration profiles, settings attribution, troubleshooting log queries, and file access — without manually digging through hundreds of files.

> **Screenshots:** place your own captures in `docs/screenshots/` matching the filenames referenced below. Each `![…](docs/screenshots/…)` tag will render automatically in GitHub and any standard markdown viewer.

---

## System Requirements

- **macOS** 12 (Monterey) or later — required to read `.logarchive` files via `/usr/bin/log`
- **Python 3.9 or later** — check with `python3 --version`
- **~500 MB free disk space** — sysdiagnose archives are extracted to a temp directory during analysis

> The app is designed to run on macOS. The Troubleshooting log-query features require `/usr/bin/log`, which is only available on macOS. All other tabs work on any platform, but log-dependent fields will be empty.

---

## Installation

```bash
# 1. Clone or download the repository
git clone https://github.com/your-org/sysdiagnose-analyzer.git
cd sysdiagnose-analyzer/SydiagnoseAnalyzer-py

# 2. Install dependencies
pip3 install -r requirements.txt

# 3. Start the app
python3 app.py
```

Then open **http://localhost:5001** in your browser.

A convenience launcher is also included:

```bash
bash run.sh
```

This checks for Python 3, installs Flask if needed, and starts the server. Press `Ctrl+C` to stop.

---

## Upload Page

Drop a sysdiagnose archive (`.tar.gz`) or an already-extracted folder onto the upload area, then click **Analyze**. The app auto-detects whether the archive is from a macOS or iOS/iPadOS device and renders the appropriate tabs.

![Upload page](docs/screenshots/00-upload.png)

The app extracts the archive to a temporary directory, parses all relevant files, and renders a tabbed report. The temp directory is kept alive until the next analysis so the Troubleshooting tab can query the logarchive.

---

## Tabs Overview

The tab bar stays **fixed at the top** as you scroll through any tab. Tabs shown depend on the platform and what was found in the archive:

**macOS:** 💻 Device → 📋 Declarations → 🔒 Config Profiles → 🔍 Troubleshooting → 📁 Files → ⚠️ Notes

**iOS/iPadOS:** 📱 Device → 📋 Declarations → 🔒 Config Profiles → 🗂 Settings → 🔍 Troubleshooting → 📁 Files → ⚠️ Notes

Each tab is only shown if relevant data was found in the archive (e.g. Config Profiles is hidden when no profile data exists).

---

## 💻 / 📱 Device Tab

![Device tab — macOS](docs/screenshots/01-device.png)
![Device tab — iOS](docs/screenshots/01-device-ios.png)

**What it's for:** Hardware identity, OS version, and enrollment or managed settings summary. The layout adapts to the archive platform.

### macOS — Device Information Card

| Field | Source |
|---|---|
| Serial Number | `ioreg/IODeviceTree.txt` — `"IOPlatformSerialNumber"` |
| Model Identifier | `ioreg/IODeviceTree.txt` — `"model"` |
| Model Number | `SystemProfiler/SPHardwareDataType.spx` — `model_number` |
| Model Name | `SystemProfiler/SPHardwareDataType.spx` — `machine_name` |
| Hostname | `logs/hostname.txt` — last `#`-delimited segment |
| OS Version | `sw_vers.txt` — `ProductVersion` |
| OS Marketing Name | Derived from `ProductVersion` via a version-to-name lookup table (e.g. `14.x → macOS Sonoma`). Not sourced from `install.log`, which can contain pending-update names. |
| Build Number | `sw_vers.txt` — `BuildVersion`. When a Rapid Security Response (RSR) is installed, `ProductVersionExtra` is also present; `BuildVersion` then maps to `supplemental.build-version`. |
| RSR Extra Version | `sw_vers.txt` — `ProductVersionExtra` (e.g. `(a)`). Only present when an RSR is installed. |
| OS Family | `sw_vers.txt` — `ProductName` |
| Device Family | `remotectl_dumpstate.txt` — `DeviceClass` |
| UDID | `remotectl_dumpstate.txt` — `UniqueDeviceID` (preferred); falls back to `"IOPlatformUUID"` in `IODeviceTree.txt` |

### macOS — Managed Settings Card

Extracted by scanning installed configuration profile payloads. Three categories are detected:

| Category | Profile Domain | What it shows |
|---|---|---|
| Managed Notifications | `com.apple.notificationsettings` | Bundle IDs with managed notification settings |
| PPPC (Privacy / TCC) | `com.apple.TCC.configuration-profile-policy` | App identifiers with managed privacy permissions |
| Managed Login Items | `com.apple.servicemanagement` | Login item rules with their comment labels |

### iOS/iPadOS — Device Information Card

Identity parsed from multiple sources in priority order:

| Field | Source |
|---|---|
| OS Version / Marketing Name | `logs/SystemVersion/SystemVersion.plist` — `ProductVersion` (preferred); falls back to `remotectl_dumpstate.txt`. Marketing name derived from version + device class (e.g. iPad → "iPadOS 18.3.2"). |
| Build Number | `logs/SystemVersion/SystemVersion.plist` — `ProductBuildVersion` |
| OS Family | Derived from `DeviceClass` — iPad → "iPadOS", iPhone → "iOS" |
| Serial Number | `remotectl_dumpstate.txt` — `SerialNumber`; falls back to `IODeviceTree.txt` |
| UDID | `remotectl_dumpstate.txt` — `UniqueDeviceID`; falls back to `IODeviceTree.txt` |
| Model Identifier | `remotectl_dumpstate.txt` — `ProductType` |
| Model Number | `remotectl_dumpstate.txt` — `ModelNumber` |
| Device Class | `remotectl_dumpstate.txt` — `DeviceClass` |
| Supervised | `logs/MCState/Shared/CloudConfigurationDetails.plist` — `IsSupervised` |
| Return to Service | `logs/MCState/Shared/CloudConfigurationDetails.plist` — `IsReturnToService` |

### iOS/iPadOS — Enrollment Information Card

Parsed from `logs/MCState/Shared/MDM.plist`:

| Field | Key |
|---|---|
| MDM Profile Identifier | `ManagingProfileIdentifier` |
| MDM Server URL | `ServerURL` |
| ADE Enrollment | `IsADEProfile` |
| APNs Topic | `Topic` |

### iOS/iPadOS — Managed Apps

Parsed from `logs/MCState/Shared/MDMAppManagement.plist`. Shows all MDM-managed apps with bundle ID, decoded state (Managed, Pending Install, etc.), flags bitmask (VPP, Remove on Unenrollment, etc.), and removability.

---

## 📋 Declarations Tab

![Declarations tab — Blueprints section](docs/screenshots/02-declarations-blueprints.png)
![Declarations tab — Status Key Paths section](docs/screenshots/02-declarations-status.png)

**What it's for:** MDM Declarative Device Management state. Use this tab to verify which Blueprints and declarations are active, identify inactive or invalid declarations, and inspect the last-known value of every MDM status key path.

Parsed from `logs/rmd/rmd_inspect_system.txt` (macOS) or the equivalent path on iOS, using a custom ASCII/NeXTSTEP plist parser.

### Blueprint Declarations

Blueprint UUIDs are extracted from activation and configuration identifiers. Entries are grouped by Blueprint UUID. Rows with identical error signatures within a Blueprint are collapsed into `×N` entries to reduce noise.

| Column | Source |
|---|---|
| Blueprint UUID | Extracted from identifier strings (`Blueprint_<UUID>_...`) |
| Declaration Type | `declarationType` |
| Activations | `state.active` (normalized — handles both string `"1"` from plutil and integer `1` from the Python parser); inactive reasons from `state.inactiveReasons[].code` |
| Configurations | Same active/inactive normalization as Activations |
| Status | `active`, `valid`, `reasons[].code` from the channel Status section |

> **Note on active/inactive display:** macOS `plutil -convert json` returns string `"1"` for unquoted numeric values in old-style ASCII plists. The app normalizes both `"1"` (string), `1` (int), and `True` (bool) as active.

### System Configurations

Standalone activations and configurations not associated with a Blueprint UUID.

### Status Key Paths

A table of every MDM-subscribed status key path with its current sync state and last known value. Values from the `.logarchive` are shown without annotation; values inferred from static files are marked `*`.

- **Key Path** column is fixed-width (no wrapping) so long paths don't push the layout.
- **Last Value** column wraps on long entries (e.g. `softwareupdate.failure-reason`) so the Log Stream button remains accessible.
- **Log Stream** button opens a new tab with a live filtered view of the `.logarchive` for that specific key path.

#### Status values from `system_logs.logarchive`

Extracted by querying the archive with `/usr/bin/log show` and parsing the last `Reporting status {…}` block from `SoftwareUpdateSubscriber`.

| Key Path | Parsed field |
|---|---|
| `softwareupdate.install-state` | `install-state` |
| `softwareupdate.install-reason` | `install-reason` / `reason` array |
| `softwareupdate.pending-version` | `pending-version` |
| `softwareupdate.failure-reason` | `failure-reason` |
| `softwareupdate.device-id` | `device-id` |

#### Status values from static files (marked `*`)

| Key Path | Source file | Field |
|---|---|---|
| `device.identifier.serial-number` | `ioreg/IODeviceTree.txt` | `"IOPlatformSerialNumber"` |
| `device.identifier.udid` | `remotectl_dumpstate.txt` | `UniqueDeviceID` |
| `device.model.identifier` | `ioreg/IODeviceTree.txt` | `"model"` |
| `device.model.number` | `SystemProfiler/SPHardwareDataType.spx` | `model_number` |
| `device.model.marketing-name` | `SystemProfiler/SPHardwareDataType.spx` | `machine_name` |
| `device.model.family` | `remotectl_dumpstate.txt` | `DeviceClass` |
| `device.operating-system.version` | `sw_vers.txt` | `ProductVersion` |
| `device.operating-system.build-version` | `sw_vers.txt` | `BuildVersion` (no RSR) |
| `device.operating-system.supplemental.build-version` | `sw_vers.txt` | `BuildVersion` (RSR installed) |
| `device.operating-system.supplemental.extra-version` | `sw_vers.txt` | `ProductVersionExtra` (RSR only) |
| `device.operating-system.family` | `sw_vers.txt` | `ProductName` |
| `device.operating-system.marketing-name` | `sw_vers.txt` | Derived from `ProductVersion` via version table |
| `softwareupdate.beta-enrollment` | `logs/install.log` | Last `BetaUpdatesManager` line |
| `diskmanagement.filevault.enabled` | `disks.txt` | First `FileVault: Yes/No` line |

#### Key paths with no static source

The following represent live MDM channel state only logged during active reporting cycles. If the archive predates a sync cycle, these fields will be blank:

`management.declarations` · `management.client-capabilities` · `security.certificate.list` · `services.background-task` · `package.list` · `app.managed.list` · `screensharing.connection.group.unresolved-connection`

---

## 🔒 Config Profiles Tab

![Config Profiles tab](docs/screenshots/03-config-profiles.png)

**What it's for:** Every installed configuration profile on the device at the time the sysdiagnose was captured.

**macOS** — Parsed from `SystemProfiler/SPConfigurationProfileDataType.spx` (binary plist). Each profile shows name, identifier, organization, install date, and expandable payload rows with raw plist content.

**iOS/iPadOS** — Parsed from `logs/MCState/Shared/PayloadManifest.plist` (for install order) and the corresponding `profile-<hash>.stub` binary plist files (one per installed profile). Profiles are listed in manifest order. Each expandable row shows payload type and a JSON rendering of the payload's non-metadata keys.

---

## 🗂 Settings Tab *(iOS/iPadOS only)*

![Settings attribution tab](docs/screenshots/06-settings.png)

**What it's for:** Attribute every managed `restrictedBool` key in `UserSettings.plist` to its actual source — a configuration profile, a DDM declaration, or the device's own default. This tab is only shown for iOS/iPadOS archives and only when `MCSettingsEvents.plist` is present.

### How attribution works

iOS's restriction manager writes to `logs/MCState/Shared/MCSettingsEvents.plist`. The `Restrictions.restrictedBool` section within that file **only contains keys that were explicitly set** — either by a configuration profile or a DDM declaration. Keys absent from this section are device defaults that have never been explicitly managed.

Each entry's `process` field identifies the source:

| Process value | Interpretation |
|---|---|
| Starts with a profile UUID | The restriction was set by that configuration profile |
| `MSRestrictionManagerWriter.applyRestrictionDictionary` | Set by a DDM Restrictions declaration |
| Other DDM process name (e.g. `com.apple.remotemanagement.PasscodeSettingsSubscriber`) | Set by another DDM declaration type (e.g. Passcode) |

> **Why not use `EffectiveSettings`?** `EffectiveSettings` is a merged cache that stamps a timestamp on every restriction key whenever the restriction manager runs — including keys that simply haven't changed. It cannot distinguish "explicitly set by a declaration" from "device default that was just recalculated." Only `Restrictions` contains the definitive explicit-set list.

### Implicit MDM baseline

When a key is attributed to a configuration profile but that profile has **no `com.apple.applicationaccess` payload**, the key is flagged as an **implicit MDM baseline**. This means iOS enforced the restriction automatically as part of device management enrollment — it is not something you would find in the profile's server-side payload configuration. In the detail column, implicit keys appear as *ProfileName (implicit MDM baseline)* with an explanatory tooltip.

### UI controls

- **Filter pills** — narrow the table to Profile, Declaration, or Default keys, or view all at once.
- **Search field** — live filter by key name (e.g. type `safari` to find all Safari-related restrictions).
- **Summary row** — shows total key count and a breakdown of how many came from each source.

### Source files

| File | Purpose |
|---|---|
| `logs/MCState/Shared/UserSettings.plist` | Canonical list of all active `restrictedBool` keys and their current effective values |
| `logs/MCState/Shared/MCSettingsEvents.plist` | `Restrictions.restrictedBool` — only explicitly set keys, with source process and timestamp |
| `logs/MCState/Shared/profile-<hash>.stub` | Per-profile binary plists — used to resolve profile UUID → display name and to detect whether the profile has a Restrictions payload |

---

## 🔍 Troubleshooting Tab

![Troubleshooting tab — category and topic selected](docs/screenshots/04-troubleshooting.png)
![Troubleshooting tab — Show Filter revealed](docs/screenshots/04-troubleshooting-filter.png)

**What it's for:** Run predefined `log show` queries against the sysdiagnose logarchive and view the output directly in the browser. Useful for quickly investigating Jamf, MDM, enrollment, networking, authentication, and security events without needing to open Console.app or write predicates manually.

### How to use

1. Choose a **Category** from the first dropdown — this filters which topics are available.
2. Choose a **Topic** from the second dropdown — the query runs immediately using the default **Last 1 Day** timeframe.
3. Adjust the **Timeframe** selector to Last 7 Days or All Time if needed.
4. Results appear as a scrollable, zebra-striped list. Timestamps are dimmed so the log message content stands out.
5. Click **Show Filter** (top right of the toolbar) to reveal the full `log show` command that was executed.
6. Use **Export** to save the current results to a `.log` file via a native macOS save dialog.

Results are capped at 2,000 lines (most recent); a count badge is shown below the output.

### Custom queries

Select the **Custom** category to run an ad-hoc predicate against the logarchive without leaving the browser:

- **Subsystem** — filters by `subsystem CONTAINS "<value>"` with `--info`. Start typing a subsystem identifier (e.g. `com.jamf.connect`) and press Enter or click away to run.
- **Process** — filters by `process CONTAINS "<value>"` with `--style compact`. Type a process name (e.g. `mdmclient`) and press Enter or click away to run.

The Topic dropdown transforms in-place into a text field when Subsystem or Process is selected.

### Available Categories and Topics

All categories and topics are alphabetically sorted in their respective dropdowns.

| Category | Topics |
|---|---|
| **App Installation and Packages** | App Store / StoreKit installs · Installer / package activity · LaunchDaemon / LaunchAgent loading |
| **Authentication and Identity** | Kerberos / Active Directory auth · Local authentication / PAM · Platform SSO (PSSO) activity |
| **Device Compliance** | Device Compliance |
| **Enrollment, Automated Device Enrollment, & DEP** | Automated Device Enrollment (ADE) activity · Profile installation and removal · Setup Assistant / enrollment flow |
| **Jamf Connect** | Daemon Elevation · Login Window · Menu Bar · Menu Bar Elevation |
| **Jamf Pro** | All Jamf Activity · MDM Client · MDM command processing and device enrollment · MDM daemon activity (enrollment, commands, profiles) |
| **Jamf Remote Assist** | Jamf Remote Assist |
| **Jamf Self Service Plus** | Self Service Plus |
| **Networking** | DNS resolution issues · General network diagnostics · Wi-Fi association and connectivity |
| **Security & Gatekeeper** | Gatekeeper / code signing checks · TCC (Transparency, Consent, and Control) — privacy permissions · XProtect malware scanning |
| **Software Updates** | DDM / Declarative Device Management update commands · SoftwareUpdate · SoftwareUpdate Daemon |
| **System and Kernel Extensions** | Endpoint security framework · System extension approvals/activations |
| **Custom** | Subsystem · Process |

---

## 📁 Files Tab

![Files tab](docs/screenshots/05-files.png)

**What it's for:** Quick access to the most useful files inside the sysdiagnose archive. Click **Open** on any file to open it directly in its default macOS application (e.g. `install.log` in Console, `.spx` files in Xcode, `.logarchive` in Console.app).

Files are grouped by category in a two-column layout that balances card heights automatically. **Categories with zero found files are hidden entirely**; individual files not present in the archive are also hidden (no "not in archive" badges). The file list adapts to the archive platform.

### macOS file groups

| Group | Files |
|---|---|
| **OS & Software** | `install.log` · `InstallHistory.plist` · `sw_vers.txt` |
| **Device & Hardware** | `remotectl_dumpstate.txt` · `IODeviceTree.txt` · `SPHardwareDataType.spx` |
| **MDM & Management** | `rmd_inspect_system.txt` · `rmd_inspect_user.txt` · `SPConfigurationProfileDataType.spx` |
| **Storage & Security** | `disks.txt` · `diskutil_list.txt` |
| **Logs & Diagnostics** | `system_logs.logarchive` · `DiagnosticMessages.log` |
| **Network** | `ifconfig.txt` · `netstat.txt` · `wifi_status.txt` |
| **Processes & Performance** | `ps.txt` · `spindump.txt` |

### iOS/iPadOS file groups

| Group | Files |
|---|---|
| **OS & Software** | `SystemVersion.plist` |
| **Device & Hardware** | `remotectl_dumpstate.txt` · `IODeviceTree.txt` |
| **MDM & Management** | `rmd_inspect_system.txt` · `rmd_inspect_user.txt` · `CloudConfigurationDetails.plist` · `MDM.plist` · `MDMAppManagement.plist` |
| **Logs & Diagnostics** | `system_logs.logarchive` · `DiagnosticMessages.log` |
| **Network** | `ifconfig.txt` · `netstat.txt` · `wifi_status.txt` |
| **Processes & Performance** | `ps.txt` · `spindump.txt` |

> `system_logs.logarchive` is a directory bundle — the app uses a directory-aware finder so it is detected correctly even though it is not a plain file.

---

## ⚠️ Notes Tab

Any processing notes generated during analysis (e.g. missing files, parse warnings) are shown here. This tab only appears when there is something to report.

---

## File Structure

```
SydiagnoseAnalyzer-py/
├── app.py                    # Flask app — all parsing logic and routes
├── run.sh                    # Convenience launcher
├── requirements.txt          # Python dependencies (Flask)
├── templates/
│   ├── index.html            # Upload / landing page
│   └── results.html          # Analysis results (tabbed UI)
├── docs/
│   └── screenshots/          # Place tab screenshots here (see filenames above)
└── README.md                 # This file
```

---

## Routes

| Route | Method | Description |
|---|---|---|
| `/` | GET | Upload page |
| `/analyze` | POST | Accepts archive upload or path, auto-detects platform, runs analysis, renders results |
| `/troubleshoot-log` | GET | Runs a predefined or custom `log show` query; returns JSON `{lines, count, command}` |
| `/log-stream` | GET | Filtered logarchive view for a specific status key path; opens in a new tab |
| `/export-log` | POST | Writes log output to a file via a native macOS save dialog; accepts JSON `{lines, filename}` |
| `/open-file` | GET | Opens a sysdiagnose file in its default macOS application via `open` |
| `/debug` | GET | Debug view showing raw parsed values and file inventory (dev use) |

---

## Technical Notes

- **Platform detection** — `is_mobile_sysdiagnose()` checks for the presence of `sw_vers.txt` (macOS) vs. `SystemVersion.plist` with `ProductName` containing "iPhone" or "iPad" (iOS/iPadOS). The detected platform controls which parsers run and which tab set is rendered.
- **Archive extraction** — `.tar.gz` archives are extracted to macOS's temp directory (`/tmp`). The temp directory is kept alive until the next analysis so the Troubleshooting tab and Log Stream links can still reach the logarchive. Cleanup happens automatically at the start of the next analysis.
- **Plist parsing** — `rmd_inspect_system.txt` uses Apple's ASCII/NeXTSTEP plist format. The app includes a custom recursive-descent `_AsciiPlistParser`. It also tries `plutil -convert json` as a first pass; because `plutil` returns string `"1"` (not integer `1`) for unquoted numeric values in this format, active/inactive state is normalized via `_norm_active()` before comparison.
- **iOS profile stubs** — Profiles are stored as `profile-<sha256>.stub` binary plists in `logs/MCState/Shared/`. Filenames use SHA-256 hashes rather than UUIDs; the `PayloadUUID` inside each stub is used for cross-referencing.
- **Settings attribution signal** — Only `MCSettingsEvents.Restrictions.restrictedBool` is used to identify explicitly set restrictions. `EffectiveSettings` is intentionally ignored because it timestamps every key on each recompute cycle, making it impossible to distinguish DDM-set keys from device defaults by timestamp alone.
- **Implicit MDM baseline detection** — A profile-attributed key is flagged implicit when the profile's stub contains no `com.apple.applicationaccess` payload, indicating iOS enforced the restriction automatically as part of enrollment rather than via an explicit Restrictions payload.
- **RSR detection** — If `ProductVersionExtra` is present in `sw_vers.txt`, a Rapid Security Response is installed; `BuildVersion` is then mapped to `supplemental.build-version` instead of the standard OS build-version key path.
- **Marketing name** — Derived from `ProductVersion` using a static lookup table (`_MACOS_NAMES` / `_IOS_VERSION_NAMES`), not from `install.log`. This prevents pending-update names from appearing as the installed version.
- **No data leaves the device.** Everything runs locally on `localhost:5001`.
