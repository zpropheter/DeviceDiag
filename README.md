# Sysdiagnose Analyzer

A local Flask web application for macOS support staff to analyze Apple sysdiagnose archives. Drop in a `.tar.gz` or an extracted sysdiagnose folder and get a structured, tabbed report across device identity, MDM declarations, configuration profiles, troubleshooting log queries, and file access — without manually digging through hundreds of files.

> **Screenshots:** place your own captures in `docs/screenshots/` matching the filenames referenced below. Each `![…](docs/screenshots/…)` tag will render automatically in GitHub and any standard markdown viewer.

---

## System Requirements

- **macOS** 12 (Monterey) or later — required to read `.logarchive` files via `/usr/bin/log`
- **Python 3.9 or later** — check with `python3 --version`
- **~500 MB free disk space** — sysdiagnose archives are extracted to a temp directory during analysis

> The app is designed to run on macOS. The Troubleshooting log-query features require `/usr/bin/log`, which is only available on macOS. All other tabs will work on any platform, but log-dependent fields will be empty.

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

Drop a sysdiagnose archive (`.tar.gz`) or an already-extracted folder onto the upload area, then click **Analyze**.

![Upload page](docs/screenshots/00-upload.png)

The app extracts the archive to a temporary directory, parses all relevant files, and renders a tabbed report. The temp directory is kept alive until the next analysis so the Troubleshooting tab can query the logarchive.

---

## Tabs Overview

The tab bar stays **fixed at the top** as you scroll through any tab. Tabs are ordered:

**💻 Device → 📋 Declarations → 🔒 Config Profiles → 🔍 Troubleshooting → 📁 Files → ⚠️ Notes**

---

## 💻 Device Tab

![Device tab](docs/screenshots/01-device.png)

**What it's for:** Hardware identity, OS version, and a summary of applied managed settings. This is the first place to check when you need to confirm what device and OS you're looking at, verify UDID/serial number, or quickly see which privacy and notification policies are in effect.

### Device Information Card

A summary of hardware and OS identity pulled from static files in the archive.

| Field | Source |
|---|---|
| Serial Number | `ioreg/IODeviceTree.txt` — `"IOPlatformSerialNumber"` |
| Model Identifier | `ioreg/IODeviceTree.txt` — `"model"` |
| Model Number | `SystemProfiler/SPHardwareDataType.spx` — `model_number` |
| Model Name | `SystemProfiler/SPHardwareDataType.spx` — `machine_name` |
| Hostname | `logs/hostname.txt` — last `#`-delimited segment |
| OS Version | `sw_vers.txt` — `ProductVersion` |
| OS Marketing Name | Derived from `ProductVersion` via a version-to-name lookup table (e.g. `14.x → macOS Sonoma`). Not sourced from install.log, which can contain pending-update names. |
| Build Number | `sw_vers.txt` — `BuildVersion`. When a Rapid Security Response (RSR) is installed, `ProductVersionExtra` is also present; in that case `BuildVersion` maps to `device.operating-system.supplemental.build-version` instead. |
| RSR Extra Version | `sw_vers.txt` — `ProductVersionExtra` (e.g. `(a)`). Only present when an RSR is installed. |
| OS Family | `sw_vers.txt` — `ProductName` |
| Device Family | `remotectl_dumpstate.txt` — `DeviceClass` |
| UDID | `remotectl_dumpstate.txt` — `UniqueDeviceID` (preferred); falls back to `"IOPlatformUUID"` in `IODeviceTree.txt` |

### Managed Settings Card

Extracted by scanning installed configuration profile payloads. Three categories are detected:

| Category | Profile Domain | What it shows |
|---|---|---|
| Managed Notifications | `com.apple.notificationsettings` | Bundle IDs with managed notification settings |
| PPPC (Privacy / TCC) | `com.apple.TCC.configuration-profile-policy` | App identifiers with managed privacy permissions |
| Managed Login Items | `com.apple.servicemanagement` | Login item rules with their comment labels |

---

## 📋 Declarations Tab

![Declarations tab — Blueprints section](docs/screenshots/02-declarations-blueprints.png)
![Declarations tab — Status Key Paths section](docs/screenshots/02-declarations-status.png)

**What it's for:** MDM Declaration-based management state. Use this tab to verify which Blueprints and declarations are active, identify inactive or invalid declarations, and inspect the last-known value of every MDM status key path.

### Blueprint Declarations

Parsed from `logs/rmd/rmd_inspect_system.txt` using a custom ASCII/NeXTSTEP plist parser. Blueprint UUIDs are extracted from activation and configuration identifiers. Entries are grouped by Blueprint UUID. Rows with identical error signatures within a Blueprint are collapsed into `×N` entries to reduce noise.

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

**What it's for:** Every installed configuration profile on the device at the time the sysdiagnose was captured. Use this tab to verify profile presence, check identifiers and UUIDs, confirm install dates, and inspect individual payload data.

Parsed from `SystemProfiler/SPConfigurationProfileDataType.spx` (binary plist).

Each profile is shown as an always-expanded card. Within each card, every payload is an expandable row showing the domain and its raw plist content.

| Field | Source key |
|---|---|
| Profile Name | `_name` |
| Identifier | `spconfigprofile_identifier` |
| Organization | `spconfigprofile_organization` |
| UUID | `spconfigprofile_uuid` |
| Install Date | `spconfigprofile_install_date` |
| Payload Domain | `spconfigprofile_domain` |
| Payload Data | `spconfigprofile_payload_data` |

---

## 🔍 Troubleshooting Tab

![Troubleshooting tab — category and topic selected](docs/screenshots/04-troubleshooting.png)
![Troubleshooting tab — Show Filter revealed](docs/screenshots/04-troubleshooting-filter.png)

**What it's for:** Run predefined `log show` queries against the sysdiagnose logarchive and view the output directly in the browser. Useful for quickly investigating Jamf, MDM, enrollment, networking, authentication, and security events without needing to open Console.app or write predicates manually.

### How to use

1. Choose a **Category** from the first dropdown — this filters which topics are available.
2. Choose a **Topic** from the second dropdown — the query runs immediately.
3. Results appear as a scrollable, zebra-striped list. Timestamps are dimmed so the log message content stands out.
4. Click **Show Filter** (top right of the toolbar) to reveal the full `log show` command that was executed.

All queries run as `log show --archive <logarchive> [flags] --predicate '…' --last 30d` against the extracted sysdiagnose logarchive. Results are capped at 2,000 lines (most recent); a count badge is shown below the output.

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

---

## 📁 Files Tab

![Files tab](docs/screenshots/05-files.png)

**What it's for:** Quick access to the most useful files inside the sysdiagnose archive. Instead of extracting and navigating the archive manually, click **Open** on any file to open it directly in its default macOS application (e.g. `install.log` in Console, `.spx` files in Xcode, `.logarchive` in Console.app).

Files are grouped by category in a two-column layout. Files present in the archive show an **Open** button; files not found show a "Not in archive" badge.

| Group | Files |
|---|---|
| **OS & Software** | `install.log` · `InstallHistory.plist` · `sw_vers.txt` |
| **MDM & Management** | `rmd_inspect_system.txt` · `SPConfigurationProfileDataType.spx` |
| **Logs & Diagnostics** | `system_logs.logarchive` · `DiagnosticMessages.log` |
| **Network** | `ifconfig.txt` · `netstat.txt` · `wifi_status.txt` |
| **Processes & Performance** | `ps.txt` · `spindump.txt` |
| **Storage & Security** | `disks.txt` · `diskutil_list.txt` |
| **Device & Hardware** | `remotectl_dumpstate.txt` · `IODeviceTree.txt` · `SPHardwareDataType.spx` |

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
| `/analyze` | POST | Accepts archive upload, runs analysis, renders results |
| `/troubleshoot-log` | GET | Runs a predefined `log show` query; returns JSON `{lines, count, command}` |
| `/log-stream` | GET | Streams a filtered logarchive view for a specific status key path |
| `/open-file` | GET | Opens a sysdiagnose file in its default macOS application via `open` |
| `/debug` | POST | Debug view showing raw parsed values (dev use) |

---

## Technical Notes

- **Archive extraction** — `.tar.gz` archives are extracted to macOS's temp directory (`/tmp`). The temp directory is kept alive until the next analysis so the Troubleshooting tab and Log Stream links can still reach the logarchive after the results page loads. Cleanup happens automatically at the start of the next analysis.
- **Plist parsing** — `rmd_inspect_system.txt` uses Apple's ASCII/NeXTSTEP plist format. The app includes a custom recursive-descent `_AsciiPlistParser`. It also tries `plutil -convert json` as a first pass; because `plutil` returns string `"1"` (not integer `1`) for unquoted numeric values in this format, active/inactive state is normalized via `_norm_active()` before comparison.
- **RSR detection** — `sw_vers.txt` is parsed into a dict before field mapping. If `ProductVersionExtra` is present, the device has a Rapid Security Response installed; `BuildVersion` is then mapped to the supplemental build-version key path instead of the standard build-version key path.
- **Marketing name** — Derived from `ProductVersion` using a static lookup table (`_MACOS_NAMES`), not from `install.log`. This prevents pending-update names from appearing as the installed version.
- **No data leaves the device.** Everything runs locally on `localhost:5001`.
