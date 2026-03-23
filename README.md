# Sysdiagnose Analyzer

A local Flask web application for macOS support staff to quickly analyze Apple sysdiagnose archives. Drop in a `.tar.gz` or an extracted sysdiagnose folder and get a structured report across device identity, OS update status, MDM declarations, configuration profiles, and managed settings — without manually digging through hundreds of files.

---

## System Requirements

- **macOS** 12 (Monterey) or later — required to read `.logarchive` files via `/usr/bin/log`
- **Python 3.9 or later** — check with `python3 --version`
- **~500 MB free disk space** — sysdiagnose archives are extracted to a temp directory during analysis

> The app is designed to run on macOS. The logarchive parsing features (`softwareupdate.*` status key path values and log stream output) require `/usr/bin/log`, which is only available on macOS. The rest of the app will function on other platforms but those fields will be empty.

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

To stop the server, press `Ctrl+C` in the terminal.

A convenience launcher script is also included:

```bash
bash run.sh
```

This checks for Python 3, installs Flask if needed, and starts the server.

---

## How It Works

Drag and drop a sysdiagnose archive (`.tar.gz`) or an already-extracted sysdiagnose folder onto the upload area. The app extracts the archive to a temporary directory, parses the relevant files, and renders a structured report with five tabs.

### Device Information

A summary card at the top of the first tab showing hardware and OS identity pulled from static files in the archive. A second card below it shows managed settings extracted from installed configuration profiles.

### OS Updates

Two sections:

**Software Update Status Key Paths** — a table of every MDM-subscribed status key path reported by the device, including its current sync state (✓ synced / ✕ needs sync) and last known value. Values sourced directly from the `.logarchive` are shown as-is. Values inferred from static files are marked with `*`. A Log Stream button opens a live filtered view of the `.logarchive` for that specific key path.

**Software Update Logs** — a scrollable view of the raw `install.log` entries related to software updates, useful for tracing update history and failure reasons.

### Declarations

A table of all MDM Blueprint declarations found in `rmd_inspect_system.txt`, grouped by Blueprint UUID. Each row shows the declaration type, active/inactive state, server token, and any error codes. Identical error signatures within a Blueprint are collapsed into a single `×N` row to reduce noise.

### Configuration Profiles

Every installed configuration profile with its metadata (identifier, organization, UUID, install date) shown in always-expanded cards. Each payload within a profile is an expandable row showing the payload domain and its raw plist data.

### Notes

A free-text field for adding notes about the analysis, scoped to the current session.

---

## Where Values Come From

This section documents the source file and field for every piece of data the app displays. Understanding the sources helps when a value is missing or unexpected.

---

### Device Information Card

| Field | Source File | Key / Method |
|---|---|---|
| Serial Number | `ioreg/IODeviceTree.txt` | `"IOPlatformSerialNumber"` |
| Model Identifier | `ioreg/IODeviceTree.txt` | `"model"` (angle-bracket value) |
| Model Number | `SystemProfiler/SPHardwareDataType.spx` | `model_number` (binary plist) |
| Hostname | `logs/hostname.txt` | Last `#`-delimited segment |
| OS Version | `sw_vers.txt` | `ProductVersion` |
| Build Number | `sw_vers.txt` | `BuildVersion` |
| Model Name | `SystemProfiler/SPHardwareDataType.spx` | `machine_name` (binary plist) |

---

### Status Key Paths — Last Value column

Values are sourced from two places and merged. The logarchive takes precedence when a value is available there. Static-file values are marked with `*` to indicate they are inferred rather than directly reported through the MDM channel.

#### Values from `system_logs.logarchive` (no asterisk)

These are extracted by querying the archive with `/usr/bin/log show` and parsing the last `Reporting status {…}` block emitted by `SoftwareUpdateSubscriber`.

| Key Path | Parsed Field |
|---|---|
| `softwareupdate.install-state` | `install-state` |
| `softwareupdate.install-reason` | `install-reason` / `reason` array |
| `softwareupdate.pending-version` | `pending-version` (dict → "version (build)") |
| `softwareupdate.failure-reason` | `failure-reason` (dict → "count = N") |
| `softwareupdate.device-id` | `device-id` |

#### Values from static files (marked `*`)

| Key Path | Source File | Field / Method |
|---|---|---|
| `device.identifier.serial-number` | `ioreg/IODeviceTree.txt` | `"IOPlatformSerialNumber"` |
| `device.identifier.udid` | `remotectl_dumpstate.txt` | `UniqueDeviceID` (preferred); falls back to `"IOPlatformUUID"` in `IODeviceTree.txt` |
| `device.model.identifier` | `ioreg/IODeviceTree.txt` | `"model"` |
| `device.model.number` | `SystemProfiler/SPHardwareDataType.spx` | `model_number` |
| `device.model.marketing-name` | `SystemProfiler/SPHardwareDataType.spx` | `machine_name` |
| `device.model.family` | `remotectl_dumpstate.txt` | `DeviceClass` |
| `device.operating-system.version` | `sw_vers.txt` | `ProductVersion` |
| `device.operating-system.build-version` | `sw_vers.txt` | `BuildVersion` |
| `device.operating-system.family` | `sw_vers.txt` | `ProductName` |
| `device.operating-system.supplemental.build-version` | `remotectl_dumpstate.txt` | `SupplementalBuildVersion` |
| `device.operating-system.marketing-name` | `logs/install.log` | Last `SU:macOS <Name> <version>` entry from `softwareupdated` |
| `device.operating-system.supplemental.extra-version` | `logs/install.log` | Build token from last `MSU_UPDATE_<token>_..._rsr` RSR product entry |
| `softwareupdate.beta-enrollment` | `logs/install.log` | Last `BetaUpdatesManager` line — "disabled" or enrolled program name |
| `diskmanagement.filevault.enabled` | `disks.txt` | First `FileVault: Yes/No` line (main data volume) |

#### Key paths with no static source

The following key paths represent live MDM channel state that macOS only logs to the `.logarchive` during active reporting cycles. If the archive does not contain a matching `Reporting status` block (e.g. the sysdiagnose was captured between sync cycles), these fields will be blank.

- `management.declarations`
- `management.client-capabilities`
- `security.certificate.list`
- `services.background-task`
- `package.list`
- `app.managed.list`
- `screensharing.connection.group.unresolved-connection`

---

### Declarations

Parsed from `logs/rmd/rmd_inspect_system.txt`, which is the output of `rmd inspect system` captured at sysdiagnose collection time.

The file is an Apple ASCII plist (NeXTSTEP format) parsed by a custom recursive-descent parser built into the app. Blueprint UUIDs are extracted from activation and configuration identifiers. Multiple entries sharing a UUID are grouped, and rows with identical error signatures are collapsed into `×N` entries.

| Field | Source |
|---|---|
| Blueprint UUID | Extracted from identifier strings (`Blueprint_<UUID>_...`) |
| Declaration Type | `declarationType` field |
| Active / Inactive | `state.active` field; inactive reasons from `state.inactiveReasons[].code` |
| Server Token | `serverToken` field |
| Status (from Status block) | `active`, `valid`, `reasons[].code` fields in the channel Status section |

---

### Configuration Profiles

Parsed from `SystemProfiler/SPConfigurationProfileDataType.spx` — a binary plist captured by System Profiler at sysdiagnose collection time.

Structure: `d[0]["_items"][0]["_items"]` — each entry is one installed profile.

| Field | Source Key |
|---|---|
| Profile Name | `_name` |
| Identifier | `spconfigprofile_identifier` |
| Organization | `spconfigprofile_organization` |
| UUID | `spconfigprofile_uuid` |
| Install Date | `spconfigprofile_install_date` |
| Payload Domain | `spconfigprofile_domain` (per payload item) |
| Payload Data | `spconfigprofile_payload_data` (raw plist string) |

---

### Managed Settings (Device tab)

Extracted by scanning all configuration profile payload data strings through the same ASCII plist parser. Three categories are detected:

| Category | Profile Domain | Extracted Field |
|---|---|---|
| Managed Notifications | `com.apple.notificationsettings` | `BundleIdentifier` per app entry |
| PPPC (Privacy / TCC) | `com.apple.TCC.configuration-profile-policy` | `Identifier` per service entry |
| Managed Login Items | `com.apple.servicemanagement` | `Comment` per rule entry |

---

## File Structure

```
SydiagnoseAnalyzer-py/
├── app.py                  # Flask app — all parsing logic and routes
├── run.sh                  # Convenience launcher
├── requirements.txt        # Python dependencies (Flask)
├── templates/
│   ├── index.html          # Upload / landing page
│   └── results.html        # Analysis results (tabbed UI)
└── README.md               # This file
```

---

## Notes

- Sysdiagnose archives are extracted to macOS's temp directory (`/tmp`) during analysis. The temp directory is kept alive until the next analysis is run (to allow log stream access after the results page loads) and then cleaned up automatically.
- The log stream feature (`/log-stream` route) calls `/usr/bin/log show` live against the extracted archive and streams output back to the browser. It requires the temp directory to still be present, which is why cleanup is deferred.
- No data is sent off-device. Everything runs locally.
