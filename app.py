#!/usr/bin/env python3
"""
Sysdiagnose Analyzer
Flask web app for analyzing macOS sysdiagnose archives.

Usage:
    python3 app.py
    Then open http://localhost:5001 in your browser.
"""

import os
import re
import json
import plistlib
import shutil
import tempfile
import subprocess
from pathlib import Path
from datetime import datetime
from typing import Optional

from flask import Flask, render_template, request

app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = 10 * 1024 * 1024 * 1024  # 10 GB

# Temp directories from the most recent successful analysis.
# Kept alive so /log-stream can still reach the logarchive after the results
# page has been returned.  Cleaned up at the start of the next analysis.
_last_tmp_dirs: list = []



# =============================================================================
# File Location Helpers
# =============================================================================

def find_sydiagnose_root(path: str) -> Path:
    p = Path(path)
    if not p.is_dir():
        return p
    subdirs = [d for d in p.iterdir() if d.is_dir()]
    if len(subdirs) == 1:
        name = subdirs[0].name.lower()
        if "sysdiagnose" in name or "sydiagnose" in name:
            return subdirs[0]
    return p


def find_file(root: Path, name: str) -> Optional[Path]:
    for p in root.rglob(name):
        if p.is_file():
            return p
    return None


def find_path(root: Path, name: str) -> Optional[Path]:
    """Like find_file but also matches directories (e.g. .logarchive bundles)."""
    for p in root.rglob(name):
        if p.is_file() or p.is_dir():
            return p
    return None


def find_logarchive(root: Path) -> Optional[Path]:
    for p in root.rglob("*.logarchive"):
        if p.is_dir() or p.is_file():
            return p
    return None


def safe_read(path: Path) -> str:
    try:
        return path.read_text(errors="ignore")
    except Exception:
        return ""


def safe_plist(path: Path):
    try:
        return plistlib.loads(path.read_bytes())
    except Exception:
        return None


# =============================================================================
# Device Info Parser
# =============================================================================

def parse_device_info(root: Path) -> dict:
    info = {
        "serial_number":    "Not found",
        "os_version":       "Not found",
        "build_number":     "Not found",
        "model_name":       "Not found",
        "model_identifier": "Not found",
        "hostname":         "Not found",
    }

    # sw_vers.txt
    for fname in ("sw_vers.txt", "sw_vers"):
        f = find_file(root, fname)
        if f:
            for line in safe_read(f).splitlines():
                if ":" not in line:
                    continue
                key, _, val = line.partition(":")
                key, val = key.strip(), val.strip()
                if key == "ProductVersion":
                    info["os_version"] = val
                elif key == "BuildVersion":
                    info["build_number"] = val
            break

    # Hardware text files
    for fname in ("hardware_overview.txt", "system_profiler.txt", "SPHardwareDataType.txt"):
        f = find_file(root, fname)
        if f:
            _parse_hardware_text(safe_read(f), info)
            if info["serial_number"] != "Not found":
                break

    # Hardware .spx plist fallback
    if info["serial_number"] == "Not found":
        for spx in root.rglob("*.spx"):
            if spx.is_file() and "hardware" in spx.name.lower():
                data = safe_plist(spx)
                if data:
                    _parse_hardware_plist(data, info)
            if info["serial_number"] != "Not found":
                break

    # Hostname
    for fname in ("hostname.txt", "hostname"):
        f = find_file(root, fname)
        if f:
            val = safe_read(f).strip()
            if val:
                # Strip shell comment/command prefix e.g. "# # /bin/hostname # LL7W4QGHVF"
                if "#" in val:
                    val = val.rsplit("#", 1)[-1].strip()
                if val:
                    info["hostname"] = val
            break

    # IODeviceTree.txt — reliable fallback for serial number and model identifier
    f = find_file(root, "IODeviceTree.txt")
    if f:
        text = safe_read(f)
        if info["serial_number"] == "Not found":
            m = re.search(r'"IOPlatformSerialNumber"\s*=\s*"([^"]+)"', text)
            if m:
                info["serial_number"] = m.group(1)
        if info["model_identifier"] == "Not found":
            m = re.search(r'"model"\s*=\s*<"([^"]+)">', text)
            if m:
                info["model_identifier"] = m.group(1)

    return info


def _parse_hardware_text(text: str, info: dict):
    for line in text.splitlines():
        if not line.strip() or ":" not in line:
            continue
        key_raw, _, val = line.partition(":")
        key_raw = key_raw.strip()
        val = val.strip()
        if not val:
            continue
        low = key_raw.lower()
        if "serial number" in low:
            info["serial_number"] = val
        elif low.startswith("model name"):
            info["model_name"] = val
        elif low.startswith("model identifier"):
            info["model_identifier"] = val
        elif "computer name" in low or "host name" in low:
            info["hostname"] = val


def _parse_hardware_plist(data, info: dict):
    if not isinstance(data, dict):
        return
    for item in data.get("SPHardwareDataType", []):
        if not isinstance(item, dict):
            continue
        if item.get("serial_number"):
            info["serial_number"] = item["serial_number"]
        if item.get("machine_name"):
            info["model_name"] = item["machine_name"]
        if item.get("machine_model"):
            info["model_identifier"] = item["machine_model"]


# =============================================================================
# Log Archive Reader
# =============================================================================

PREDICATE_STATUS_ITEMS = (
    'subsystem BEGINSWITH "com.apple.remotemanagement" '
    'OR process == "remotemanagementd"'
)

# Troubleshooting log topics — shown in the Troubleshooting tab dropdown.
# Nested structure: category → topic → {extra_args, predicate}
# All commands run as `log show --archive <path> [extra_args] --predicate <pred> --last 30d`
# (original `log stream` commands are converted to `log show --archive` equivalents)
# Categories and topics are sorted alphabetically in the UI.
TROUBLESHOOT_TOPICS: dict = {
    "App Installation and Packages": {
        "App Store / StoreKit installs": {
            "extra_args": ["--info"],
            "predicate": 'subsystem CONTAINS "com.apple.commerce"',
        },
        "Installer / package activity": {
            "extra_args": ["--info"],
            "predicate": 'process == "installer"',
        },
        "LaunchDaemon / LaunchAgent loading": {
            "extra_args": ["--info"],
            "predicate": 'process == "launchd"',
        },
    },
    "Authentication and Identity": {
        "Kerberos / Active Directory auth": {
            "extra_args": ["--info"],
            "predicate": 'subsystem CONTAINS "com.apple.Kerberos"',
        },
        "Local authentication / PAM": {
            "extra_args": ["--info"],
            "predicate": 'subsystem == "com.apple.authorization"',
        },
        "Platform SSO (PSSO) activity": {
            "extra_args": ["--info"],
            "predicate": 'subsystem CONTAINS "com.apple.AppSSO"',
        },
    },
    "Device Compliance": {
        "Device Compliance": {
            "extra_args": ["--debug", "--info"],
            "predicate": (
                'subsystem CONTAINS "jamfAAD" '
                'OR subsystem BEGINSWITH "com.apple.AppSSO" '
                'OR subsystem BEGINSWITH "com.jamf.backgroundworkflows"'
            ),
        },
    },
    "Enrollment, Automated Device Enrollment, & DEP": {
        "Automated Device Enrollment (ADE) activity": {
            "extra_args": ["--info"],
            "predicate": 'subsystem == "com.apple.ManagedClient" AND category == "DEPEnrollment"',
        },
        "Profile installation and removal": {
            "extra_args": ["--info"],
            "predicate": 'subsystem == "com.apple.ManagedClient" AND category CONTAINS "Profile"',
        },
        "Setup Assistant / enrollment flow": {
            "extra_args": ["--info"],
            "predicate": 'process == "Setup Assistant"',
        },
    },
    "Jamf Connect": {
        "Daemon Elevation": {
            "extra_args": ["--style", "compact"],
            "predicate": '(subsystem == "com.jamf.connect.daemon") && (category == "PrivilegeElevation")',
        },
        "Login Window": {
            "extra_args": ["--info"],
            "predicate": 'subsystem CONTAINS "com.jamf.connect.login"',
        },
        "Menu Bar": {
            "extra_args": ["--style", "compact"],
            "predicate": 'subsystem == "com.jamf.connect"',
        },
        "Menu Bar Elevation": {
            "extra_args": ["--style", "compact"],
            "predicate": '(subsystem == "com.jamf.connect") && (category == "PrivilegeElevation")',
        },
    },
    "Jamf Pro": {
        "All Jamf Activity": {
            "extra_args": ["--info"],
            "predicate": 'subsystem CONTAINS "com.jamf" OR subsystem CONTAINS "com.jamfsoftware"',
        },
        "MDM Client": {
            "extra_args": ["--style", "compact"],
            "predicate": 'process CONTAINS "mdmclient"',
        },
        "MDM command processing and device enrollment": {
            "extra_args": ["--info"],
            "predicate": 'subsystem == "com.apple.ManagedClient"',
        },
        "MDM daemon activity (enrollment, commands, profiles)": {
            "extra_args": ["--info"],
            "predicate": 'subsystem == "com.apple.ManagedClient"',
        },
    },
    "Jamf Remote Assist": {
        "Jamf Remote Assist": {
            "extra_args": ["--style", "compact"],
            "predicate": 'subsystem BEGINSWITH "com.jamf.remoteassist"',
        },
    },
    "Jamf Self Service Plus": {
        "Self Service Plus": {
            "extra_args": ["--style", "compact"],
            "predicate": 'subsystem == "com.jamf.selfserviceplus"',
        },
    },
    "Networking": {
        "DNS resolution issues": {
            "extra_args": ["--info"],
            "predicate": 'process == "mDNSResponder"',
        },
        "General network diagnostics": {
            "extra_args": ["--info"],
            "predicate": 'subsystem == "com.apple.network"',
        },
        "Wi-Fi association and connectivity": {
            "extra_args": ["--info"],
            "predicate": 'subsystem == "com.apple.wifi"',
        },
    },
    "Security & Gatekeeper": {
        "Gatekeeper / code signing checks": {
            "extra_args": ["--info"],
            "predicate": 'subsystem == "com.apple.security.gatekeeper"',
        },
        "TCC (Transparency, Consent, and Control) — privacy permissions": {
            "extra_args": ["--info"],
            "predicate": 'subsystem == "com.apple.TCC"',
        },
        "XProtect malware scanning": {
            "extra_args": ["--info"],
            "predicate": 'subsystem CONTAINS "com.apple.XProtect"',
        },
    },
    "Software Updates": {
        "DDM / Declarative Device Management update commands": {
            "extra_args": ["--info"],
            "predicate": 'subsystem CONTAINS "com.apple.ManagedClient" AND category CONTAINS "SoftwareUpdate"',
        },
        "SoftwareUpdate": {
            "extra_args": ["--info"],
            "predicate": 'subsystem == "com.apple.SoftwareUpdate"',
        },
        "SoftwareUpdate Daemon": {
            "extra_args": ["--info"],
            "predicate": 'process == "softwareupdated"',
        },
    },
    "System and Kernel Extensions": {
        "Endpoint security framework": {
            "extra_args": ["--info"],
            "predicate": 'subsystem == "com.apple.EndpointSecurity"',
        },
        "System extension approvals/activations": {
            "extra_args": ["--info"],
            "predicate": 'subsystem == "com.apple.SystemExtensions"',
        },
    },
}


LEVEL_MAP = {16: "fault", 17: "error", 18: "warning",
             0: "default", 1: "info", 2: "debug"}


def read_logarchive(archive_path: str, predicate: str,
                    last_days: int = 30, max_lines: int = 500) -> list:
    cmd = [
        "/usr/bin/log", "show",
        "--archive", archive_path,
        "--predicate", predicate,
        "--style", "ndjson",
        "--info",
        "--last", f"{last_days}d",
    ]
    try:
        result = subprocess.run(cmd, capture_output=True, timeout=180)
        output = result.stdout.decode("utf-8", errors="ignore")
    except subprocess.TimeoutExpired:
        return []
    except Exception:
        return []

    entries = []
    for line in output.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            obj = json.loads(line)
        except json.JSONDecodeError:
            continue

        ts = obj.get("timestamp", "")
        if len(ts) > 22:
            ts = ts[:22]

        process_path = obj.get("processImagePath", "")
        process = process_path.split("/")[-1] if process_path else ""

        msg = obj.get("eventMessage", "")
        if not msg:
            continue

        entries.append({
            "timestamp": ts,
            "process":   process,
            "subsystem": obj.get("subsystem", ""),
            "message":   msg,
            "level":     LEVEL_MAP.get(obj.get("messageType", 0), "default"),
        })
        if len(entries) >= max_lines:
            break

    return entries


# =============================================================================
# =============================================================================
# Sysdiagnose File Browser
# =============================================================================

# Known files grouped by diagnostic category.
# Each entry: (filename, description)
FILE_GROUPS: list = [
    ("OS & Software", [
        ("install.log",   "Software installation and update history"),
        ("sw_vers.txt",   "OS version, build number, and product name"),
    ]),
    ("Device & Hardware", [
        ("remotectl_dumpstate.txt", "Device state: UDID, build versions, hardware class"),
        ("IODeviceTree.txt",        "Hardware I/O device tree (serial number, UUID, model)"),
        ("SPHardwareDataType.spx",  "System Profiler: hardware overview including serial number and model"),
    ]),
    ("MDM & Management", [
        ("rmd_inspect_system.txt",              "Remote Management daemon: declarations, activations, and status"),
        ("SPConfigurationProfileDataType.spx",  "System Profiler: installed configuration profiles"),
    ]),
    ("Storage & Security", [
        ("disks.txt",         "Disk list, APFS volumes, and FileVault encryption status"),
        ("diskutil_list.txt", "Full diskutil list output"),
    ]),
    ("Logs & Diagnostics", [
        ("system_logs.logarchive", "Unified system log archive — opens in Console.app"),
        ("DiagnosticMessages.log", "Diagnostic messages log"),
    ]),
    ("Network", [
        ("ifconfig.txt",    "Network interface configuration and addresses"),
        ("netstat.txt",     "Active network connections and routing stats"),
        ("wifi_status.txt", "Wi-Fi status and association details"),
    ]),
    ("Processes & Performance", [
        ("ps.txt",         "Running process list at capture time"),
        ("spindump.txt",   "System-wide spindump with CPU backtraces"),
    ]),
]


def gather_sysdiagnose_files(root: Path) -> dict:
    """
    Return a dict mapping group name → list of file entries, each enriched
    with the resolved absolute path (or None if not found in this archive).
    Uses find_path (not find_file) so directory bundles like .logarchive match.
    """
    result: dict = {}
    for group_name, entries in FILE_GROUPS:
        files = []
        for fname, desc in entries:
            p = find_path(root, fname)
            files.append({
                "name":        fname,
                "description": desc,
                "path":        str(p) if p else None,
                "found":       p is not None,
            })
        result[group_name] = files
    return result


# =============================================================================
# MDM Declarations Parser
# =============================================================================

_BP_RE = re.compile(r'Blueprint_([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})_',
                    re.IGNORECASE)


def read_status_item_logs(archive_path: str, key_paths: list) -> dict:
    """
    Query the logarchive for the most recent entry mentioning each status key path.
    Returns dict: keyPath -> {"timestamp": str, "message": str}
    """
    if not key_paths or not archive_path:
        return {}
    entries = read_logarchive(archive_path, PREDICATE_STATUS_ITEMS,
                              last_days=90, max_lines=3000)
    result: dict = {}
    # Iterate newest-first (read_logarchive returns chronological order)
    for entry in reversed(entries):
        msg = entry.get("message", "")
        for kp in key_paths:
            if kp not in result and kp in msg:
                result[kp] = {
                    "timestamp": entry.get("timestamp", ""),
                    "message":   msg,
                }
    return result


def _extract_bp_uuid(identifier: str) -> Optional[str]:
    """Return the Blueprint UUID from an identifier like Blueprint_<UUID>_s1_sys_act1, or None."""
    m = _BP_RE.search(identifier)
    return m.group(1) if m else None


def _extract_reason_codes(reasons_raw) -> list:
    """Extract error code strings from a reasons/inactiveReasons list (may be dicts or strings)."""
    codes = []
    for r in (reasons_raw or []):
        if isinstance(r, dict):
            code = r.get("code") or r.get("Code") or ""
            codes.append(str(code) if code else str(r))
        elif r:
            codes.append(str(r))
    return codes


def _norm_active(val) -> int:
    """Normalize plist active/bool values to int 1 or 0.

    plutil -convert json returns the JSON string "1"/"0" for unquoted numeric
    values in old-style ASCII plists (the format has no typed integers).
    The pure-Python fallback parser coerces them to int 1/0.  Both need to be
    treated as truthy/falsy, so normalise to int here at the source.
    """
    return 1 if val in (1, True, "1") else 0


def _is_ok(active, valid: str) -> bool:
    return (_norm_active(active) == 1) and (str(valid).lower() == "valid")


def _group_by_status(entries: list) -> list:
    """
    Group declaration entries by their status signature.
    Returns list of {ok, count, active, valid, reasons} sorted ok-first.
    """
    groups: dict = {}
    for e in entries:
        ok      = _is_ok(e.get("active"), e.get("valid", ""))
        reasons = tuple(sorted(set(e.get("all_reasons", []))))
        key     = (ok, reasons)
        if key not in groups:
            groups[key] = {
                "ok":      ok,
                "count":   0,
                "active":  e.get("active"),
                "valid":   e.get("valid", ""),
                "reasons": list(reasons),
            }
        groups[key]["count"] += 1
    # Sort: ok entries first, then by reason string
    return sorted(groups.values(), key=lambda g: (not g["ok"], g["reasons"]))


def _rmd_to_json(path: Path) -> Optional[dict]:
    """Convert Apple old-style ASCII plist to JSON via plutil and return parsed dict."""
    try:
        result = subprocess.run(
            ["plutil", "-convert", "json", "-o", "-", str(path)],
            capture_output=True, timeout=30
        )
        if result.returncode == 0:
            return json.loads(result.stdout.decode("utf-8", errors="ignore"))
    except Exception:
        pass
    # Fallback: pure-Python ASCII plist parser
    return _parse_ascii_plist(path)


class _AsciiPlistParser:
    """Minimal recursive-descent parser for Apple ASCII (NeXTSTEP) plist format."""

    def __init__(self, text: str):
        self.text = text
        self.pos = 0
        self.n = len(text)

    def _skip(self):
        while self.pos < self.n:
            c = self.text[self.pos]
            if c in " \t\n\r":
                self.pos += 1
            elif self.text[self.pos:self.pos + 2] == "//":
                while self.pos < self.n and self.text[self.pos] != "\n":
                    self.pos += 1
            elif self.text[self.pos:self.pos + 2] == "/*":
                self.pos += 2
                while self.pos < self.n - 1 and self.text[self.pos:self.pos + 2] != "*/":
                    self.pos += 1
                self.pos += 2
            else:
                break

    def _read_quoted(self) -> str:
        self.pos += 1  # consume opening "
        parts = []
        start = self.pos
        while self.pos < self.n and self.text[self.pos] != '"':
            if self.text[self.pos] == "\\":
                parts.append(self.text[start:self.pos])
                self.pos += 1
                parts.append(self.text[self.pos] if self.pos < self.n else "")
                self.pos += 1
                start = self.pos
            else:
                self.pos += 1
        parts.append(self.text[start:self.pos])
        if self.pos < self.n:
            self.pos += 1  # consume closing "
        return "".join(parts)

    def _read_word(self):
        start = self.pos
        while self.pos < self.n and self.text[self.pos] not in ' \t\n\r{}()=;,"':
            self.pos += 1
        w = self.text[start:self.pos]
        # Coerce simple numbers to int so truthy checks work
        if w == "1":
            return 1
        if w == "0":
            return 0
        return w

    def _value(self):
        self._skip()
        if self.pos >= self.n:
            return None
        c = self.text[self.pos]
        if c == "{":
            return self._dict()
        if c == "(":
            return self._array()
        if c == '"':
            return self._read_quoted()
        return self._read_word()

    def _dict(self) -> dict:
        self.pos += 1  # consume {
        out: dict = {}
        while True:
            self._skip()
            if self.pos >= self.n or self.text[self.pos] == "}":
                self.pos += 1 if self.pos < self.n else 0
                break
            key = self._read_quoted() if self.text[self.pos] == '"' else self._read_word()
            if isinstance(key, int):
                key = str(key)
            self._skip()
            if self.pos < self.n and self.text[self.pos] == "=":
                self.pos += 1
            val = self._value()
            out[key] = val
            self._skip()
            if self.pos < self.n and self.text[self.pos] == ";":
                self.pos += 1
        return out

    def _array(self) -> list:
        self.pos += 1  # consume (
        out: list = []
        while True:
            self._skip()
            if self.pos >= self.n or self.text[self.pos] == ")":
                self.pos += 1 if self.pos < self.n else 0
                break
            val = self._value()
            if val is not None:
                out.append(val)
            self._skip()
            if self.pos < self.n and self.text[self.pos] == ",":
                self.pos += 1
        return out

    def parse(self):
        self._skip()
        return self._value()


def _parse_ascii_plist(path: Path) -> Optional[dict]:
    """Parse Apple ASCII plist format using a pure-Python parser."""
    try:
        text = safe_read(path)
        if not text:
            return None
        return _AsciiPlistParser(text).parse()
    except Exception:
        return None


def _format_swupdate_value(val) -> str:
    """
    Format a parsed plist value from a 'Reporting status' block for table display.
    Handles strings, ints, lists (arrays), and nested dicts.
    """
    if val is None or val == "" or val == [] or val == {}:
        return "—"
    if isinstance(val, bool):
        return "true" if val else "false"
    if isinstance(val, int):
        return str(val) if val else "—"
    if isinstance(val, str):
        return val.strip() if val.strip() else "—"
    if isinstance(val, list):
        parts = [str(v).strip() for v in val if v is not None and str(v).strip()]
        return ", ".join(parts) if parts else "—"
    if isinstance(val, dict):
        # pending-version: contains os-version / build-version
        if "os-version" in val or "build-version" in val:
            parts = []
            ov = str(val.get("os-version", "")).strip()
            bv = str(val.get("build-version", "")).strip()
            if ov:
                parts.append(ov)
            if bv:
                parts.append(f"({bv})")
            return " ".join(parts) if parts else "—"
        # failure-reason / install-reason: contains a "reason" key (may be an array)
        if "reason" in val:
            r = val["reason"]
            if isinstance(r, list):
                items = [str(x).strip() for x in r if x is not None and str(x).strip()]
                return ", ".join(items) if items else "—"
            return str(r).strip() if r else "—"
        # count-only dict (e.g., failure-reason = { count = 0; })
        if list(val.keys()) == ["count"]:
            return f"count = {val['count']}"
        # Generic dict fallback
        parts = [f"{k}: {v}" for k, v in val.items()
                 if v is not None and v != "" and v != [] and v != {}]
        return "; ".join(parts) if parts else "—"
    return str(val).strip() or "—"


def parse_swupdate_status_values(archive_path: str) -> dict:
    """
    Query the logarchive for the most recent 'Reporting status' block emitted by
    SoftwareUpdateSubscriber, parse it with _AsciiPlistParser (handles unquoted
    values, arrays, and nested dicts), and return a dict of
    softwareupdate.* keyPath -> display string.
    """
    if not archive_path:
        return {}

    cmd = [
        "/usr/bin/log", "show",
        "--archive", archive_path,
        "--predicate", 'process == "SoftwareUpdateSubscriber" AND eventMessage CONTAINS "Reporting status {"',
        "--style", "syslog",
        "--info",
        "--last", "30d",
    ]
    try:
        result = subprocess.run(cmd, capture_output=True, timeout=120)
        output = result.stdout.decode("utf-8", errors="ignore")
    except Exception:
        return {}

    if not output:
        return {}

    # Find the *last* "Reporting status {" occurrence in the output
    idx = output.rfind("Reporting status {")
    if idx == -1:
        return {}

    # Locate the outer opening "{" and the closing "} (null)"
    dict_start = output.index("{", idx)
    end_marker  = output.find("} (null)", dict_start)
    if end_marker == -1:
        return {}
    block = output[dict_start : end_marker + 1]   # includes closing "}"

    # Parse the block as an ASCII plist dict — handles quoted/unquoted values,
    # arrays ( ... ), and nested dicts { ... }
    try:
        parsed = _AsciiPlistParser(block).parse()
    except Exception:
        return {}

    if not isinstance(parsed, dict):
        return {}

    return {
        str(key): _format_swupdate_value(val)
        for key, val in parsed.items()
        if str(key).startswith("softwareupdate.")
    }


# Maps macOS major version (or "major.minor" for 10.x) to marketing name.
# Used to derive device.operating-system.marketing-name from ProductVersion
# in sw_vers.txt — far more reliable than scraping install.log, which can
# contain entries for pending updates rather than the installed OS.
_MACOS_NAMES: dict = {
    "10.9":  "Mavericks",
    "10.10": "Yosemite",
    "10.11": "El Capitan",
    "10.12": "Sierra",
    "10.13": "High Sierra",
    "10.14": "Mojave",
    "10.15": "Catalina",
    "11":    "Big Sur",
    "12":    "Monterey",
    "13":    "Ventura",
    "14":    "Sonoma",
    "15":    "Sequoia",
    "26":    "Tahoe",
}


def _macos_marketing_name(product_version: str) -> str:
    """Return 'macOS <Name>' for a given ProductVersion string, or '' if unknown."""
    parts = product_version.split(".")
    # 10.x releases use major.minor as the key
    if parts and parts[0] == "10" and len(parts) >= 2:
        key = f"10.{parts[1]}"
    else:
        key = parts[0] if parts else ""
    name = _MACOS_NAMES.get(key, "")
    return f"macOS {name}" if name else ""


def parse_static_status_values(root: Path) -> dict:
    """
    Extract status key path values from static files in the sysdiagnose.
    All values here are inferred from static files (not directly from the MDM
    reporting channel / logarchive), so they are returned with a trailing " *"
    to indicate implied values.

    Mappings
    --------
    sw_vers.txt
        ProductVersion      → device.operating-system.version
        ProductName         → device.operating-system.family
        BuildVersion        → device.operating-system.build-version
                              (when ProductVersionExtra absent — no RSR)
        BuildVersion        → device.operating-system.supplemental.build-version
        ProductVersionExtra → device.operating-system.supplemental.extra-version
                              (when ProductVersionExtra present — RSR installed)

    IODeviceTree.txt
        "IOPlatformSerialNumber"  → device.identifier.serial-number
        "IOPlatformUUID"          → device.identifier.udid  (fallback)
        "model"                   → device.model.identifier

    remotectl_dumpstate.txt
        UniqueDeviceID            → device.identifier.udid  (preferred)
        SupplementalBuildVersion  → device.operating-system.supplemental.build-version
        DeviceClass               → device.model.family

    SPHardwareDataType.spx  (binary plist, items at d[0]["_items"][0])
        model_number              → device.model.number
        machine_name              → device.model.marketing-name

    disks.txt
        FileVault: Yes/No         → diskmanagement.filevault.enabled

    sw_vers.txt (continued)
        ProductVersion lookup     → device.operating-system.marketing-name
                                    (version-to-name table; e.g. 14.x → "macOS Sonoma")

    logs/install.log
        SoftwareUpdateSettingsExtension → softwareupdate.beta-enrollment
    """
    # All values from static files get a trailing " *" (implied, not from logarchive)
    STAR = " *"

    values: dict = {}

    # ── sw_vers.txt ───────────────────────────────────────────────────────────
    for fname in ("sw_vers.txt", "sw_vers"):
        f = find_file(root, fname)
        if f:
            sw = {}
            for line in safe_read(f).splitlines():
                if ":" not in line:
                    continue
                k, _, v = line.partition(":")
                sw[k.strip()] = v.strip()

            if "ProductVersion" in sw:
                pv = sw["ProductVersion"]
                values["device.operating-system.version"] = pv + STAR
                mkt = _macos_marketing_name(pv)
                if mkt:
                    values["device.operating-system.marketing-name"] = mkt + STAR
            if "ProductName" in sw:
                values["device.operating-system.family"] = sw["ProductName"] + STAR

            if "ProductVersionExtra" in sw:
                # RSR is installed: BuildVersion carries the supplemental build
                # (e.g. 25D771280a) and ProductVersionExtra is the suffix (e.g. (a))
                values["device.operating-system.supplemental.extra-version"] = sw["ProductVersionExtra"] + STAR
                if "BuildVersion" in sw:
                    values["device.operating-system.supplemental.build-version"] = sw["BuildVersion"] + STAR
            else:
                # No RSR: BuildVersion is simply the OS build version
                if "BuildVersion" in sw:
                    values["device.operating-system.build-version"] = sw["BuildVersion"] + STAR
            break

    # ── IODeviceTree.txt ──────────────────────────────────────────────────────
    f = find_file(root, "IODeviceTree.txt")
    if f:
        text = safe_read(f)
        m = re.search(r'"IOPlatformSerialNumber"\s*=\s*"([^"]+)"', text)
        if m:
            values["device.identifier.serial-number"] = m.group(1) + STAR

        # UUID fallback — remotectl is preferred; may be overwritten below
        m = re.search(r'"IOPlatformUUID"\s*=\s*"([^"]+)"', text)
        if m:
            values["device.identifier.udid"] = m.group(1) + STAR

        # Angle-bracket data value:  "model" = <"MacBookPro18,3">
        m = re.search(r'"model"\s*=\s*<"([^"]+)">', text)
        if m:
            values["device.model.identifier"] = m.group(1) + STAR

    # ── remotectl_dumpstate.txt ───────────────────────────────────────────────
    f = find_file(root, "remotectl_dumpstate.txt")
    if f:
        text = safe_read(f)
        # UniqueDeviceID => 00006000-001A112E14FA401E  (preferred UDID)
        m = re.search(r'UniqueDeviceID\s*=>\s*(\S+)', text)
        if m:
            values["device.identifier.udid"] = m.group(1).strip() + STAR

        # SupplementalBuildVersion => 25D2128
        m = re.search(r'SupplementalBuildVersion\s*=>\s*(\S+)', text)
        if m:
            values["device.operating-system.supplemental.build-version"] = m.group(1).strip() + STAR

        # DeviceClass => Mac
        m = re.search(r'DeviceClass\s*=>\s*(\S+)', text)
        if m:
            values["device.model.family"] = m.group(1).strip() + STAR

    # ── SPHardwareDataType.spx ────────────────────────────────────────────────
    f = find_file(root, "SPHardwareDataType.spx")
    if f:
        try:
            data = plistlib.loads(f.read_bytes())
            if isinstance(data, list) and data:
                items = data[0].get("_items", []) if isinstance(data[0], dict) else []
                if items and isinstance(items[0], dict):
                    hw = items[0]
                    mn = hw.get("model_number", "").strip()
                    if mn:
                        values["device.model.number"] = mn + STAR
                    name = hw.get("machine_name", "").strip()
                    if name:
                        values["device.model.marketing-name"] = name + STAR
        except Exception:
            pass

    # ── disks.txt → diskmanagement.filevault.enabled ─────────────────────────
    f = find_file(root, "disks.txt")
    if f:
        m = re.search(r'FileVault:\s+(Yes|No)', safe_read(f))
        if m:
            enabled = m.group(1) == "Yes"
            values["diskmanagement.filevault.enabled"] = ("true" if enabled else "false") + STAR

    # ── logs/install.log ─────────────────────────────────────────────────────
    install_log = find_file(root, "install.log")
    if install_log:
        log_text = safe_read(install_log)

        # softwareupdate.beta-enrollment — last occurrence wins
        beta_val = None
        for line in reversed(log_text.splitlines()):
            m_on = re.search(r'Beta enrollment is enabled[:\s]+(\S[^{]*?)(?:\s*\{|$)', line, re.IGNORECASE)
            if m_on:
                beta_val = m_on.group(1).strip() + STAR
                break
            if re.search(r'Beta enrollment is disabled', line, re.IGNORECASE):
                beta_val = "disabled" + STAR
                break
        if beta_val:
            values["softwareupdate.beta-enrollment"] = beta_val

    return values


def parse_declarations(root: Path, log_archive: Optional[Path] = None) -> dict:
    """
    Parse rmd_inspect_system.txt and aggregate MDM declarations by Blueprint UUID.
    Multiple activations/configs sharing the same UUID are grouped by status signature
    so identical errors collapse into a single "×N" row.

    Returns a dict with keys:
      found          – bool
      error          – str or None
      blueprints     – list of Blueprint dicts
      standalone     – list of non-Blueprint declaration dicts
      conduit        – dict with last-sync metadata
      status_items   – list of {keyPath, needsSync, lastReceivedDate, log_entry or None}
    """
    empty = {"found": False, "error": None, "blueprints": [], "standalone": [],
             "conduit": {}, "status_items": []}

    rmd_file = find_file(root, "rmd_inspect_system.txt")
    if not rmd_file:
        return empty

    data = _rmd_to_json(rmd_file)
    if not data:
        return {**empty, "found": True, "error": "plutil conversion failed — file may be malformed"}

    # ── Management Sources ────────────────────────────────────────────────────
    try:
        sources = data["Detail"]["Report"]["Management Sources"]
    except (KeyError, TypeError):
        return {**empty, "found": True, "error": "Unexpected structure (no Management Sources)"}

    if not sources:
        return {**empty, "found": True}

    source         = sources[0]
    activations    = source.get("activations",    []) or []
    configurations = source.get("configurations", []) or []
    management     = source.get("management",     []) or []

    # ── Conduit / last-sync metadata ─────────────────────────────────────────
    conduit = {}
    try:
        cc = source.get("conduitConfig", {}) or {}
        st = cc.get("state", {}) or {}
        conduit = {
            "last_received":      st.get("lastReceivedServerTokensFromServerTimestamp", ""),
            "last_processed":     st.get("lastProcessedDeclarationsToken", ""),
            "consecutive_errors": st.get("numberOfConsecutiveErrors", 0),
        }
    except Exception:
        pass

    # ── Subscribed status key paths ───────────────────────────────────────────
    status_items = []
    try:
        for kp_entry in (source.get("subscribedStatusKeyPaths") or []):
            kp = kp_entry.get("keyPath", "")
            if kp:
                raw_ns = kp_entry.get("needsSync", 0)
                status_items.append({
                    "keyPath":          kp,
                    # Normalise to plain bool so template comparisons are unambiguous.
                    # Apple's plist: 1 = key path has been received/synced (✓), 0 = not yet synced (✕)
                    "needsSync":        bool(raw_ns) if raw_ns not in (None, "") else False,
                    "lastReceivedDate": kp_entry.get("lastReceivedDate", ""),
                    "log_entry":        None,   # filled after log query below
                })
    except Exception:
        pass

    # ── Status section → per-identifier {active, valid, reasons} ─────────────
    status_by_id: dict = {}
    try:
        status_list = data["Detail"]["Status"]
        if status_list:
            decls = status_list[0]["Status"]["management"]["declarations"]
            for section in ("activations", "configurations", "management"):
                for entry in (decls.get(section) or []):
                    ident = entry.get("identifier", "")
                    if ident:
                        status_by_id[ident] = {
                            "active":   _norm_active(entry.get("active")),
                            "valid":    str(entry.get("valid", "")),
                            "reasons":  _extract_reason_codes(entry.get("reasons")),
                        }
    except (KeyError, TypeError, IndexError):
        pass

    # ── Accumulate raw entries per Blueprint UUID ─────────────────────────────
    # bp_raw[uuid] = {act_type, cfg_type, raw_acts, raw_cfgs, raw_mgmt}
    bp_raw: dict  = {}
    standalone: list = []

    def _bp(uuid, act_type="", cfg_type=""):
        if uuid not in bp_raw:
            bp_raw[uuid] = {
                "uuid":     uuid,
                "act_type": act_type,
                "cfg_type": cfg_type,
                "raw_acts": [],
                "raw_cfgs": [],
                "raw_mgmt": [],
            }
        if act_type:
            bp_raw[uuid]["act_type"] = act_type
        if cfg_type:
            bp_raw[uuid]["cfg_type"] = cfg_type
        return bp_raw[uuid]

    # Activations
    for act in activations:
        ident   = act.get("identifier", "")
        bp_uuid = _extract_bp_uuid(ident)
        status  = status_by_id.get(ident, {})
        state   = act.get("state") or {}
        # Combine reasons from state.inactiveReasons and Status.reasons
        reasons = list(dict.fromkeys(
            _extract_reason_codes(state.get("inactiveReasons"))
            + status.get("reasons", [])
        ))
        raw = {
            "identifier":  ident,
            "loadState":   act.get("loadState", ""),
            "active":      _norm_active(state.get("active")),
            "valid":       status.get("valid", ""),
            "all_reasons": reasons,
        }
        if bp_uuid:
            _bp(bp_uuid, act_type=act.get("declarationType", ""))["raw_acts"].append(raw)
        else:
            standalone.append({
                "section":         "activation",
                "identifier":      ident,
                "declarationType": act.get("declarationType", ""),
                "loadState":       act.get("loadState", ""),
                "active":          _norm_active(state.get("active")),
            })

    # Configurations
    for cfg in configurations:
        ident   = cfg.get("identifier", "")
        bp_uuid = _extract_bp_uuid(ident)
        status  = status_by_id.get(ident, {})
        raw = {
            "identifier":  ident,
            "loadState":   cfg.get("loadState", ""),
            "active":      _norm_active(cfg.get("active")),
            "valid":       status.get("valid", ""),
            "all_reasons": status.get("reasons", []),
        }
        if bp_uuid:
            _bp(bp_uuid, cfg_type=cfg.get("declarationType", ""))["raw_cfgs"].append(raw)
        else:
            standalone.append({
                "section":         "configuration",
                "identifier":      ident,
                "declarationType": cfg.get("declarationType", ""),
                "loadState":       cfg.get("loadState", ""),
                "active":          _norm_active(cfg.get("active")),
            })

    # Management
    for mgmt in management:
        ident   = mgmt.get("identifier", "")
        bp_uuid = _extract_bp_uuid(ident)
        status  = status_by_id.get(ident, {})
        raw = {
            "identifier":  ident,
            "loadState":   mgmt.get("loadState", ""),
            "active":      _norm_active(status.get("active")),
            "valid":       status.get("valid", ""),
            "all_reasons": status.get("reasons", []),
        }
        if bp_uuid:
            _bp(bp_uuid)["raw_mgmt"].append(raw)
        else:
            standalone.append({
                "section":         "management",
                "identifier":      ident,
                "declarationType": mgmt.get("declarationType", ""),
                "loadState":       mgmt.get("loadState", ""),
                "active":          _norm_active(status.get("active")),
            })

    # ── Build final Blueprint records with grouped statuses ───────────────────
    blueprints = []
    for uuid, raw in bp_raw.items():
        blueprints.append({
            "uuid":              uuid,
            "act_type":          raw["act_type"],
            "cfg_type":          raw["cfg_type"],
            "activation_groups": _group_by_status(raw["raw_acts"]),
            "config_groups":     _group_by_status(raw["raw_cfgs"]),
            "mgmt_entries":      raw["raw_mgmt"],
        })

    # ── Enrich status items with values and log entries ──────────────────────
    # Static files (sw_vers, IODeviceTree, SPHardwareDataType) are always available.
    static_values = parse_static_status_values(root)

    if log_archive and status_items:
        kp_list   = [kp["keyPath"] for kp in status_items]
        log_vals  = read_status_item_logs(str(log_archive), kp_list)
        sw_values = parse_swupdate_status_values(str(log_archive))
        # Merge: static values as base, sw_update values take precedence
        all_values = {**static_values, **sw_values}
        for item in status_items:
            item["log_entry"] = log_vals.get(item["keyPath"])
            item["last_value"] = all_values.get(item["keyPath"], "")
    else:
        for item in status_items:
            item["log_entry"] = None
            item["last_value"] = static_values.get(item["keyPath"], "")

    return {
        "found":        True,
        "error":        None,
        "blueprints":   blueprints,
        "standalone":   standalone,
        "conduit":      conduit,
        "status_items": status_items,
    }


# =============================================================================
# Configuration Profiles Parser
# =============================================================================

_ISO_DATE_RE = re.compile(r'\((\d{4}-\d{2}-\d{2} [\d:]+)')


def parse_config_profiles(root: Path) -> dict:
    """
    Parse SPConfigurationProfileDataType.spx and return all installed
    configuration profiles with their payloads.

    Structure of the spx (binary plist):
      list[0]["_items"][0]["_items"]  →  list of profile dicts
      Each profile dict has metadata fields + "_items" list of payload dicts.

    Returns:
      {
        "found":    bool,
        "error":    str | None,
        "profiles": [
          {
            "name":               str,
            "org":                str,
            "source":             str,   # e.g. "MDM"
            "install_date":       str,   # ISO-ish date extracted from string
            "removal_disallowed": bool,
            "verified":           bool,
            "identifier":         str,
            "payloads": [
              {
                "display_name":  str,
                "domain":        str,   # preference domain (_name)
                "payload_data":  str,   # raw plist text for display
              }
            ]
          }
        ]
      }
    """
    empty = {"found": False, "error": None, "profiles": []}

    spx = find_file(root, "SPConfigurationProfileDataType.spx")
    if not spx:
        return empty

    try:
        data = plistlib.loads(spx.read_bytes())
    except Exception as e:
        return {**empty, "found": True, "error": f"Failed to parse SPX: {e}"}

    try:
        raw_profiles = data[0]["_items"][0]["_items"]
    except (IndexError, KeyError, TypeError):
        return {**empty, "found": True, "error": "Unexpected SPX structure"}

    profiles = []
    for rp in raw_profiles:
        if not isinstance(rp, dict):
            continue

        # Install date — extract ISO portion from the long localized string
        raw_date = str(rp.get("spconfigprofile_install_date", ""))
        m = _ISO_DATE_RE.search(raw_date)
        install_date = m.group(1) if m else raw_date[:30].strip()

        payloads = []
        for pl in (rp.get("_items") or []):
            if not isinstance(pl, dict):
                continue
            payloads.append({
                "display_name": str(pl.get("spconfigprofile_payload_display_name", "")).strip()
                                or str(pl.get("_name", "")),
                "domain":       str(pl.get("_name", "")).strip(),
                "payload_data": str(pl.get("spconfigprofile_payload_data", "")).strip(),
            })

        profiles.append({
            "name":               str(rp.get("_name", "")).strip(),
            "org":                str(rp.get("spconfigprofile_organization", "")).strip(),
            "source":             str(rp.get("spconfigprofile_install_source", "")).strip(),
            "install_date":       install_date,
            "removal_disallowed": str(rp.get("spconfigprofile_RemovalDisallowed", "")).lower() == "yes",
            "verified":           str(rp.get("spconfigprofile_verification_state", "")).lower() == "verified",
            "identifier":         str(rp.get("spconfigprofile_profile_identifier", "")).strip(),
            "payloads":           payloads,
        })

    return {"found": True, "error": None, "profiles": profiles}


# =============================================================================
# Managed Settings Extractor
# =============================================================================

def extract_managed_settings(profiles: list) -> dict:
    """
    Scan all parsed config profile payloads and extract three sets of values
    for display in the Device tab's Managed Settings section.

    com.apple.notificationsettings
        → NotificationSettings[*].BundleIdentifier  (managed_notifications)

    com.apple.TCC.configuration-profile-policy
        → Services.*[*].Identifier                  (pppc_identifiers)

    com.apple.servicemanagement
        → Rules[*].Comment                          (managed_login_items)

    Duplicates are dropped (first-seen wins), empty strings are skipped.
    """
    notifications: list = []
    pppc:          list = []
    login_items:   list = []

    seen_notif = set()
    seen_pppc  = set()
    seen_login = set()

    for profile in profiles:
        for payload in profile.get("payloads", []):
            domain   = payload.get("domain", "")
            raw_data = payload.get("payload_data", "")
            if not raw_data:
                continue

            try:
                parsed = _AsciiPlistParser(raw_data).parse()
            except Exception:
                continue

            if not isinstance(parsed, dict):
                continue

            # ── Managed Notifications ─────────────────────────────────────────
            if domain == "com.apple.notificationsettings":
                for item in (parsed.get("NotificationSettings") or []):
                    if isinstance(item, dict):
                        bid = str(item.get("BundleIdentifier", "")).strip()
                        if bid and bid not in seen_notif:
                            notifications.append(bid)
                            seen_notif.add(bid)

            # ── PPPC Identifiers ──────────────────────────────────────────────
            elif domain == "com.apple.TCC.configuration-profile-policy":
                services = parsed.get("Services", {})
                if isinstance(services, dict):
                    for entries in services.values():
                        if isinstance(entries, list):
                            for entry in entries:
                                if isinstance(entry, dict):
                                    ident = str(entry.get("Identifier", "")).strip()
                                    if ident and ident not in seen_pppc:
                                        pppc.append(ident)
                                        seen_pppc.add(ident)

            # ── Managed Login Items ───────────────────────────────────────────
            elif domain == "com.apple.servicemanagement":
                for rule in (parsed.get("Rules") or []):
                    if isinstance(rule, dict):
                        comment = str(rule.get("Comment", "")).strip()
                        if comment and comment not in seen_login:
                            login_items.append(comment)
                            seen_login.add(comment)

    return {
        "managed_notifications": notifications,
        "pppc_identifiers":      pppc,
        "managed_login_items":   login_items,
    }


# =============================================================================
# Debug Route
# =============================================================================

@app.route("/debug")
def debug():
    path_input = request.args.get("path", "").strip()
    if not path_input:
        return "<h2>Usage: /debug?path=/path/to/sydiagnose</h2>", 400

    work_path = os.path.expanduser(path_input)
    if not os.path.exists(work_path):
        return f"<h2>Path not found: {work_path}</h2>", 404

    tmp_extract = None
    if os.path.isfile(work_path) and (work_path.endswith(".tar.gz") or work_path.endswith(".tgz")):
        tmp_extract = tempfile.mkdtemp(prefix="sydiag_dbg_")
        r = subprocess.run(["tar", "xzf", work_path, "-C", tmp_extract], capture_output=True)
        if r.returncode != 0:
            return f"<h2>Extraction failed: {r.stderr.decode(errors='ignore')}</h2>", 500
        work_path = tmp_extract

    root = find_sydiagnose_root(work_path)

    all_files = sorted(str(p.relative_to(root)) for p in root.rglob("*") if p.is_file())

    key_files = {
        "sw_vers.txt":   str(find_file(root, "sw_vers.txt") or find_file(root, "sw_vers") or "NOT FOUND"),
        "install.log":   str(find_file(root, "install.log") or "NOT FOUND"),
        "logarchive":    str(find_logarchive(root) or "NOT FOUND"),
    }

    device_info = parse_device_info(root)

    html = f"""<!DOCTYPE html>
<html><head><title>Debug</title>
<style>
  body {{ font-family: monospace; padding: 24px; background: #1e1e1e; color: #d4d4d4; }}
  h2 {{ color: #4ec9b0; margin-top: 24px; }}
  pre {{ background: #252526; padding: 16px; border-radius: 8px; overflow-x: auto;
         white-space: pre-wrap; word-break: break-word; font-size: 12px; line-height: 1.6; }}
</style></head><body>
<h1 style="color:#ce9178">🔍 Sysdiagnose Debug</h1>
<p style="color:#9cdcfe">Root: {root}</p>

<h2>Key Files</h2>
<pre>{json.dumps(key_files, indent=2)}</pre>

<h2>Parsed Device Info</h2>
<pre>{json.dumps(device_info, indent=2)}</pre>

<h2>All Files ({len(all_files)})</h2>
<pre>{"<br>".join(all_files)}</pre>
</body></html>"""

    if tmp_extract and os.path.exists(tmp_extract):
        shutil.rmtree(tmp_extract, ignore_errors=True)

    return html


# =============================================================================
# Flask Routes
# =============================================================================

@app.route("/")
def index():
    return render_template("index.html")


@app.route("/analyze", methods=["POST"])
def analyze():
    global _last_tmp_dirs
    path_input = request.form.get("path", "").strip()
    uploaded   = request.files.get("file")

    # Clean up temp dirs from the previous analysis now that a new one is starting
    for _d in _last_tmp_dirs:
        if _d and os.path.exists(_d):
            shutil.rmtree(_d, ignore_errors=True)
    _last_tmp_dirs = []

    tmp_upload  = None
    tmp_extract = None

    try:
        if uploaded and uploaded.filename:
            tmp_upload = tempfile.mkdtemp(prefix="sydiag_up_")
            save_path  = os.path.join(tmp_upload, uploaded.filename)
            uploaded.save(save_path)
            work_path  = save_path
            name       = uploaded.filename
        elif path_input:
            work_path = os.path.expanduser(path_input)
            name      = os.path.basename(work_path.rstrip("/"))
        else:
            return render_template("index.html",
                                   error="Please provide a file path or upload a file.")

        if not os.path.exists(work_path):
            return render_template("index.html",
                                   error=f"Path not found: {work_path}")

        if os.path.isfile(work_path) and (
            work_path.endswith(".tar.gz") or work_path.endswith(".tgz")
        ):
            tmp_extract = tempfile.mkdtemp(prefix="sydiag_ext_")
            r = subprocess.run(
                ["tar", "xzf", work_path, "-C", tmp_extract],
                capture_output=True
            )
            if r.returncode != 0:
                return render_template(
                    "index.html",
                    error="Archive extraction failed: " + r.stderr.decode(errors="ignore"),
                )
            work_path = tmp_extract

        root        = find_sydiagnose_root(work_path)
        log_archive = find_logarchive(root)
        notes       = []

        if not log_archive:
            notes.append("No .logarchive found — declaration log entries unavailable.")

        device_info      = parse_device_info(root)
        sysdiag_files    = gather_sysdiagnose_files(root)
        declarations     = parse_declarations(root, log_archive=log_archive)
        config_profiles  = parse_config_profiles(root)
        managed_settings = extract_managed_settings(config_profiles.get("profiles", []))

        if not declarations["found"]:
            notes.append("rmd_inspect_system.txt not found — declarations unavailable.")
        elif declarations.get("error"):
            notes.append(f"Declarations parse error: {declarations['error']}")

        if not config_profiles["found"]:
            notes.append("SPConfigurationProfileDataType.spx not found — config profiles unavailable.")

        analysis = {
            "name":             name,
            "analyzed_at":      datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "device_info":      device_info,
            "sysdiag_files":    sysdiag_files,
            "declarations":     declarations,
            "config_profiles":  config_profiles,
            "managed_settings": managed_settings,
            "log_archive_path":    str(log_archive) if log_archive else "",
            "troubleshoot_topics": {
                cat: sorted(topics.keys())
                for cat, topics in sorted(TROUBLESHOOT_TOPICS.items())
            },
            "notes":            notes,
        }

        # On success: defer cleanup so /log-stream can still reach the logarchive
        for _d in (tmp_upload, tmp_extract):
            if _d:
                _last_tmp_dirs.append(_d)
        return render_template("results.html", a=analysis)

    except Exception as e:
        import traceback
        # On error: clean up immediately — no results page, no log-stream buttons
        for _d in (tmp_upload, tmp_extract):
            if _d and os.path.exists(_d):
                shutil.rmtree(_d, ignore_errors=True)
        return render_template("index.html",
                               error=f"Processing error: {e}\n\n{traceback.format_exc()}")


@app.route("/log-stream")
def log_stream():
    archive = request.args.get("archive", "").strip()
    keypath = request.args.get("keypath", "").strip()

    if not archive or not keypath:
        return "<h2>Missing archive or keypath parameter</h2>", 400
    if not os.path.exists(archive):
        return f"<h2>Archive not found: {archive}</h2><p>The sydiagnose archive may have been cleaned up. Re-analyze to refresh.</p>", 404

    # For softwareupdate.* key paths, also pull from the three SW Update processes
    # that report status values (not just remotemanagementd).
    if keypath.startswith("softwareupdate."):
        predicate = (
            f'(process == "SoftwareUpdateSubscriber" '
            f'OR process == "softwareupdated" '
            f'OR process == "SoftwareUpdateNotificationManager" '
            f'OR subsystem BEGINSWITH "com.apple.remotemanagement" '
            f'OR process == "remotemanagementd") '
            f'AND eventMessage CONTAINS "{keypath}"'
        )
    else:
        predicate = (
            f'(subsystem BEGINSWITH "com.apple.remotemanagement" '
            f'OR process == "remotemanagementd") '
            f'AND eventMessage CONTAINS "{keypath}"'
        )
    entries = read_logarchive(archive, predicate, last_days=1, max_lines=500)

    level_colors = {
        "fault": "#FEE2E2", "error": "#FEE2E2",
        "warning": "#FEF9C3", "default": "", "info": "", "debug": "#F0F9FF",
    }

    rows_html = ""
    if entries:
        for e in reversed(entries):  # newest first
            bg = level_colors.get(e.get("level", "default"), "")
            bg_style = f'background:{bg};' if bg else ''
            rows_html += (
                f'<tr style="{bg_style}">'
                f'<td style="white-space:nowrap;color:#64748b;font-size:11px;padding:6px 12px">{e["timestamp"]}</td>'
                f'<td style="white-space:nowrap;font-weight:600;color:#64748b;font-size:11px;padding:6px 12px">{e.get("process","")}</td>'
                f'<td style="word-break:break-word;font-size:12px;padding:6px 12px">{e["message"]}</td>'
                f'</tr>'
            )
    else:
        rows_html = '<tr><td colspan="3" style="padding:32px;text-align:center;color:#94a3b8">No matching log entries found in the last 24 hours of this archive.</td></tr>'

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Log Stream — {keypath}</title>
<style>
  * {{ box-sizing:border-box; margin:0; padding:0; }}
  body {{ font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif;
          background:#f0f2f5; color:#1e293b; font-size:14px; }}
  .header {{ background:#fff; border-bottom:1px solid #e2e8f0;
             padding:14px 24px; display:flex; align-items:center; gap:12px;
             position:sticky; top:0; z-index:10; }}
  .header h1 {{ font-size:15px; font-weight:700; }}
  .keypath {{ font-family:"SF Mono",monospace; background:#EFF6FF; color:#2563EB;
              padding:3px 10px; border-radius:99px; font-size:12px; font-weight:600; }}
  .count {{ font-size:12px; color:#64748b; margin-left:auto; }}
  .card {{ background:#fff; border:1px solid #e2e8f0; border-radius:12px;
           box-shadow:0 1px 8px rgba(0,0,0,.07); margin:20px 24px; overflow:hidden; }}
  table {{ width:100%; border-collapse:collapse; }}
  th {{ padding:8px 12px; text-align:left; font-size:11px; font-weight:600;
        text-transform:uppercase; letter-spacing:.04em; color:#64748b;
        background:#f8fafc; border-bottom:1px solid #e2e8f0; white-space:nowrap; }}
  tr {{ border-bottom:1px solid #e2e8f0; }}
  tr:last-child {{ border-bottom:none; }}
  tr:hover td {{ background:#f8fafc !important; }}
</style>
</head>
<body>
<div class="header">
  <h1>📋 Log Stream</h1>
  <span class="keypath">{keypath}</span>
  <span class="count">{len(entries)} entries · last 24 h of archive</span>
</div>
<div class="card">
  <table>
    <thead>
      <tr>
        <th>Timestamp</th>
        <th>Process</th>
        <th>Message</th>
      </tr>
    </thead>
    <tbody>
      {rows_html}
    </tbody>
  </table>
</div>
</body>
</html>"""
    return html


@app.route("/troubleshoot-log")
def troubleshoot_log():
    """Run a predefined log show query against the sysdiagnose logarchive.

    Query params:
        archive  – absolute path to the .logarchive directory
        category – top-level category key from TROUBLESHOOT_TOPICS
        topic    – topic name within that category
    """
    from flask import jsonify

    archive  = request.args.get("archive",  "").strip()
    category = request.args.get("category", "").strip()
    topic    = request.args.get("topic",    "").strip()

    if not archive or not os.path.exists(archive):
        return jsonify({"error": "Logarchive not found or unavailable.", "lines": []}), 404

    cat_def = TROUBLESHOOT_TOPICS.get(category)
    if not cat_def:
        return jsonify({"error": f"Unknown category: {category}", "lines": []}), 400

    topic_def = cat_def.get(topic)
    if not topic_def:
        return jsonify({"error": f"Unknown topic: {topic}", "lines": []}), 400

    extra_args = topic_def["extra_args"]
    predicate  = topic_def["predicate"]

    # Build the full command
    cmd = (
        ["/usr/bin/log", "show", "--archive", archive]
        + extra_args
        + ["--predicate", predicate]
        + ["--last", "30d"]
    )

    # Build a display version of the command (without --archive path for brevity)
    display_extra = " ".join(extra_args)
    command_display = (
        f"log show --archive <logarchive> {display_extra} "
        f"--predicate '{predicate}' --last 30d"
    ).strip()

    try:
        result = subprocess.run(cmd, capture_output=True, timeout=120, text=True,
                                errors="replace")
        lines = result.stdout.splitlines()
        # Cap to last 2 000 lines so the page stays responsive
        if len(lines) > 2000:
            lines = lines[-2000:]
        return jsonify({
            "lines":   lines,
            "count":   len(lines),
            "command": command_display,
        })
    except subprocess.TimeoutExpired:
        return jsonify({"error": "Query timed out (>120 s). Try a more specific predicate.", "lines": []}), 504
    except Exception as e:
        return jsonify({"error": str(e), "lines": []}), 500


@app.route("/open-file")
def open_file():
    """Open a sysdiagnose file in the system default application (macOS: open).

    Query param:
        path – absolute path to the file or directory to open
    """
    path = request.args.get("path", "").strip()
    if not path or not os.path.exists(path):
        return "Not found", 404
    try:
        subprocess.Popen(["open", path])
    except Exception as e:
        return f"Could not open file: {e}", 500
    return "", 204


if __name__ == "__main__":
    print("=" * 55)
    print("  Sysdiagnose Analyzer")
    print("  http://localhost:5001")
    print("=" * 55)
    app.run(debug=False, host="127.0.0.1", port=5001)
