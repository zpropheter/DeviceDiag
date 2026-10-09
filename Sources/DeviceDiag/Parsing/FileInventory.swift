import Foundation

/// Port of `MACOS_FILE_GROUPS` / `IOS_FILE_GROUPS` / `gather_sysdiagnose_files`.
enum FileInventory {

    static let macOSGroups: [(String, [(String, String)])] = [
        ("OS & Software", [
            ("install.log", "Software installation and update history"),
            ("InstallHistory.plist", "Plist log of all installed packages and updates"),
            ("sw_vers.txt", "OS version, build number, and product name"),
        ]),
        ("Device & Hardware", [
            ("remotectl_dumpstate.txt", "Device state: UDID, build versions, hardware class"),
            ("IODeviceTree.txt", "Hardware I/O device tree (serial number, UUID, model)"),
            ("SPHardwareDataType.spx", "System Profiler: hardware overview including serial number and model"),
        ]),
        ("MDM & Management", [
            ("rmd_inspect_system.txt", "Remote Management daemon: system-scoped declarations, activations, and status"),
            ("rmd_inspect_user.txt", "Remote Management daemon: user-scoped declarations and activations"),
            ("SPConfigurationProfileDataType.spx", "System Profiler: installed configuration profiles"),
        ]),
        ("Storage & Security", [
            ("disks.txt", "Disk list, APFS volumes, and FileVault encryption status"),
            ("diskutil_list.txt", "Full diskutil list output"),
            ("psm_status.txt", "FileVault key-slot state: enrolled users, recovery key, MDM bootstrap token — same data the Device tab's FileVault card is built from"),
            ("psm_list.txt", "FileVault admin/recovery summary from /usr/bin/psm list"),
            ("psm_stderr.txt", "Per-slot FileVault unlock-attempt/lockout counters from /usr/bin/psm"),
        ]),
        ("Logs & Diagnostics", [
            ("system_logs.logarchive", "Unified system log archive — opens in Console.app"),
            ("launchctl-*", "Launchd job/agent/daemon state dumps (dumpstate, list, and print, per UID) — reveals all of them together in Finder"),
        ]),
        // The individual files the Networking tab's report
        // (`NetworkReportParser`, a port of `sysdiag_netcheck.py`) reads
        // from all live under just two top-level folders,
        // `network-info/` and `WiFi/` — listing all ~20 of them here one
        // row at a time used to make this card by far the tallest in the
        // Files tab's two-column grid, which (since a `LazyVGrid` sizes
        // each row of the grid to its tallest cell) pushed every card
        // below it down the page behind a wall of blank space. Two
        // folder-level rows that just open in Finder are far more useful
        // anyway — admins can browse everything in either folder at once
        // rather than hunting row by row. `NetworkReportParser` still
        // locates each individual file itself via
        // `NetworkReportParser.wantedSuffixes`; that's unrelated to and
        // doesn't need to stay in sync with what's listed here anymore.
        // macOS-only — the Networking tab's report is macOS-specific, and
        // iOS sysdiagnoses lay these files out differently (see `iosGroups`'
        // own unrelated "Network" group below).
        ("Networking", [
            ("network-info", "Network interface, routing, DNS, proxy, and reachability diagnostic files — opens the folder in Finder."),
            ("WiFi", "Wi-Fi status, diagnostics, scan results, and CoreCapture debug bundles — opens the folder in Finder."),
        ]),
        ("Processes & Performance", [
            ("ps.txt", "Running process list at capture time"),
            ("spindump.txt", "System-wide spindump with CPU backtraces"),
            ("systemextensionsctl_diagnose.txt", "System extension registration and approval state"),
            ("system.log", "Flat system log (legacy, in addition to the unified log archive)"),
        ]),
    ]

    static let iosGroups: [(String, [(String, String)])] = [
        ("OS & Software", [
            ("SystemVersion.plist", "OS version, build number, and product name"),
        ]),
        ("Device & Hardware", [
            ("remotectl_dumpstate.txt", "Device state: UDID, build versions, hardware class"),
            ("IODeviceTree.txt", "Hardware I/O device tree (serial number, UUID, model)"),
        ]),
        ("MDM & Management", [
            ("rmd_inspect_system.txt", "Remote Management daemon: system-scoped declarations, activations, and status"),
            ("rmd_inspect_user.txt", "Remote Management daemon: user-scoped declarations and activations"),
            ("CloudConfigurationDetails.plist", "DEP/ADE enrollment configuration and supervision details"),
            ("MDM.plist", "MDM enrollment record: server URL, topic, identity, and capabilities"),
            ("MDMAppManagement.plist", "MDM-managed app inventory: bundle IDs, install state, and flags"),
        ]),
        ("Logs & Diagnostics", [
            ("system_logs.logarchive", "Unified system log archive — opens in Console.app"),
        ]),
        ("Network", [
            ("ifconfig.txt", "Network interface configuration and addresses"),
            ("netstat.txt", "Active network connections and routing stats"),
            ("wifi_status.txt", "Wi-Fi status and association details"),
        ]),
        ("Processes & Performance", [
            ("ps.txt", "Running process list at capture time"),
            ("spindump.txt", "System-wide spindump with CPU backtraces"),
        ]),
    ]

    /// Friendly display names for wildcard "collection" entries (see below) —
    /// keyed by the prefix before the trailing `*`.
    private static let collectionDisplayNames: [String: String] = [
        "launchctl-": "Launchd Files",
    ]

    /// Returns only groups that have at least one file present in the archive.
    static func gather(root: URL, isMobile: Bool) -> [SysdiagFileGroup] {
        let groups = isMobile ? iosGroups : macOSGroups
        var result: [SysdiagFileGroup] = []
        for (groupName, entries) in groups {
            var files: [SysdiagFileEntry] = []
            for (fname, desc) in entries {
                if fname.hasSuffix("*") {
                    // A "collection" entry: search by prefix instead of an
                    // exact filename, since e.g. launchd's per-UID dumps
                    // don't have a single fixed name. Represented as one row
                    // that reveals every match together in Finder rather
                    // than picking one arbitrarily.
                    let prefix = String(fname.dropLast())
                    let matches = FileLocating.findAllMatchingPrefix(root, prefix: prefix)
                    let displayName = collectionDisplayNames[prefix] ?? prefix
                    files.append(SysdiagFileEntry(
                        name: displayName, description: desc,
                        path: matches.first?.path, found: !matches.isEmpty,
                        groupedPaths: matches.dropFirst().map { $0.path }
                    ))
                } else if fname.contains("/") {
                    // A root-relative path suffix rather than a bare
                    // filename (see the "Networking" group above) — some
                    // sysdiagnose filenames aren't unique on their own, so
                    // this searches by the longer suffix instead of an
                    // exact filename match to land on the right one.
                    let p = FileLocating.findPathSuffix(root, suffix: fname)
                    files.append(SysdiagFileEntry(name: fname, description: desc, path: p?.path, found: p != nil))
                } else {
                    let p = FileLocating.findPath(root, fname)
                    var isDir: ObjCBool = false
                    if let p { FileManager.default.fileExists(atPath: p.path, isDirectory: &isDir) }
                    // A bundle like `system_logs.logarchive` is technically a
                    // directory on disk too, but it's opened as a single
                    // unit (in Console.app), not browsed into like a plain
                    // folder — only give the folder icon/behavior to an
                    // actual plain folder, which won't have a path extension.
                    let isPlainFolder = isDir.boolValue && (p?.pathExtension.isEmpty ?? true)
                    files.append(SysdiagFileEntry(name: fname, description: desc, path: p?.path, found: p != nil, isDirectory: isPlainFolder))
                }
            }
            if files.contains(where: { $0.found }) {
                result.append(SysdiagFileGroup(group: groupName, files: files))
            }
        }
        return result
    }

    /// Most cataloged files are a single point-in-time snapshot (a `system_profiler`
    /// dump, a process list, a disk inventory) rather than a rolling log with a
    /// timestamp on every line — "nearest timestamp" companion matching against
    /// one of those either lands on a meaningless line or, worse, a plausible-looking
    /// but unrelated one. This is an explicit allowlist of files actually worth
    /// offering, rather than "every text-ish file that happens to be cataloged" —
    /// `InstallHistory.plist` was deliberately left off despite carrying real
    /// timestamps, since they aren't the kind that's useful to correlate against.
    private static let companionCandidateNames: Set<String> = ["install.log", "system.log"]

    /// Every catalogued file that's actually present, openable in the fast
    /// in-app text viewer, AND on `companionCandidateNames` — shared by the
    /// Log Stream window and the Troubleshooting tab's "open alongside" file
    /// pickers so both list exactly the same candidates rather than two
    /// copies that can drift. "Collection" entries (more than one underlying
    /// file, like launchd's per-UID dumps) are left out too — there's no
    /// single file to search a timestamp in.
    static func viewableCandidates(from groups: [SysdiagFileGroup]) -> [(group: String, files: [SysdiagFileEntry])] {
        groups.compactMap { group in
            let files = group.files.filter { file in
                guard file.found, let path = file.path, file.groupedPaths.isEmpty else { return false }
                guard companionCandidateNames.contains(file.name.lowercased()) else { return false }
                let ext = (path as NSString).pathExtension.lowercased()
                return FileTextLoader.viewableExtensions.contains(ext)
            }
            return files.isEmpty ? nil : (group.group, files)
        }
    }
}
