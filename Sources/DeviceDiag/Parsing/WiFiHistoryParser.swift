import Foundation

/// Decodes "Historical Wi-Fi Events" out of a sysdiagnose's CoreCapture
/// bundle(s) — not covered by `sysdiag_netcheck.py`, which this app doesn't
/// otherwise have a source for.
///
/// Background: when macOS captures Wi-Fi debug data (either because
/// something asked it to, or automatically as part of `sysdiagnose`), it
/// writes a small, timestamp-named `.tgz` under
/// `WiFi/CoreCapture/WiFi/[timestamp]=WiFiDebug~sysdiag~POST[hash].tgz`.
/// That's a second, nested archive — not a plain file — so it isn't picked
/// up by `FileInventory`/`FileLocating`'s ordinary suffix search, which only
/// looks at files already sitting on disk after the outer sysdiagnose
/// archive is extracted. Inside it, at
/// `Data/com.apple.driver.AppleBCMWLANCoreV3.0/StateSnapshots/History.txt`,
/// is a rolling log of Wi-Fi association/auth/deauth/recovery events — the
/// same subsystem the Networking tab's other Wi-Fi data comes from, but
/// covering however far back the on-device buffer reaches (days, not just
/// "at capture time").
///
/// `History.txt`'s format, decoded from a real sample:
/// ```
/// [0]96727.225245\t Auth Timeout or No Resp~Auth failures NO_ACK_NO_RESP good RSSI - Logged: Yes
/// [5]1136009.539234\t WiFiDebug~sysdiag~POST[2D397] - Logged: No
/// ```
/// The number after the bracketed index is seconds (with microseconds)
/// since boot on a monotonic clock — *not* wall-clock time — so it can't be
/// displayed as-is. `Metadata/capture.plist` in the same bundle records the
/// bundle's own absolute capture time (`Time secs`/`Time usecs`). The last
/// History.txt entry is always the bundle's own trigger event (its message
/// literally echoes the bundle's own `WiFiDebug~sysdiag~POST[hash]` name),
/// logged at the moment of capture — so its uptime value and the bundle's
/// absolute capture time are the same instant. That gives an exact anchor:
/// `bootEpoch = captureEpoch - lastEntryUptime`, from which every other
/// entry's real date/time is `bootEpoch + itsUptime`. Verified against a
/// real sysdiagnose: the last entry's computed timestamp landed on the
/// bundle's capture time to the microsecond.
enum WiFiHistoryParser {

    /// `[<index>]<uptime seconds>.<uptime microseconds>\t <category>~<detail> - Logged: <Yes|No>`
    /// e.g. `[4]641976.404372\t Net Deauthentication~WCLDeauthDisassoc is_deauth = 1 Reason code=3 - Logged: Yes`.
    /// Some lines have no `~` (just a bare description) — handled by
    /// `splitBody` falling back to putting the whole thing in `category`.
    private static let linePattern = #"^\[\d+\](\d+\.\d+)\s+(.*?)\s*-\s*Logged:\s*(Yes|No)\s*$"#

    static func parse(root: URL) -> (result: WiFiHistoryResult, tempDirs: [URL]) {
        var result = WiFiHistoryResult()
        var newTempDirs: [URL] = []

        let bundles = findCoreCaptureBundles(root: root)
        guard !bundles.isEmpty else { return (result, newTempDirs) }
        result.bundleCount = bundles.count

        var allEvents: [WiFiHistoryEvent] = []
        var seenKeys = Set<String>()

        for bundleURL in bundles {
            guard let extractedRoot = extract(bundleURL, into: &newTempDirs) else { continue }
            guard let historyFile = FileLocating.findPathSuffix(extractedRoot, suffix: "StateSnapshots/History.txt"),
                  let captureFile = FileLocating.findPathSuffix(extractedRoot, suffix: "Metadata/capture.plist"),
                  let text = try? String(contentsOf: historyFile, encoding: .utf8),
                  let capture = readCaptureInfo(captureFile) else { continue }

            let rows = regexAllMatchGroups(linePattern, in: text, options: [.anchorsMatchLines])
                .compactMap { groups -> (uptime: Double, body: String, logged: Bool)? in
                    guard groups.count == 3, let uptime = Double(groups[0]) else { return nil }
                    return (uptime, groups[1], groups[2] == "Yes")
                }
            // The bundle's own trigger entry is always the one with the
            // highest uptime value (it's written at the moment of capture,
            // after everything else) — that's the calibration anchor. It's
            // also purely self-referential bookkeeping (its body is just
            // the bundle's own `Reason`, e.g. `WiFiDebug~sysdiag~POST[hash]`),
            // not a real Wi-Fi event, so it's excluded from what's displayed
            // once it's served its purpose as the anchor.
            guard let anchorUptime = rows.map(\.uptime).max() else { continue }
            let bootEpoch = capture.epoch - anchorUptime

            let bundleName = bundleURL.lastPathComponent
            for row in rows {
                if let reason = capture.reason, row.body == reason { continue }
                let (category, detail) = splitBody(row.body)
                let ts = Date(timeIntervalSince1970: bootEpoch + row.uptime)
                // Two overlapping CoreCapture bundles from the same device
                // often carry the same older entries again — de-dupe by
                // rounded uptime + message rather than by bundle, so the
                // same real-world event only shows up once.
                let key = "\(Int(row.uptime))|\(category)|\(detail)"
                guard seenKeys.insert(key).inserted else { continue }
                allEvents.append(WiFiHistoryEvent(
                    timestamp: ts, uptimeSeconds: row.uptime,
                    category: category, detail: detail,
                    logged: row.logged, sourceBundle: bundleName
                ))
            }
        }

        allEvents.sort { ($0.timestamp ?? .distantPast) > ($1.timestamp ?? .distantPast) }
        result.events = allEvents
        result.found = !allEvents.isEmpty
        return (result, newTempDirs)
    }

    /// Splits `"Net Deauthentication~WCLDeauthDisassoc is_deauth = 1 Reason code=3"`
    /// into `("Net Deauthentication", "WCLDeauthDisassoc is_deauth = 1 Reason code=3")`.
    /// Falls back to putting the whole string in `category` with an empty
    /// `detail` for the rare line with no `~` at all.
    private static func splitBody(_ body: String) -> (category: String, detail: String) {
        guard let tildeRange = body.range(of: "~") else {
            return (body.trimmingCharacters(in: .whitespaces), "")
        }
        let category = String(body[body.startIndex..<tildeRange.lowerBound]).trimmingCharacters(in: .whitespaces)
        let detail = String(body[tildeRange.upperBound...]).trimmingCharacters(in: .whitespaces)
        return (category, detail)
    }

    /// `Metadata/capture.plist`'s `Time secs`/`Time usecs` (the bundle's own
    /// absolute capture time, as a fractional Unix epoch) plus `Reason`
    /// (used to identify — and exclude from display — History.txt's
    /// self-referential trigger entry).
    private static func readCaptureInfo(_ plistURL: URL) -> (epoch: Double, reason: String?)? {
        guard let data = try? Data(contentsOf: plistURL),
              let plist = try? PropertyListSerialization.propertyList(from: data, options: [], format: nil) as? [String: Any],
              let secs = plist["Time secs"] as? NSNumber else { return nil }
        let usecs = (plist["Time usecs"] as? NSNumber)?.doubleValue ?? 0
        return (secs.doubleValue + usecs / 1_000_000.0, plist["Reason"] as? String)
    }

    /// Every WiFiDebug CoreCapture bundle under `WiFi/CoreCapture` — usually
    /// just one, but a device can accumulate more than one debug capture
    /// between sysdiagnoses.
    private static func findCoreCaptureBundles(root: URL) -> [URL] {
        let base = root.appendingPathComponent("WiFi/CoreCapture")
        guard FileManager.default.fileExists(atPath: base.path),
              let en = FileManager.default.enumerator(at: base, includingPropertiesForKeys: [.isRegularFileKey], options: []) else { return [] }
        var found: [URL] = []
        for case let url as URL in en {
            let path = url.path
            if path.hasSuffix(".tgz") || path.hasSuffix(".tar.gz") {
                found.append(url)
            }
        }
        return found.sorted { $0.lastPathComponent < $1.lastPathComponent }
    }

    /// Extracts one CoreCapture bundle into a fresh temp directory. Same
    /// `tar`-via-`Process` shape (and stderr-draining, to sidestep the
    /// classic Process+Pipe deadlock when a pipe fills and nothing's
    /// reading it) as the outer sysdiagnose archive extraction in
    /// `AnalysisEngine` — these bundles carry pcapng/bin captures that can
    /// produce plenty of their own tar warnings.
    private static func extract(_ bundleURL: URL, into tempDirs: inout [URL]) -> URL? {
        let tmpDir = FileManager.default.temporaryDirectory
            .appendingPathComponent("devicediag_wifihist_" + UUID().uuidString, isDirectory: true)
        guard (try? FileManager.default.createDirectory(at: tmpDir, withIntermediateDirectories: true)) != nil else {
            DiagnosticsLog.error("WiFiHistoryParser: couldn't create temp dir for \(bundleURL.lastPathComponent)")
            return nil
        }

        let proc = Process()
        proc.executableURL = URL(fileURLWithPath: "/usr/bin/tar")
        proc.arguments = ["xzf", bundleURL.path, "-C", tmpDir.path]
        let errPipe = Pipe()
        proc.standardError = errPipe
        guard (try? proc.run()) != nil else {
            DiagnosticsLog.error("WiFiHistoryParser: failed to launch tar for \(bundleURL.lastPathComponent)")
            return nil
        }

        let errQueue = DispatchQueue(label: "com.devicediag.wifihist.tarstderr")
        errQueue.async { _ = errPipe.fileHandleForReading.readDataToEndOfFile() }
        proc.waitUntilExit()
        errQueue.sync {}

        guard proc.terminationStatus == 0 else {
            DiagnosticsLog.error("WiFiHistoryParser: tar exited \(proc.terminationStatus) extracting \(bundleURL.lastPathComponent)")
            return nil
        }
        tempDirs.append(tmpDir)
        return tmpDir
    }
}
