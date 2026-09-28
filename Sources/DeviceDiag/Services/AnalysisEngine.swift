import Foundation

enum AnalysisError: LocalizedError {
    case pathNotFound(String)
    case extractionFailed(String)
    case processingError(String)

    var errorDescription: String? {
        switch self {
        case .pathNotFound(let p): return "Path not found: \(p)"
        case .extractionFailed(let msg): return "Archive extraction failed: \(msg)"
        case .processingError(let msg): return "Processing error: \(msg)"
        }
    }
}

/// Orchestrates the full "analyze" flow — the Swift equivalent of the Flask
/// app's `/analyze` route. Extracts `.tar.gz` archives, locates the
/// sysdiagnose root, detects platform, and runs every parser.
enum AnalysisEngine {

    private static let tarGzPattern = #"\.tar\d*\.gz$|\.tgz$"#

    static func isTarGz(_ path: String) -> Bool {
        regexFirstMatch(tarGzPattern, in: path, group: 0) != nil
    }

    /// Runs the full analysis pipeline for a file or folder path (a `.tar.gz`
    /// archive, or an already-extracted sysdiagnose folder).
    static func analyze(inputPath: String) throws -> AnalysisResult {
        let analysisStart = Date()
        DiagnosticsLog.info("Analysis started: \(inputPath)")

        let expanded = (inputPath as NSString).expandingTildeInPath
        guard FileManager.default.fileExists(atPath: expanded) else {
            DiagnosticsLog.error("Path not found: \(expanded)")
            throw AnalysisError.pathNotFound(expanded)
        }

        var workURL = URL(fileURLWithPath: expanded)
        let name = workURL.lastPathComponent
        var tempDirs: [URL] = []

        var isDir: ObjCBool = false
        FileManager.default.fileExists(atPath: expanded, isDirectory: &isDir)

        if !isDir.boolValue, isTarGz(expanded) {
            let tmpDir = FileManager.default.temporaryDirectory
                .appendingPathComponent("devicediag_" + UUID().uuidString, isDirectory: true)
            try FileManager.default.createDirectory(at: tmpDir, withIntermediateDirectories: true)

            let extractStart = Date()
            DiagnosticsLog.info("Extracting \(expanded) -> \(tmpDir.path)")

            let proc = Process()
            proc.executableURL = URL(fileURLWithPath: "/usr/bin/tar")
            proc.arguments = ["xzf", expanded, "-C", tmpDir.path]
            let errPipe = Pipe()
            proc.standardError = errPipe
            try proc.run()

            // Drain stderr concurrently while tar runs — sysdiagnose archives
            // often contain many files with ACLs/xattrs that make tar emit a
            // steady stream of warnings. If nothing reads the pipe while it
            // fills (~64KB), tar blocks on write() and `waitUntilExit()` below
            // would never return (a classic Process+Pipe deadlock).
            let errBox = NSMutableData()
            let errQueue = DispatchQueue(label: "com.devicediag.tarstderr")
            errQueue.async {
                let data = errPipe.fileHandleForReading.readDataToEndOfFile()
                errBox.append(data)
            }

            proc.waitUntilExit()
            errQueue.sync {} // ensure the read above has finished

            let extractElapsed = Date().timeIntervalSince(extractStart)
            if proc.terminationStatus != 0 {
                let errStr = String(data: errBox as Data, encoding: .utf8) ?? ""
                DiagnosticsLog.error("Extraction failed after \(String(format: "%.1f", extractElapsed))s (exit \(proc.terminationStatus)): \(expanded) — \(errStr)")
                throw AnalysisError.extractionFailed(errStr)
            }
            DiagnosticsLog.info("Extraction finished in \(String(format: "%.1f", extractElapsed))s: \(expanded)")
            workURL = tmpDir
            tempDirs.append(tmpDir)
        }

        let root = FileLocating.findSysdiagnoseRoot(workURL)
        let logArchive = FileLocating.findLogarchive(root)
        var notes: [String] = []
        let isMobile = PlatformDetector.isMobile(root: root)

        if logArchive == nil {
            notes.append("No .logarchive found — declaration log entries unavailable.")
        }

        let sysdiagFiles = FileInventory.gather(root: root, isMobile: isMobile)
        let declarations = DeclarationsParser.parse(root: root, logArchive: logArchive)

        if !declarations.found {
            notes.append("rmd_inspect_system.txt not found — declarations unavailable.")
        } else if let err = declarations.error {
            notes.append("Declarations parse error: \(err)")
        }

        let formatter = DateFormatter()
        formatter.dateFormat = "yyyy-MM-dd HH:mm:ss"

        var result = AnalysisResult(name: name, analyzedAt: formatter.string(from: Date()), isMobile: isMobile)
        result.sysdiagFiles = sysdiagFiles
        result.declarations = declarations
        result.logArchivePath = logArchive?.path
        result.rootURL = root
        result.tempDirectories = tempDirs

        result.networkReport = NetworkReportParser.parse(root: root)
        if !result.networkReport.found {
            notes.append("No network-info/ifconfig.txt or netstat.txt found — network report unavailable.")
        }

        // Decodes History.txt out of any WiFi/CoreCapture bundle(s) — these
        // are nested .tgz archives, so this does its own extraction (into
        // its own temp dirs, folded into result.tempDirectories below for
        // the usual cleanup) separate from the outer sysdiagnose extraction
        // above. See WiFiHistoryParser's header comment for why.
        let (wifiHistory, wifiHistoryTempDirs) = WiFiHistoryParser.parse(root: root)
        result.wifiHistory = wifiHistory
        result.tempDirectories.append(contentsOf: wifiHistoryTempDirs)

        if isMobile {
            result.mobileDeviceInfo = MobileDeviceInfoParser.parse(root: root)
            result.mobileEnrollment = MobileEnrollmentParser.parse(root: root)
            result.mobileManagedApps = MobileManagedAppsParser.parse(root: root)
            result.configProfiles = MobileProfilesParser.parse(root: root)
            // Real DDM declaration presence, already parsed above from
            // rmd_inspect_system.txt — passed in so SettingsAttributionParser
            // never labels a restrictedBool key "Declaration" on a device
            // that provably has none (a non-UUID last-touch process name in
            // MCSettingsEvents.plist is not, on its own, evidence of one).
            let hasDeclarations = !declarations.blueprints.isEmpty || !declarations.standalone.isEmpty
            result.settingsAttribution = SettingsAttributionParser.parse(root: root, hasDeclarations: hasDeclarations)

            if !result.configProfiles.found {
                notes.append("PayloadManifest.plist not found — configuration profiles unavailable.")
            }
            if !result.settingsAttribution.found {
                notes.append("UserSettings.plist not found — settings attribution unavailable.")
            }
        } else {
            result.deviceInfo = DeviceInfoParser.parse(root: root)
            result.configProfiles = ConfigProfilesParser.parse(root: root)
            result.managedSettings = ManagedSettingsExtractor.extract(profiles: result.configProfiles.profiles)

            // A missing MDM bootstrap token only matters on a Mac that's
            // actually MDM-managed — an unmanaged one never has one. Either
            // an MDM-sourced config profile or a DDM declaration (from
            // rmd_inspect_system.txt, already parsed above) is good enough
            // evidence of that.
            let isMDMManaged = result.configProfiles.profiles.contains { $0.source.uppercased().contains("MDM") }
                || declarations.found
            result.fileVault = FileVaultParser.parse(root: root, isMDMManaged: isMDMManaged)

            if !result.configProfiles.found {
                notes.append("SPConfigurationProfileDataType.spx not found — config profiles unavailable.")
            }
        }

        result.notes = notes
        let totalElapsed = Date().timeIntervalSince(analysisStart)
        DiagnosticsLog.info("Analysis finished in \(String(format: "%.1f", totalElapsed))s: \(name) (isMobile=\(isMobile), notes=\(notes.count))")
        return result
    }

    /// Cleans up temp directories created for a previous analysis, mirroring
    /// `_last_tmp_dirs` cleanup in the Flask app.
    static func cleanup(_ result: AnalysisResult?) {
        guard let result else { return }
        for dir in result.tempDirectories {
            try? FileManager.default.removeItem(at: dir)
        }
    }
}
