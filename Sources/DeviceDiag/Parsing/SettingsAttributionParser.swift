import Foundation

/// Port of `parse_settings_attribution` — attributes each managed
/// `restrictedBool` key in UserSettings.plist to a configuration profile,
/// a DDM declaration, or a device default.
enum SettingsAttributionParser {
    private static let uuidPrefixPattern = #"^([0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12})"#

    private struct ExplicitEntry {
        var source: String
        var profileName: String?
        var implicit: Bool
        var timestamp: String
    }

    /// Internal MCF/OS bookkeeping actors that show up as a restrictedBool
    /// key's last-touch `process` in MCSettingsEvents.plist's `Restrictions`
    /// bucket but never represent a DDM declaration actually pushing that
    /// key: `MCMigrator`/`MCCleanupMigrator` re-derive the restriction cache
    /// during OS updates, `MCRestrictionManagerWriter`/`MCProfileServiceServer`
    /// recompute effective values, and SpringBoard/`dmd`/Preferences/
    /// purplebuddy/iad-cloudkit/exchangesyncd reflect user- or account-level
    /// toggles rather than a managed declaration. Without this denylist,
    /// "not a UUID" alone was being treated as proof of a declaration, which
    /// mislabels every one of these as "Declaration" — including on
    /// completely unmanaged devices with zero real declarations.
    private static let knownSystemProcesses: Set<String> = [
        "com.apple.springboard", "com.apple.dmd", "com.apple.preferences",
        "com.apple.purplebuddy", "com.apple.iad-cloudkit", "com.apple.exchangesyncd",
    ]
    private static let knownSystemProcessPrefixes = [
        "mcmigrator.", "mccleanupmigrator.", "mcrestrictionmanagerwriter.", "mcprofileserviceserver.",
    ]

    private static func isKnownSystemProcess(_ proc: String) -> Bool {
        let lower = proc.lowercased()
        if knownSystemProcesses.contains(lower) { return true }
        return knownSystemProcessPrefixes.contains { lower.hasPrefix($0) }
    }

    static func parse(root: URL, hasDeclarations: Bool) -> SettingsAttributionResult {
        var result = SettingsAttributionResult()

        guard let userSettingsFile = FileLocating.findPreferring(root, named: "UserSettings.plist", pathContains: "Shared") else {
            return result
        }
        let eventsFile = FileLocating.findPreferring(root, named: "MCSettingsEvents.plist", pathContains: "Shared")

        guard let userSettings = FileLocating.safePlist(userSettingsFile) else {
            result.found = true
            result.error = "Failed to parse UserSettings.plist"
            return result
        }

        var restricted: [String: PlistValue] = [:]
        if let rb = userSettings["restrictedBool"]?.asDict {
            for (key, val) in rb {
                if let inner = val.asDict, let v = inner["value"] {
                    restricted[key] = v
                } else {
                    restricted[key] = val
                }
            }
        }

        guard !restricted.isEmpty else {
            result.found = true
            result.error = "No restrictedBool keys found in UserSettings.plist"
            return result
        }

        // Stub files: profile UUID -> display name + has-restrictions-payload flag
        var stubNames: [String: String] = [:]
        var stubHasRestrictions: [String: Bool] = [:]
        let mcstateDir = userSettingsFile.deletingLastPathComponent()
        if let stubPaths = try? FileManager.default.contentsOfDirectory(at: mcstateDir, includingPropertiesForKeys: nil) {
            for stubPath in stubPaths where stubPath.lastPathComponent.hasPrefix("profile-") && stubPath.pathExtension == "stub" {
                guard let stubData = FileLocating.safePlist(stubPath), let dict = stubData.asDict else { continue }
                let uuid = (dict["PayloadUUID"]?.stringified ?? "").trimmingCharacters(in: .whitespaces).uppercased()
                let name = (dict["PayloadDisplayName"]?.stringified ?? "").trimmingCharacters(in: .whitespaces)
                guard !uuid.isEmpty, !name.isEmpty else { continue }
                stubNames[uuid] = name
                let payloadTypes = (dict["PayloadContent"]?.asArray ?? []).compactMap { $0["PayloadType"]?.stringified }
                stubHasRestrictions[uuid] = payloadTypes.contains("com.apple.applicationaccess")
            }
        }

        var explicitlySet: [String: ExplicitEntry] = [:]
        if let eventsFile, let events = FileLocating.safePlist(eventsFile) {
            let rbRestr = events["Restrictions"]?["restrictedBool"]?.asDict ?? [:]
            // A single key can carry several sub-entries ("value",
            // "preference", "ask", "overrideUserSettings"), each its own
            // last-touch process/event — Dictionary iteration order isn't
            // guaranteed, so grabbing "whichever happens to be non-empty
            // first" could pick a different one across runs. "value" is the
            // one that actually reflects the enforced value's last writer,
            // so it's preferred; the others are only a fallback.
            let subKeyPriority = ["value", "preference", "ask", "overrideUserSettings"]

            for (key, outer) in rbRestr {
                guard let outerDict = outer.asDict, !outerDict.isEmpty else { continue }
                var innerVal: [String: PlistValue]?
                for subKey in subKeyPriority {
                    if let candidate = outerDict[subKey]?.asDict, !candidate.isEmpty {
                        innerVal = candidate
                        break
                    }
                }
                if innerVal == nil {
                    innerVal = outerDict.values.first(where: { !($0.asDict?.isEmpty ?? true) })?.asDict
                }
                guard let innerVal else { continue }

                // "remove" means this write REMOVED the restriction — it
                // isn't currently in effect, so it's not evidence of a live
                // profile/declaration attribution. Skipping it here leaves
                // the key to fall through to "default" below, which is the
                // correct read for a restriction with no active managed
                // source (this is what was producing fake "Profile"
                // attributions from long-gone, already-removed profiles).
                let event = (innerVal["event"]?.stringified ?? "").trimmingCharacters(in: .whitespaces)
                guard event != "remove" else { continue }

                let proc = (innerVal["process"]?.stringified ?? "").trimmingCharacters(in: .whitespaces)
                var tsStr = ""
                if let tsVal = innerVal["timestamp"], case .date(let d) = tsVal {
                    let fmt = DateFormatter()
                    fmt.dateFormat = "yyyy-MM-dd HH:mm:ss"
                    tsStr = fmt.string(from: d)
                } else if let tsVal = innerVal["timestamp"] {
                    tsStr = tsVal.stringified.trimmingCharacters(in: .whitespaces)
                }

                if let uuid = regexFirstMatch(uuidPrefixPattern, in: proc)?.uppercased(), let profileName = stubNames[uuid] {
                    // Only trust a UUID-shaped process as a "profile"
                    // attribution when it actually resolves to a real
                    // installed profile stub. MCSettingsEvents.plist's own
                    // internal actor IDs are UUID-shaped too (including
                    // Apple's own placeholder "00000000-0000-0000-A000-
                    // 4A414D460003") and aren't profiles at all — an
                    // unmatched UUID no longer gets a fabricated name from
                    // its own prefix and instead falls through to
                    // "default" below.
                    let implicit = !(stubHasRestrictions[uuid] ?? false)
                    explicitlySet[key] = ExplicitEntry(source: "profile", profileName: profileName, implicit: implicit, timestamp: tsStr)
                } else if hasDeclarations, !isKnownSystemProcess(proc) {
                    // Only attribute to a DDM declaration when the device
                    // actually has real declaration data (confirmed
                    // separately from rmd_inspect_system.txt) — a non-UUID
                    // process name alone was previously treated as proof of
                    // a declaration, which is how an unmanaged device with
                    // zero declarations still showed dozens of keys as
                    // "Declaration" (they were really MCMigrator restriction-
                    // cache rewrites, SpringBoard, and similar OS-internal
                    // writers, all filtered out by isKnownSystemProcess).
                    explicitlySet[key] = ExplicitEntry(source: "declaration", profileName: nil, implicit: false, timestamp: tsStr)
                }
                // Anything else — no matching profile stub, no confirmed
                // declaration — is left out of explicitlySet and falls
                // through to "default" below rather than guessing.
            }
        }

        var keysOut: [SettingsAttributionEntry] = []
        var profileCount = 0, declarationCount = 0, defaultCount = 0

        for key in restricted.keys.sorted() {
            let rawVal = restricted[key]!
            let valStr: String
            if case .bool(let b) = rawVal { valStr = b ? "true" : "false" }
            else if rawVal.isEmpty { valStr = "—" }
            else { valStr = rawVal.stringified }

            if let entry = explicitlySet[key] {
                keysOut.append(SettingsAttributionEntry(key: key, value: valStr, source: entry.source,
                                                          profileName: entry.profileName, implicit: entry.implicit,
                                                          timestamp: entry.timestamp))
                if entry.source == "profile" { profileCount += 1 } else { declarationCount += 1 }
            } else {
                keysOut.append(SettingsAttributionEntry(key: key, value: valStr, source: "default"))
                defaultCount += 1
            }
        }

        result.found = true
        result.total = keysOut.count
        result.profileCount = profileCount
        result.declarationCount = declarationCount
        result.defaultCount = defaultCount
        result.entries = keysOut
        return result
    }
}
