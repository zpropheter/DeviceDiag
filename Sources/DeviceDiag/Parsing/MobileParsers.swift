import Foundation

/// Port of `is_mobile_sysdiagnose` — detects iOS/iPadOS vs macOS archives.
enum PlatformDetector {
    static func isMobile(root: URL) -> Bool {
        if FileLocating.findFile(root, "sw_vers.txt") != nil || FileLocating.findFile(root, "sw_vers") != nil {
            return false
        }
        guard let sysver = FileLocating.findFile(root, "SystemVersion.plist"),
              let data = FileLocating.safePlist(sysver) else { return false }
        let product = data["ProductName"]?.asString ?? ""
        return product.contains("iPhone") || product.contains("iPad") || product.lowercased().contains("ios")
    }
}

/// Port of `parse_mobile_device_info`.
enum MobileDeviceInfoParser {
    static func parse(root: URL) -> MobileDeviceInfo {
        var info = MobileDeviceInfo()

        if let rc = FileLocating.findFile(root, "remotectl_dumpstate.txt") {
            let text = FileLocating.safeRead(rc)
            let map: [String: String] = [
                "SerialNumber": "serial", "UniqueDeviceID": "udid", "ProductType": "modelIdentifier",
                "ModelNumber": "modelNumber", "DeviceClass": "deviceClass",
                "OSVersion": "osVersion", "BuildVersion": "buildNumber",
            ]
            for line in text.components(separatedBy: .newlines) {
                guard let range = line.range(of: "=>") else { continue }
                let key = String(line[line.startIndex..<range.lowerBound]).trimmingCharacters(in: .whitespaces)
                let val = String(line[range.upperBound...]).trimmingCharacters(in: .whitespaces)
                guard let field = map[key], !val.isEmpty else { continue }
                switch field {
                case "serial": info.serialNumber = val
                case "udid": info.udid = val
                case "modelIdentifier": info.modelIdentifier = val
                case "modelNumber": info.modelNumber = val
                case "deviceClass": info.deviceClass = val
                case "osVersion": info.osVersion = val
                case "buildNumber": info.buildNumber = val
                default: break
                }
            }
        }

        if let iodt = FileLocating.findFile(root, "IODeviceTree.txt") {
            let text = FileLocating.safeRead(iodt)
            if info.serialNumber == "Not found", let m = regexFirstMatch(#""IOPlatformSerialNumber"\s*=\s*"([^"]+)""#, in: text) { info.serialNumber = m }
            if info.udid == "Not found", let m = regexFirstMatch(#""IOPlatformUUID"\s*=\s*"([^"]+)""#, in: text) { info.udid = m }
            if info.modelIdentifier == "Not found", let m = regexFirstMatch(#""model"\s*=\s*<"([^"]+)">"#, in: text) { info.modelIdentifier = m }
        }

        // SystemVersion.plist — prefer path not containing "Splat"
        let candidates = FileLocating.findAll(root, named: "SystemVersion.plist")
        if let sysver = candidates.first(where: { !$0.pathComponents.contains("Splat") }) ?? candidates.first,
           let data = FileLocating.safePlist(sysver) {
            if let pv = data["ProductVersion"]?.asString?.trimmingCharacters(in: .whitespaces), !pv.isEmpty { info.osVersion = pv }
            if let pb = data["ProductBuildVersion"]?.asString?.trimmingCharacters(in: .whitespaces), !pb.isEmpty { info.buildNumber = pb }
        }

        let dc = info.deviceClass
        let pv = info.osVersion != "Not found" ? info.osVersion : ""
        if !dc.isEmpty, !pv.isEmpty {
            info.osFamily = dc.lowercased() == "ipad" ? "iPadOS" : "iOS"
            info.marketingName = MarketingNames.iosMarketingName(pv, deviceClass: dc)
        } else if !pv.isEmpty {
            info.osFamily = "iPhone OS"
            info.marketingName = MarketingNames.iosMarketingName(pv, deviceClass: "")
        }

        if let ccd = FileLocating.findFile(root, "CloudConfigurationDetails.plist"), let data = FileLocating.safePlist(ccd) {
            info.isSupervised = data["IsSupervised"]?.asBool ?? false
            info.isRTS = data["IsReturnToService"]?.asBool ?? false
        }

        return info
    }
}

/// Port of `parse_mobile_enrollment_info`.
enum MobileEnrollmentParser {
    static func parse(root: URL) -> MobileEnrollmentInfo {
        var info = MobileEnrollmentInfo()
        let mdmPlist = FileLocating.findPreferring(root, named: "MDM.plist", pathContains: "Shared")
        guard let mdmPlist, let data = FileLocating.safePlist(mdmPlist) else { return info }
        info.mdmProfileID = data["ManagingProfileIdentifier"]?.stringified.trimmingCharacters(in: .whitespaces) ?? ""
        info.serverURL = data["ServerURL"]?.stringified.trimmingCharacters(in: .whitespaces) ?? ""
        info.isADE = data["IsADEProfile"]?.asBool ?? false
        info.topic = data["Topic"]?.stringified.trimmingCharacters(in: .whitespaces) ?? ""
        return info
    }
}

/// Port of `parse_mobile_managed_apps` — MDMAppManagement.plist.
enum MobileManagedAppsParser {
    private static let stateLabels: [Int: String] = [
        0: "Unknown", 1: "Queued", 2: "Prompting User", 3: "Pending Install",
        4: "Managed", 5: "Waiting for Login", 6: "Update Available",
        7: "Managed (Installed)", 8: "Managed (Validated)", 9: "Removal Queued",
    ]
    private static let flagLabels: [(Int, String)] = [
        (1, "Managed"), (2, "Remove on Unenrollment"), (4, "VPP"), (8, "Per-Device VPP"),
        (16, "Device-Based VPP"), (32, "Externally Owned"), (64, "Has Configuration"), (128, "Has Feedback"),
    ]

    static func parse(root: URL) -> [ManagedApp] {
        guard let appPlist = FileLocating.findFile(root, "MDMAppManagement.plist"),
              let data = FileLocating.safePlist(appPlist),
              let metadata = data["metadataByBundleID"]?.asDict else { return [] }

        var apps: [ManagedApp] = []
        for bundleID in metadata.keys.sorted() {
            guard let meta = metadata[bundleID]?.asDict else { continue }
            let stateInt = meta["state"]?.asInt ?? 0
            let flagsInt = meta["flags"]?.asInt ?? 0
            let removable = meta["Attributes"]?["Removable"]?.asBool ?? true
            apps.append(ManagedApp(
                bundleID: bundleID, stateRaw: stateInt,
                state: stateLabels[stateInt] ?? "State \(stateInt)",
                flags: decodeFlags(flagsInt), removable: removable
            ))
        }
        return apps
    }

    private static func decodeFlags(_ flags: Int) -> String {
        guard flags != 0 else { return "—" }
        let matched = flagLabels.filter { flags & $0.0 != 0 }.map { $0.1 }
        return matched.isEmpty ? "flags=\(flags)" : matched.joined(separator: ", ")
    }
}

/// Port of `parse_mobile_profiles` — PayloadManifest.plist + profile-*.stub files.
enum MobileProfilesParser {
    static func parse(root: URL) -> ConfigProfilesResult {
        var result = ConfigProfilesResult()

        let manifestFile = FileLocating.findPreferring(root, named: "PayloadManifest.plist", pathContains: "Shared")
        guard let manifestFile, let manifestData = FileLocating.safePlist(manifestFile) else {
            return result
        }

        let orderedUUIDs = (manifestData["OrderedProfiles"]?.asArray ?? []).compactMap { $0.asString }.filter { !$0.isEmpty }

        let mcstateDir = manifestFile.deletingLastPathComponent()
        let stubFiles = (try? FileManager.default.contentsOfDirectory(at: mcstateDir, includingPropertiesForKeys: nil))?
            .filter { $0.lastPathComponent.hasPrefix("profile-") && $0.pathExtension == "stub" }
            .sorted { $0.lastPathComponent < $1.lastPathComponent } ?? []

        let skipKeys: Set<String> = ["PayloadType", "PayloadDisplayName", "PayloadUUID", "PayloadVersion",
                                      "PayloadIdentifier", "PayloadDescription", "PayloadOrganization"]

        var stubByUUID: [String: ConfigProfileEntry] = [:]
        for stubPath in stubFiles {
            guard let stubData = FileLocating.safePlist(stubPath), let dict = stubData.asDict else { continue }

            var uuid = dict["PayloadUUID"]?.stringified.trimmingCharacters(in: .whitespaces) ?? ""
            if uuid.isEmpty {
                let stem = stubPath.deletingPathExtension().lastPathComponent
                let parts = stem.split(separator: "-", maxSplits: 1)
                uuid = parts.count > 1 ? String(parts[1]) : ""
            }
            guard !uuid.isEmpty else { continue }

            let installDate = dict["InstallDate"].map { v -> String in
                if case .date(let d) = v {
                    let fmt = DateFormatter()
                    fmt.dateFormat = "yyyy-MM-dd HH:mm:ss"
                    return fmt.string(from: d)
                }
                return String(v.stringified.prefix(30)).trimmingCharacters(in: .whitespaces)
            } ?? ""

            var payloads: [ConfigProfilePayload] = []
            for pl in (dict["PayloadContent"]?.asArray ?? []) {
                guard let pld = pl.asDict else { continue }
                let domain = pld["PayloadType"]?.stringified.trimmingCharacters(in: .whitespaces) ?? ""
                var displayName = pld["PayloadDisplayName"]?.stringified.trimmingCharacters(in: .whitespaces) ?? ""
                if displayName.isEmpty { displayName = domain }
                let filtered = pld.filter { !skipKeys.contains($0.key) }
                let payloadStr = filtered.isEmpty ? "" : jsonStringify(filtered)
                payloads.append(ConfigProfilePayload(displayName: displayName, domain: domain, payloadData: payloadStr))
            }

            stubByUUID[uuid] = ConfigProfileEntry(
                name: dict["PayloadDisplayName"]?.stringified.trimmingCharacters(in: .whitespaces) ?? "",
                org: dict["PayloadOrganization"]?.stringified.trimmingCharacters(in: .whitespaces) ?? "",
                installDate: installDate,
                identifier: dict["PayloadIdentifier"]?.stringified.trimmingCharacters(in: .whitespaces) ?? "",
                uuid: uuid,
                description: dict["PayloadDescription"]?.stringified.trimmingCharacters(in: .whitespaces) ?? "",
                payloads: payloads
            )
        }

        var profiles: [ConfigProfileEntry] = []
        var seen = Set<String>()
        for uuid in orderedUUIDs {
            if let p = stubByUUID[uuid] { profiles.append(p); seen.insert(uuid) }
        }
        for (uuid, p) in stubByUUID where !seen.contains(uuid) { profiles.append(p) }

        result.found = !profiles.isEmpty || true
        result.profiles = profiles
        return result
    }

    private static func jsonStringify(_ dict: [String: PlistValue]) -> String {
        func toAny(_ v: PlistValue) -> Any {
            switch v {
            case .string(let s): return s
            case .int(let i): return i
            case .bool(let b): return b
            case .double(let d): return d
            case .date(let d): return ISO8601DateFormatter().string(from: d)
            case .data: return "<data>"
            case .array(let a): return a.map(toAny)
            case .dict(let d): var out: [String: Any] = [:]; for (k, v) in d { out[k] = toAny(v) }; return out
            case .null: return NSNull()
            }
        }
        let obj = dict.mapValues(toAny)
        guard let data = try? JSONSerialization.data(withJSONObject: obj, options: [.prettyPrinted, .sortedKeys]) else { return "" }
        return String(data: data, encoding: .utf8) ?? ""
    }
}
