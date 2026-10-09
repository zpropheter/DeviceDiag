import Foundation

/// Port of `parse_config_profiles` — parses SPConfigurationProfileDataType.spx
/// (macOS System Profiler binary plist) into a normalized profile list.
enum ConfigProfilesParser {

    private static let isoDatePattern = #"\((\d{4}-\d{2}-\d{2} [\d:]+)"#

    static func parse(root: URL) -> ConfigProfilesResult {
        var result = ConfigProfilesResult()

        guard let spx = FileLocating.findFile(root, "SPConfigurationProfileDataType.spx") else {
            return result
        }
        guard let data = FileLocating.safePlist(spx) else {
            result.found = true
            result.error = "Failed to parse SPX"
            return result
        }
        guard let topItems = data.asArray?.first?["_items"]?.asArray else {
            result.found = true
            result.error = "Unexpected SPX structure"
            return result
        }

        // Roughly macOS Ventura onward, `system_profiler` stopped returning a
        // flat profile list here and instead groups results by scope — two
        // wrapper dicts, each named something like "Device Configuration
        // Profiles" / "User Configuration Profiles", each holding its own
        // `_items` array of the real profile dicts. Older macOS (and
        // presumably any future reshuffle) may still hand back real profile
        // dicts directly at this level with no wrapper at all.
        //
        // This used to assume one fixed depth (`topItems.first?["_items"]`),
        // which silently discarded every scope after the first — if "User"
        // sorted first and only had one profile in it, that's literally all
        // that ever rendered, no matter how many "Device" profiles existed.
        // Instead, classify every element structurally and recurse into
        // anything that isn't a profile itself, tagging whatever's found
        // inside with that group's scope.
        var profiles: [ConfigProfileEntry] = []
        for item in topItems {
            collectProfiles(from: item, scope: "", into: &profiles)
        }

        result.found = true
        result.profiles = profiles
        return result
    }

    /// A real profile dict carries its own metadata keys; a scope-group
    /// wrapper dict (e.g. "Device Configuration Profiles") only carries
    /// `_name` + `_items` and none of these.
    private static func looksLikeProfile(_ d: [String: PlistValue]) -> Bool {
        d["spconfigprofile_profile_identifier"] != nil
            || d["spconfigprofile_install_date"] != nil
            || d["spconfigprofile_organization"] != nil
    }

    private static func scopeLabel(fromGroupName name: String) -> String {
        if name.localizedCaseInsensitiveContains("device") { return "Device" }
        if name.localizedCaseInsensitiveContains("user") { return "User" }
        if name.localizedCaseInsensitiveContains("provisioning") { return "Provisioning" }
        return ""
    }

    private static func collectProfiles(from item: PlistValue, scope: String, into profiles: inout [ConfigProfileEntry]) {
        guard let d = item.asDict else { return }

        if looksLikeProfile(d) {
            profiles.append(makeProfile(from: d, scope: scope))
            return
        }

        if let nested = d["_items"]?.asArray {
            // Not a profile itself, but has its own `_items` — a scope
            // group (Device / User / Provisioning, or whatever Apple calls
            // the next one). Recurse, carrying its scope down to whatever's
            // inside.
            let groupName = d["_name"]?.stringified ?? ""
            let groupScope = scopeLabel(fromGroupName: groupName)
            for nestedItem in nested {
                collectProfiles(from: nestedItem, scope: groupScope.isEmpty ? scope : groupScope, into: &profiles)
            }
            return
        }

        // Terminal leaf — no `_items` to recurse into, and it didn't match
        // the MDM config-profile shape. Provisioning profiles land here:
        // they carry a completely different field set (team/expiration/UUID
        // instead of organization/install-source/verification-state), so
        // `looksLikeProfile` never matches them, and unlike config profiles
        // they have no nested payload list either. Capture by name rather
        // than silently dropping it — this is exactly the class of item
        // that went missing before this function existed.
        guard d["_name"] != nil else { return }
        profiles.append(makeProfile(from: d, scope: scope))
    }

    private static func makeProfile(from d: [String: PlistValue], scope: String) -> ConfigProfileEntry {
        let name = d["_name"]?.stringified.trimmingCharacters(in: .whitespaces) ?? ""

        guard looksLikeProfile(d) else {
            // Provisioning profile (or any other non-MDM leaf in this
            // report). Field names here are a best-effort match to Apple's
            // `spprovisioningprofile_*` naming convention — the same pattern
            // `spconfigprofile_*` follows for MDM profiles — but unverified
            // against a real sample. If these come up blank in practice,
            // this is the first place to check real key names against an
            // actual SPX dump.
            let team = d["spprovisioningprofile_team_name"]?.stringified.trimmingCharacters(in: .whitespaces) ?? ""
            let uuid = d["spprovisioningprofile_UUID"]?.stringified.trimmingCharacters(in: .whitespaces) ?? ""
            let expires = d["spprovisioningprofile_expiration_date"]?.stringified.trimmingCharacters(in: .whitespaces) ?? ""
            return ConfigProfileEntry(
                name: name,
                org: team,
                installDate: expires,
                identifier: uuid,
                scope: scope.isEmpty ? "Provisioning" : scope,
                payloads: []
            )
        }

        let rawDate = d["spconfigprofile_install_date"]?.stringified ?? ""
        let installDate = regexFirstMatch(isoDatePattern, in: rawDate) ?? String(rawDate.prefix(30)).trimmingCharacters(in: .whitespaces)

        var payloads: [ConfigProfilePayload] = []
        for pl in (d["_items"]?.asArray ?? []) {
            guard let pd = pl.asDict else { continue }
            let displayName = pd["spconfigprofile_payload_display_name"]?.stringified.trimmingCharacters(in: .whitespaces)
            let payloadName = pd["_name"]?.stringified ?? ""
            payloads.append(ConfigProfilePayload(
                displayName: ((displayName?.isEmpty ?? true) ? payloadName : displayName!),
                domain: payloadName.trimmingCharacters(in: .whitespaces),
                payloadData: pd["spconfigprofile_payload_data"]?.stringified.trimmingCharacters(in: .whitespaces) ?? ""
            ))
        }

        return ConfigProfileEntry(
            name: name,
            org: d["spconfigprofile_organization"]?.stringified.trimmingCharacters(in: .whitespaces) ?? "",
            source: d["spconfigprofile_install_source"]?.stringified.trimmingCharacters(in: .whitespaces) ?? "",
            installDate: installDate,
            removalDisallowed: (d["spconfigprofile_RemovalDisallowed"]?.stringified.lowercased() == "yes"),
            verified: (d["spconfigprofile_verification_state"]?.stringified.lowercased() == "verified"),
            identifier: d["spconfigprofile_profile_identifier"]?.stringified.trimmingCharacters(in: .whitespaces) ?? "",
            scope: scope,
            payloads: payloads
        )
    }
}

/// Port of `extract_managed_settings` — scans parsed config profile payloads
/// for managed notifications, PPPC identifiers, and managed login items.
enum ManagedSettingsExtractor {
    static func extract(profiles: [ConfigProfileEntry]) -> ManagedSettings {
        var settings = ManagedSettings()
        var seenNotif = Set<String>()
        var seenPPPC = Set<String>()
        var seenLogin = Set<String>()

        for profile in profiles {
            for payload in profile.payloads {
                guard !payload.payloadData.isEmpty else { continue }
                let parsed = AsciiPlistParser(payload.payloadData).parse()
                guard let dict = parsed.asDict else { continue }

                switch payload.domain {
                case "com.apple.notificationsettings":
                    for item in (dict["NotificationSettings"]?.asArray ?? []) {
                        guard let bid = item["BundleIdentifier"]?.asString?.trimmingCharacters(in: .whitespaces), !bid.isEmpty else { continue }
                        if seenNotif.insert(bid).inserted { settings.managedNotifications.append(bid) }
                    }
                case "com.apple.TCC.configuration-profile-policy":
                    if let services = dict["Services"]?.asDict {
                        for entries in services.values {
                            for entry in (entries.asArray ?? []) {
                                guard let ident = entry["Identifier"]?.asString?.trimmingCharacters(in: .whitespaces), !ident.isEmpty else { continue }
                                if seenPPPC.insert(ident).inserted { settings.pppcIdentifiers.append(ident) }
                            }
                        }
                    }
                case "com.apple.servicemanagement":
                    for rule in (dict["Rules"]?.asArray ?? []) {
                        guard let comment = rule["Comment"]?.asString?.trimmingCharacters(in: .whitespaces), !comment.isEmpty else { continue }
                        if seenLogin.insert(comment).inserted { settings.managedLoginItems.append(comment) }
                    }
                default:
                    break
                }
            }
        }
        return settings
    }
}
