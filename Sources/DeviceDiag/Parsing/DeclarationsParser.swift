import Foundation

/// Port of `parse_declarations` — parses `rmd_inspect_system.txt` and
/// aggregates MDM declarations by Blueprint UUID.
enum DeclarationsParser {

    private static let blueprintUUIDPattern = #"Blueprint_([0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12})_"#

    private struct RawEntry {
        var identifier: String
        var loadState: String
        var active: Int
        var valid: String
        var allReasons: [String]
    }

    private struct BPAccumulator {
        var uuid: String
        var actType: String = ""
        var cfgType: String = ""
        var rawActs: [RawEntry] = []
        var rawCfgs: [RawEntry] = []
    }

    static func parse(root: URL, logArchive: URL?) -> DeclarationsResult {
        var result = DeclarationsResult()

        guard let rmdFile = FileLocating.findFile(root, "rmd_inspect_system.txt") else {
            return result // found = false
        }

        guard let data = FileLocating.rmdToPlistValue(rmdFile) else {
            result.found = true
            result.error = "plutil conversion failed — file may be malformed"
            return result
        }

        guard let sources = data["Detail"]?["Report"]?["Management Sources"]?.asArray else {
            result.found = true
            result.error = "Unexpected structure (no Management Sources)"
            return result
        }
        guard let source = sources.first else {
            result.found = true
            return result
        }

        let activations = source["activations"]?.asArray ?? []
        let configurations = source["configurations"]?.asArray ?? []
        let management = source["management"]?.asArray ?? []

        // Conduit / last-sync metadata
        if let cc = source["conduitConfig"], let st = cc["state"] {
            result.conduit.lastReceived = st["lastReceivedServerTokensFromServerTimestamp"]?.stringified ?? ""
            result.conduit.lastProcessed = st["lastProcessedDeclarationsToken"]?.stringified ?? ""
            result.conduit.consecutiveErrors = st["numberOfConsecutiveErrors"]?.asInt ?? 0
        }

        // Subscribed status key paths
        var statusItems: [StatusItem] = []
        if let kpEntries = source["subscribedStatusKeyPaths"]?.asArray {
            for kpEntry in kpEntries {
                guard let kp = kpEntry["keyPath"]?.asString, !kp.isEmpty else { continue }
                let rawNeedsSync = kpEntry["needsSync"]
                // Lenient on purpose: accepts "1"/true/"yes" with any surrounding
                // whitespace/case, rather than requiring an exact "1" match, in case
                // the underlying plist/plutil formatting differs from what's assumed.
                let needsSync = rawNeedsSync?.isLenientlyTruthy ?? false
                statusItems.append(StatusItem(keyPath: kp, needsSync: needsSync,
                                               lastReceivedDate: kpEntry["lastReceivedDate"]?.stringified ?? "",
                                               rawNeedsSyncDebug: rawNeedsSync?.debugDescription ?? "missing"))
            }
        }

        // Status section → per-identifier {active, valid, reasons}
        var statusByID: [String: (active: Int, valid: String, reasons: [String])] = [:]
        if let statusList = data["Detail"]?["Status"]?.asArray, let first = statusList.first,
           let decls = first["Status"]?["management"]?["declarations"] {
            for section in ["activations", "configurations", "management"] {
                guard let entries = decls[section]?.asArray else { continue }
                for entry in entries {
                    guard let ident = entry["identifier"]?.asString, !ident.isEmpty else { continue }
                    statusByID[ident] = (
                        active: entry["active"]?.isTruthyActive ?? false ? 1 : 0,
                        valid: entry["valid"]?.stringified ?? "",
                        reasons: extractReasonCodes(entry["reasons"])
                    )
                }
            }
        }

        var bpRaw: [String: BPAccumulator] = [:]
        var standalone: [StandaloneDeclaration] = []

        func bp(_ uuid: String, actType: String = "", cfgType: String = "") -> BPAccumulator {
            var acc = bpRaw[uuid] ?? BPAccumulator(uuid: uuid)
            if !actType.isEmpty { acc.actType = actType }
            if !cfgType.isEmpty { acc.cfgType = cfgType }
            bpRaw[uuid] = acc
            return acc
        }

        // Activations
        for act in activations {
            let ident = act["identifier"]?.asString ?? ""
            let bpUUID = extractBlueprintUUID(ident)
            let status = statusByID[ident]
            let state = act["state"]
            let inactiveReasons = extractReasonCodes(state?["inactiveReasons"])
            var combined = inactiveReasons
            for r in (status?.reasons ?? []) where !combined.contains(r) { combined.append(r) }

            let raw = RawEntry(identifier: ident, loadState: act["loadState"]?.asString ?? "",
                                active: state?["active"]?.isTruthyActive ?? false ? 1 : 0,
                                valid: status?.valid ?? "", allReasons: combined)
            if let bpUUID {
                var acc = bp(bpUUID, actType: act["declarationType"]?.asString ?? "")
                acc.rawActs.append(raw)
                bpRaw[bpUUID] = acc
            } else {
                standalone.append(StandaloneDeclaration(section: "activation", identifier: ident,
                    declarationType: act["declarationType"]?.asString ?? "",
                    loadState: act["loadState"]?.asString ?? "",
                    active: state?["active"]?.isTruthyActive ?? false ? 1 : 0))
            }
        }

        // Configurations
        for cfg in configurations {
            let ident = cfg["identifier"]?.asString ?? ""
            let bpUUID = extractBlueprintUUID(ident)
            let status = statusByID[ident]
            let raw = RawEntry(identifier: ident, loadState: cfg["loadState"]?.asString ?? "",
                                active: cfg["active"]?.isTruthyActive ?? false ? 1 : 0,
                                valid: status?.valid ?? "", allReasons: status?.reasons ?? [])
            if let bpUUID {
                var acc = bp(bpUUID, cfgType: cfg["declarationType"]?.asString ?? "")
                acc.rawCfgs.append(raw)
                bpRaw[bpUUID] = acc
            } else {
                standalone.append(StandaloneDeclaration(section: "configuration", identifier: ident,
                    declarationType: cfg["declarationType"]?.asString ?? "",
                    loadState: cfg["loadState"]?.asString ?? "",
                    active: cfg["active"]?.isTruthyActive ?? false ? 1 : 0))
            }
        }

        // Management
        for mgmt in management {
            let ident = mgmt["identifier"]?.asString ?? ""
            let bpUUID = extractBlueprintUUID(ident)
            let status = statusByID[ident]
            _ = bpUUID // management entries aren't grouped into blueprints in the original app either
            standalone.append(StandaloneDeclaration(section: "management", identifier: ident,
                declarationType: mgmt["declarationType"]?.asString ?? "",
                loadState: mgmt["loadState"]?.asString ?? "",
                active: (status?.active ?? 0) == 1 ? 1 : 0))
        }

        // Build final Blueprint records with grouped statuses
        var blueprints: [BlueprintDeclaration] = []
        for (uuid, acc) in bpRaw {
            blueprints.append(BlueprintDeclaration(
                uuid: uuid, actType: acc.actType, cfgType: acc.cfgType,
                activationGroups: groupByStatus(acc.rawActs),
                configGroups: groupByStatus(acc.rawCfgs)
            ))
        }
        blueprints.sort { $0.uuid < $1.uuid }

        // Enrich status items with values + log entries
        let staticValues = StaticStatusValuesParser.parse(root: root)
        if let logArchive, !statusItems.isEmpty {
            let kpList = statusItems.map { $0.keyPath }
            let logVals = LogArchiveService.readStatusItemLogs(archivePath: logArchive.path, keyPaths: kpList)
            let swValues = LogArchiveService.parseSoftwareUpdateStatusValues(archivePath: logArchive.path)
            var allValues = staticValues
            for (k, v) in swValues { allValues[k] = v }
            for i in statusItems.indices {
                statusItems[i].lastValue = allValues[statusItems[i].keyPath] ?? ""
                _ = logVals[statusItems[i].keyPath]
            }
        } else {
            for i in statusItems.indices {
                statusItems[i].lastValue = staticValues[statusItems[i].keyPath] ?? ""
            }
        }

        result.found = true
        result.blueprints = blueprints
        result.standalone = standalone
        result.statusItems = statusItems
        return result
    }

    private static func extractBlueprintUUID(_ identifier: String) -> String? {
        regexFirstMatch(blueprintUUIDPattern, in: identifier)
    }

    private static func extractReasonCodes(_ reasonsRaw: PlistValue?) -> [String] {
        guard let arr = reasonsRaw?.asArray else { return [] }
        var codes: [String] = []
        for r in arr {
            if let d = r.asDict {
                let code = d["code"]?.stringified ?? d["Code"]?.stringified ?? ""
                codes.append(code.isEmpty ? r.stringified : code)
            } else if !r.isEmpty {
                codes.append(r.stringified)
            }
        }
        return codes
    }

    private static func isOK(active: Int, valid: String) -> Bool {
        active == 1 && valid.lowercased() == "valid"
    }

    /// Port of `_group_by_status` — groups entries sharing the same (ok, reasons)
    /// signature, collapsing duplicates into a `count`.
    private static func groupByStatus(_ entries: [RawEntry]) -> [DeclarationStatusGroup] {
        struct Key: Hashable { var ok: Bool; var reasons: [String] }
        var groups: [Key: DeclarationStatusGroup] = [:]
        var order: [Key] = []
        for e in entries {
            let ok = isOK(active: e.active, valid: e.valid)
            let reasons = Array(Set(e.allReasons)).sorted()
            let key = Key(ok: ok, reasons: reasons)
            if var g = groups[key] {
                g.count += 1
                groups[key] = g
            } else {
                groups[key] = DeclarationStatusGroup(ok: ok, count: 1, active: e.active, valid: e.valid, reasons: reasons)
                order.append(key)
            }
        }
        return order.map { groups[$0]! }.sorted { a, b in
            if a.ok != b.ok { return a.ok }
            return a.reasons.lexicographicallyPrecedes(b.reasons)
        }
    }
}
