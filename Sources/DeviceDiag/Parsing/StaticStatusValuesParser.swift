import Foundation

/// Port of `parse_static_status_values` — extracts MDM status key-path values
/// from static sysdiagnose files (not the logarchive). All values are suffixed
/// with " *" to indicate they're implied rather than sourced live from the MDM
/// reporting channel.
enum StaticStatusValuesParser {
    private static let star = " *"

    static func parse(root: URL) -> [String: String] {
        var values: [String: String] = [:]

        // sw_vers.txt
        if let f = FileLocating.findFile(root, "sw_vers.txt") ?? FileLocating.findFile(root, "sw_vers") {
            var sw: [String: String] = [:]
            for line in FileLocating.safeRead(f).components(separatedBy: .newlines) {
                guard let idx = line.firstIndex(of: ":") else { continue }
                let k = line[line.startIndex..<idx].trimmingCharacters(in: .whitespaces)
                let v = line[line.index(after: idx)...].trimmingCharacters(in: .whitespaces)
                sw[k] = v
            }
            if let pv = sw["ProductVersion"] {
                values["device.operating-system.version"] = pv + star
                let mkt = MarketingNames.macOSMarketingName(pv)
                if !mkt.isEmpty { values["device.operating-system.marketing-name"] = mkt + star }
            }
            if let pn = sw["ProductName"] {
                values["device.operating-system.family"] = pn + star
            }
            if let extra = sw["ProductVersionExtra"] {
                values["device.operating-system.supplemental.extra-version"] = extra + star
                if let bv = sw["BuildVersion"] {
                    values["device.operating-system.supplemental.build-version"] = bv + star
                }
            } else if let bv = sw["BuildVersion"] {
                values["device.operating-system.build-version"] = bv + star
            }
        }

        // IODeviceTree.txt
        if let f = FileLocating.findFile(root, "IODeviceTree.txt") {
            let text = FileLocating.safeRead(f)
            if let m = regexFirstMatch(#""IOPlatformSerialNumber"\s*=\s*"([^"]+)""#, in: text) {
                values["device.identifier.serial-number"] = m + star
            }
            if let m = regexFirstMatch(#""IOPlatformUUID"\s*=\s*"([^"]+)""#, in: text) {
                values["device.identifier.udid"] = m + star
            }
            if let m = regexFirstMatch(#""model"\s*=\s*<"([^"]+)">"#, in: text) {
                values["device.model.identifier"] = m + star
            }
        }

        // remotectl_dumpstate.txt
        if let f = FileLocating.findFile(root, "remotectl_dumpstate.txt") {
            let text = FileLocating.safeRead(f)
            if let m = regexFirstMatch(#"UniqueDeviceID\s*=>\s*(\S+)"#, in: text) {
                values["device.identifier.udid"] = m.trimmingCharacters(in: .whitespaces) + star
            }
            if let m = regexFirstMatch(#"SupplementalBuildVersion\s*=>\s*(\S+)"#, in: text) {
                values["device.operating-system.supplemental.build-version"] = m.trimmingCharacters(in: .whitespaces) + star
            }
            if let m = regexFirstMatch(#"DeviceClass\s*=>\s*(\S+)"#, in: text) {
                values["device.model.family"] = m.trimmingCharacters(in: .whitespaces) + star
            }
        }

        // SPHardwareDataType.spx
        if let f = FileLocating.findFile(root, "SPHardwareDataType.spx"), let data = FileLocating.safePlist(f) {
            if let arr = data.asArray, let first = arr.first, let items = first["_items"]?.asArray, let hw = items.first?.asDict {
                if let mn = hw["model_number"]?.asString?.trimmingCharacters(in: .whitespaces), !mn.isEmpty {
                    values["device.model.number"] = mn + star
                }
                if let name = hw["machine_name"]?.asString?.trimmingCharacters(in: .whitespaces), !name.isEmpty {
                    values["device.model.marketing-name"] = name + star
                }
            }
        }

        // disks.txt → filevault
        if let f = FileLocating.findFile(root, "disks.txt") {
            if let m = regexFirstMatch(#"FileVault:\s+(Yes|No)"#, in: FileLocating.safeRead(f)) {
                values["diskmanagement.filevault.enabled"] = (m == "Yes" ? "true" : "false") + star
            }
        }

        // install.log → beta enrollment (last occurrence wins, scanning newest-first)
        if let f = FileLocating.findFile(root, "install.log") {
            let lines = FileLocating.safeRead(f).components(separatedBy: .newlines)
            var betaVal: String?
            for line in lines.reversed() {
                if let m = regexFirstMatch(#"Beta enrollment is enabled[:\s]+(\S[^{]*?)(?:\s*\{|$)"#, in: line) {
                    betaVal = m.trimmingCharacters(in: .whitespaces) + star
                    break
                }
                if line.range(of: "Beta enrollment is disabled", options: .caseInsensitive) != nil {
                    betaVal = "disabled" + star
                    break
                }
            }
            if let betaVal { values["softwareupdate.beta-enrollment"] = betaVal }
        }

        return values
    }
}
