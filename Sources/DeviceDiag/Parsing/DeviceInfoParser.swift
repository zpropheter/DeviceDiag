import Foundation

/// Port of `parse_device_info` — macOS device identity from sw_vers.txt,
/// hardware overview text/plist files, hostname.txt, and IODeviceTree.txt.
enum DeviceInfoParser {

    static func parse(root: URL) -> DeviceInfo {
        var info = DeviceInfo()

        // sw_vers.txt
        if let f = FileLocating.findFile(root, "sw_vers.txt") ?? FileLocating.findFile(root, "sw_vers") {
            for line in FileLocating.safeRead(f).components(separatedBy: .newlines) {
                guard let idx = line.firstIndex(of: ":") else { continue }
                let key = line[line.startIndex..<idx].trimmingCharacters(in: .whitespaces)
                let val = line[line.index(after: idx)...].trimmingCharacters(in: .whitespaces)
                if key == "ProductVersion" { info.osVersion = val }
                else if key == "BuildVersion" { info.buildNumber = val }
            }
        }

        // Hardware text files
        for fname in ["hardware_overview.txt", "system_profiler.txt", "SPHardwareDataType.txt"] {
            guard let f = FileLocating.findFile(root, fname) else { continue }
            parseHardwareText(FileLocating.safeRead(f), into: &info)
            if info.serialNumber != "Not found" { break }
        }

        // Hardware .spx plist fallback
        if info.serialNumber == "Not found" {
            if let en = FileManager.default.enumerator(at: root, includingPropertiesForKeys: nil) {
                for case let url as URL in en {
                    guard url.pathExtension == "spx", url.lastPathComponent.lowercased().contains("hardware") else { continue }
                    if let data = FileLocating.safePlist(url) {
                        parseHardwarePlist(data, into: &info)
                    }
                    if info.serialNumber != "Not found" { break }
                }
            }
        }

        // Hostname — `hostname.txt` is actually `/bin/hostname`'s own
        // "#\n# /bin/hostname\n#\n<name>\n" comment-header format, not a
        // bare name, hence splitting on "#" and keeping the last piece.
        // That last piece still starts with the newline that followed the
        // final "#", though — `.whitespaces` (used below) only strips
        // horizontal whitespace, not newlines, so without
        // `.whitespacesAndNewlines` here the parsed hostname kept a leading
        // "\n" that rendered as a literal line break in the Device tab.
        if let f = FileLocating.findFile(root, "hostname.txt") ?? FileLocating.findFile(root, "hostname") {
            var val = FileLocating.safeRead(f).trimmingCharacters(in: .whitespacesAndNewlines)
            if !val.isEmpty {
                if val.contains("#") {
                    val = val.components(separatedBy: "#").last!.trimmingCharacters(in: .whitespacesAndNewlines)
                }
                if !val.isEmpty { info.hostname = val }
            }
        }

        // IODeviceTree.txt — fallback for serial number / model identifier
        if let f = FileLocating.findFile(root, "IODeviceTree.txt") {
            let text = FileLocating.safeRead(f)
            if info.serialNumber == "Not found", let m = firstMatch(#""IOPlatformSerialNumber"\s*=\s*"([^"]+)""#, in: text) {
                info.serialNumber = m
            }
            if info.modelIdentifier == "Not found", let m = firstMatch(#""model"\s*=\s*<"([^"]+)">"#, in: text) {
                info.modelIdentifier = m
            }
        }

        return info
    }

    private static func parseHardwareText(_ text: String, into info: inout DeviceInfo) {
        for line in text.components(separatedBy: .newlines) {
            guard !line.trimmingCharacters(in: .whitespaces).isEmpty, let idx = line.firstIndex(of: ":") else { continue }
            let keyRaw = line[line.startIndex..<idx].trimmingCharacters(in: .whitespaces)
            let val = line[line.index(after: idx)...].trimmingCharacters(in: .whitespaces)
            if val.isEmpty { continue }
            let low = keyRaw.lowercased()
            if low.contains("serial number") { info.serialNumber = val }
            else if low.hasPrefix("model name") { info.modelName = val }
            else if low.hasPrefix("model identifier") { info.modelIdentifier = val }
            else if low.contains("computer name") || low.contains("host name") { info.hostname = val }
        }
    }

    private static func parseHardwarePlist(_ data: PlistValue, into info: inout DeviceInfo) {
        guard let items = data["SPHardwareDataType"]?.asArray else { return }
        for item in items {
            guard let d = item.asDict else { continue }
            if let sn = d["serial_number"]?.asString, !sn.isEmpty { info.serialNumber = sn }
            if let mn = d["machine_name"]?.asString, !mn.isEmpty { info.modelName = mn }
            if let mm = d["machine_model"]?.asString, !mm.isEmpty { info.modelIdentifier = mm }
        }
    }

    private static func firstMatch(_ pattern: String, in text: String) -> String? {
        guard let re = try? NSRegularExpression(pattern: pattern) else { return nil }
        let range = NSRange(text.startIndex..., in: text)
        guard let match = re.firstMatch(in: text, range: range), match.numberOfRanges > 1,
              let r = Range(match.range(at: 1), in: text) else { return nil }
        return String(text[r])
    }
}

/// Shared regex helper used across several parsers. `options` defaults to
/// none, same as a bare Python `re.search` — pass `.dotMatchesLineSeparators`
/// for Python's `re.DOTALL`, `.anchorsMatchLines` for `re.MULTILINE`.
func regexFirstMatch(_ pattern: String, in text: String, group: Int = 1, options: NSRegularExpression.Options = []) -> String? {
    guard let re = try? NSRegularExpression(pattern: pattern, options: options) else { return nil }
    let range = NSRange(text.startIndex..., in: text)
    guard let match = re.firstMatch(in: text, range: range), match.numberOfRanges > group,
          let r = Range(match.range(at: group), in: text) else { return nil }
    return String(text[r])
}

func regexAllMatches(_ pattern: String, in text: String, options: NSRegularExpression.Options = []) -> [NSTextCheckingResult] {
    guard let re = try? NSRegularExpression(pattern: pattern, options: options) else { return [] }
    let range = NSRange(text.startIndex..., in: text)
    return re.matches(in: text, range: range)
}

/// Every captured group (1...N) of the first match, as an array of strings
/// (empty string for a group that didn't participate, e.g. an optional
/// `(...)?` group) — for patterns with more than one capture where pulling
/// each out individually via `regexFirstMatch(group:)` would mean matching
/// the same pattern repeatedly. Nil if the pattern didn't match at all.
func regexMatchGroups(_ pattern: String, in text: String, options: NSRegularExpression.Options = []) -> [String]? {
    guard let re = try? NSRegularExpression(pattern: pattern, options: options) else { return nil }
    let range = NSRange(text.startIndex..., in: text)
    guard let match = re.firstMatch(in: text, range: range) else { return nil }
    var groups: [String] = []
    for i in 1..<match.numberOfRanges {
        if let r = Range(match.range(at: i), in: text) {
            groups.append(String(text[r]))
        } else {
            groups.append("")
        }
    }
    return groups
}

/// Every match's captured groups (not just the first), for patterns used
/// with Python's `re.finditer` — e.g. pulling out every `route get` result
/// or every reachability probe in one pass.
func regexAllMatchGroups(_ pattern: String, in text: String, options: NSRegularExpression.Options = []) -> [[String]] {
    guard let re = try? NSRegularExpression(pattern: pattern, options: options) else { return [] }
    let range = NSRange(text.startIndex..., in: text)
    return re.matches(in: text, range: range).map { match in
        var groups: [String] = []
        for i in 1..<match.numberOfRanges {
            if let r = Range(match.range(at: i), in: text) {
                groups.append(String(text[r]))
            } else {
                groups.append("")
            }
        }
        return groups
    }
}
