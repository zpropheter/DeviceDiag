import Foundation

/// Port of the Python file-location helpers (`find_sydiagnose_root`, `find_file`,
/// `find_path`, `find_logarchive`, `safe_read`, `safe_plist`).
enum FileLocating {

    /// If `path` is a directory containing exactly one subdirectory whose name
    /// contains "sysdiagnose"/"sydiagnose", descend into it. Otherwise return as-is.
    static func findSysdiagnoseRoot(_ path: URL) -> URL {
        var isDir: ObjCBool = false
        guard FileManager.default.fileExists(atPath: path.path, isDirectory: &isDir), isDir.boolValue else {
            return path
        }
        guard let entries = try? FileManager.default.contentsOfDirectory(at: path, includingPropertiesForKeys: nil) else {
            return path
        }
        let subdirs = entries.filter { url in
            var d: ObjCBool = false
            FileManager.default.fileExists(atPath: url.path, isDirectory: &d)
            return d.boolValue
        }
        if subdirs.count == 1 {
            let name = subdirs[0].lastPathComponent.lowercased()
            if name.contains("sysdiagnose") || name.contains("sydiagnose") {
                return subdirs[0]
            }
        }
        return path
    }

    /// Recursively find the first *file* named `name` under `root`.
    static func findFile(_ root: URL, _ name: String) -> URL? {
        guard let en = FileManager.default.enumerator(at: root, includingPropertiesForKeys: [.isRegularFileKey], options: []) else { return nil }
        for case let url as URL in en {
            if url.lastPathComponent == name {
                var isDir: ObjCBool = false
                if FileManager.default.fileExists(atPath: url.path, isDirectory: &isDir), !isDir.boolValue {
                    return url
                }
            }
        }
        return nil
    }

    /// Like findFile but also matches directories (e.g. `.logarchive` bundles).
    static func findPath(_ root: URL, _ name: String) -> URL? {
        guard let en = FileManager.default.enumerator(at: root, includingPropertiesForKeys: nil, options: []) else { return nil }
        for case let url as URL in en {
            if url.lastPathComponent == name {
                return url
            }
        }
        return nil
    }

    /// Recursively finds the first *file* whose path ends with `suffix` —
    /// port of the network report script's `find_file(root, suffix)`. Needed
    /// because some sysdiagnose filenames aren't unique on their own (e.g.
    /// `ifconfig.txt` exists under both `network-info/` and `WiFi/`), so a
    /// bare filename search like `findFile` can't tell them apart; searching
    /// by a longer path suffix (`"network-info/ifconfig.txt"`) can.
    static func findPathSuffix(_ root: URL, suffix: String) -> URL? {
        guard let en = FileManager.default.enumerator(at: root, includingPropertiesForKeys: [.isRegularFileKey], options: []) else { return nil }
        for case let url as URL in en {
            guard url.path.hasSuffix(suffix) else { continue }
            var isDir: ObjCBool = false
            if FileManager.default.fileExists(atPath: url.path, isDirectory: &isDir), !isDir.boolValue {
                return url
            }
        }
        return nil
    }

    static func findLogarchive(_ root: URL) -> URL? {
        guard let en = FileManager.default.enumerator(at: root, includingPropertiesForKeys: nil, options: []) else { return nil }
        for case let url as URL in en {
            if url.pathExtension == "logarchive" {
                return url
            }
        }
        return nil
    }

    /// Recursively find all files/dirs matching a name, honoring a "prefer path
    /// containing this component" rule (used for `Shared/` vs `User/` variants).
    static func findAll(_ root: URL, named name: String) -> [URL] {
        guard let en = FileManager.default.enumerator(at: root, includingPropertiesForKeys: nil, options: []) else { return [] }
        var results: [URL] = []
        for case let url as URL in en {
            if url.lastPathComponent == name {
                results.append(url)
            }
        }
        return results
    }

    /// Recursively find all *files* whose name starts with `prefix` — used
    /// for "grab every launchctl-*.txt dump" style collections where the
    /// exact filenames vary by UID and aren't worth enumerating one by one.
    static func findAllMatchingPrefix(_ root: URL, prefix: String) -> [URL] {
        guard let en = FileManager.default.enumerator(at: root, includingPropertiesForKeys: [.isRegularFileKey], options: []) else { return [] }
        var results: [URL] = []
        for case let url as URL in en {
            guard url.lastPathComponent.hasPrefix(prefix) else { continue }
            var isDir: ObjCBool = false
            if FileManager.default.fileExists(atPath: url.path, isDirectory: &isDir), !isDir.boolValue {
                results.append(url)
            }
        }
        return results.sorted { $0.lastPathComponent < $1.lastPathComponent }
    }

    static func findPreferring(_ root: URL, named name: String, pathContains component: String) -> URL? {
        let all = findAll(root, named: name)
        if let preferred = all.first(where: { $0.pathComponents.contains(component) }) {
            return preferred
        }
        return all.first
    }

    static func safeRead(_ url: URL?) -> String {
        guard let url else { return "" }
        guard let data = try? Data(contentsOf: url) else { return "" }
        return String(data: data, encoding: .utf8) ?? String(decoding: data, as: UTF8.self)
    }

    /// Loads a binary/XML plist (Apple's real plist formats) into a PlistValue tree.
    static func safePlist(_ url: URL?) -> PlistValue? {
        guard let url else { return nil }
        guard let data = try? Data(contentsOf: url) else { return nil }
        guard let obj = try? PropertyListSerialization.propertyList(from: data, options: [], format: nil) else { return nil }
        return .from(any: obj)
    }

    /// Parses a file as an Apple ASCII/NeXTSTEP plist using the pure-Swift parser.
    static func parseAsciiPlist(_ url: URL?) -> PlistValue? {
        guard let url else { return nil }
        let text = safeRead(url)
        guard !text.isEmpty else { return nil }
        return AsciiPlistParser(text).parse()
    }

    /// Mirrors `_rmd_to_json`: try `plutil -convert json` first (handles Apple's
    /// old-style ASCII plist quirks the same way macOS itself does), falling back
    /// to the pure-Swift ASCII parser if `plutil` fails or is unavailable.
    static func rmdToPlistValue(_ url: URL) -> PlistValue? {
        let proc = Process()
        proc.executableURL = URL(fileURLWithPath: "/usr/bin/plutil")
        proc.arguments = ["-convert", "json", "-o", "-", url.path]
        let pipe = Pipe()
        proc.standardOutput = pipe
        proc.standardError = Pipe()
        do {
            try proc.run()
            let data = pipe.fileHandleForReading.readDataToEndOfFile()
            proc.waitUntilExit()
            if proc.terminationStatus == 0, !data.isEmpty,
               let json = try? JSONSerialization.jsonObject(with: data) {
                return .from(any: json)
            }
        } catch {
            // fall through to ASCII parser
        }
        return parseAsciiPlist(url)
    }
}
