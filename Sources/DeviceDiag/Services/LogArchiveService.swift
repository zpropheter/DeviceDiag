import Foundation

/// Predefined `log show` categories/topics for the Troubleshooting tab.
/// Originally a direct port of `TROUBLESHOOT_TOPICS` from the Flask app,
/// which only ever targeted macOS. iOS/iPadOS sysdiagnoses often use
/// different process/subsystem names for the same underlying activity
/// (macOS's `mdmclient`/`com.apple.ManagedClient` vs. iOS's `mdmd`/
/// `com.apple.ManagedConfiguration`, most notably), and some topics are
/// macOS-only concepts that don't exist on iOS at all (Gatekeeper, XProtect,
/// Endpoint Security/System Extensions, LaunchDaemons, and Jamf products
/// with no iOS/iPadOS agent). Every topic's `platform` field says which of
/// those three buckets it's in — see `LogTopicDefinition.resolvedPredicate`.
enum TroubleshootCatalog {
    static let topics: [String: [String: LogTopicDefinition]] = [
        "App Installation and Packages": [
            "App Store / StoreKit installs": .init(extraArgs: ["--info"], predicate: #"subsystem CONTAINS "com.apple.commerce""#),
            "Installer / package activity": .init(extraArgs: ["--info"], predicate: #"process == "installer""#, platform: .macOSOnly),
            "LaunchDaemon / LaunchAgent loading": .init(extraArgs: ["--info"], predicate: #"process == "launchd""#, platform: .macOSOnly),
        ],
        "Authentication and Identity": [
            "Kerberos / Active Directory auth": .init(extraArgs: ["--info"], predicate: #"subsystem CONTAINS "com.apple.Kerberos""#, platform: .macOSOnly),
            "Local authentication / PAM": .init(extraArgs: ["--info"], predicate: #"subsystem == "com.apple.authorization""#, platform: .macOSOnly),
            "Platform SSO (PSSO) activity": .init(extraArgs: ["--info"], predicate: #"subsystem CONTAINS "com.apple.AppSSO""#),
        ],
        "Device Compliance": [
            "Device Compliance": .init(extraArgs: ["--debug", "--info"], predicate: #"subsystem CONTAINS "jamfAAD" OR subsystem BEGINSWITH "com.apple.AppSSO" OR subsystem BEGINSWITH "com.jamf.backgroundworkflows""#),
        ],
        "Enrollment, Automated Device Enrollment, & DEP": [
            // iOS's DEP/ADE activity is logged under com.apple.ManagedConfiguration
            // too, but the macOS category name ("DEPEnrollment") isn't
            // confirmed on iOS — dropping the category clause on iOS keeps
            // this from silently returning zero results over a guessed name.
            "Automated Device Enrollment (ADE) activity": .init(
                extraArgs: ["--info"], predicate: #"subsystem == "com.apple.ManagedClient" AND category == "DEPEnrollment""#,
                platform: .differs(ios: #"subsystem == "com.apple.ManagedConfiguration""#)
            ),
            "Profile installation and removal": .init(
                extraArgs: ["--info"], predicate: #"subsystem == "com.apple.ManagedClient" AND category CONTAINS "Profile""#,
                platform: .differs(ios: #"subsystem == "com.apple.ManagedConfiguration" AND category CONTAINS "Profile""#)
            ),
            // iOS's Setup Assistant runs as Setup.app ("Setup"), not the
            // "Setup Assistant" binary name macOS uses.
            "Setup Assistant / enrollment flow": .init(
                extraArgs: ["--info"], predicate: #"process == "Setup Assistant""#,
                platform: .differs(ios: #"process == "Setup""#)
            ),
        ],
        // Jamf Connect has no iOS/iPadOS agent — every topic here is
        // macOS-only, which also removes the whole category from an iOS
        // sysdiagnose's picker (see `sortedCategories(isMobile:)`).
        "Jamf Connect": [
            "Daemon Elevation": .init(extraArgs: ["--style", "compact"], predicate: #"(subsystem == "com.jamf.connect.daemon") && (category == "PrivilegeElevation")"#, platform: .macOSOnly),
            "Login Window": .init(extraArgs: ["--info"], predicate: #"subsystem CONTAINS "com.jamf.connect.login""#, platform: .macOSOnly),
            "Menu Bar": .init(extraArgs: ["--style", "compact"], predicate: #"subsystem == "com.jamf.connect""#, platform: .macOSOnly),
            "Menu Bar Elevation": .init(extraArgs: ["--style", "compact"], predicate: #"(subsystem == "com.jamf.connect") && (category == "PrivilegeElevation")"#, platform: .macOSOnly),
        ],
        "Jamf Pro": [
            "All Jamf Activity": .init(extraArgs: ["--info"], predicate: #"subsystem CONTAINS "com.jamf" OR subsystem CONTAINS "com.jamfsoftware""#),
            "MDM Client": .init(
                extraArgs: ["--style", "compact"], predicate: #"process CONTAINS "mdmclient""#,
                platform: .differs(ios: #"process CONTAINS "mdmd""#)
            ),
            "MDM command processing and device enrollment": .init(
                extraArgs: ["--info"], predicate: #"subsystem == "com.apple.ManagedClient""#,
                platform: .differs(ios: #"subsystem == "com.apple.ManagedConfiguration""#)
            ),
            "MDM daemon activity (enrollment, commands, profiles)": .init(
                extraArgs: ["--info"], predicate: #"subsystem == "com.apple.ManagedClient""#,
                platform: .differs(ios: #"subsystem == "com.apple.ManagedConfiguration""#)
            ),
        ],
        // Jamf Remote Assist has no iOS/iPadOS agent — macOS-only, same as
        // Jamf Connect above.
        "Jamf Remote Assist": [
            "Jamf Remote Assist": .init(extraArgs: ["--style", "compact"], predicate: #"subsystem BEGINSWITH "com.jamf.remoteassist""#, platform: .macOSOnly),
        ],
        "Jamf Self Service Plus": [
            "Self Service Plus": .init(extraArgs: ["--style", "compact"], predicate: #"subsystem == "com.jamf.selfserviceplus""#),
        ],
        "Networking": [
            "DNS resolution issues": .init(extraArgs: ["--info"], predicate: #"process == "mDNSResponder""#),
            "General network diagnostics": .init(extraArgs: ["--info"], predicate: #"subsystem == "com.apple.network""#),
            "Wi-Fi association and connectivity": .init(extraArgs: ["--info"], predicate: #"subsystem == "com.apple.wifi""#),
        ],
        // Gatekeeper and XProtect are macOS-only security mechanisms — iOS's
        // app-review/sandboxing model doesn't have an equivalent to filter
        // on. TCC exists on both.
        "Security & Gatekeeper": [
            "Gatekeeper / code signing checks": .init(extraArgs: ["--info"], predicate: #"subsystem == "com.apple.security.gatekeeper""#, platform: .macOSOnly),
            "TCC (Transparency, Consent, and Control) — privacy permissions": .init(extraArgs: ["--info"], predicate: #"subsystem == "com.apple.TCC""#),
            "XProtect malware scanning": .init(extraArgs: ["--info"], predicate: #"subsystem CONTAINS "com.apple.XProtect""#, platform: .macOSOnly),
        ],
        "Software Updates": [
            // Same unverified-category-name situation as ADE/DEP above —
            // DDM is cross-platform, but iOS's category name under
            // com.apple.ManagedConfiguration isn't confirmed, so the iOS
            // predicate drops the category clause rather than guess it.
            "DDM / Declarative Device Management update commands": .init(
                extraArgs: ["--info"], predicate: #"subsystem CONTAINS "com.apple.ManagedClient" AND category CONTAINS "SoftwareUpdate""#,
                platform: .differs(ios: #"subsystem CONTAINS "com.apple.ManagedConfiguration""#)
            ),
            "SoftwareUpdate": .init(extraArgs: ["--info"], predicate: #"subsystem == "com.apple.SoftwareUpdate""#),
            "SoftwareUpdate Daemon": .init(extraArgs: ["--info"], predicate: #"process == "softwareupdated""#),
        ],
        // Endpoint Security and System Extensions are both macOS-only
        // frameworks — this entire category disappears on iOS.
        "System and Kernel Extensions": [
            "Endpoint security framework": .init(extraArgs: ["--info"], predicate: #"subsystem == "com.apple.EndpointSecurity""#, platform: .macOSOnly),
            "System extension approvals/activations": .init(extraArgs: ["--info"], predicate: #"subsystem == "com.apple.SystemExtensions""#, platform: .macOSOnly),
        ],
    ]

    /// Categories + topics that actually apply to this platform, sorted for
    /// populating dropdowns — a category where every topic resolves to
    /// `nil` for this platform (e.g. "Jamf Connect" on iOS) is left out
    /// entirely rather than shown with nothing usable inside it.
    static func sortedCategories(isMobile: Bool) -> [String] {
        topics.filter { _, topicsForCategory in
            topicsForCategory.values.contains { $0.resolvedPredicate(isMobile: isMobile) != nil }
        }.keys.sorted()
    }

    static func sortedTopics(for category: String, isMobile: Bool) -> [String] {
        (topics[category]?.filter { $0.value.resolvedPredicate(isMobile: isMobile) != nil }.keys.sorted()) ?? []
    }

    /// Matches one atomic `field <op> "value"` comparison inside a topic's
    /// predicate string, e.g. `subsystem CONTAINS "com.apple.commerce"` or
    /// `category == "PrivilegeElevation"`.
    private static let termPattern = #"(process|subsystem|category)\s*(==|CONTAINS|BEGINSWITH)\s*"([^"]*)""#

    /// Pulls every atomic comparison out of a predicate, regardless of how
    /// they're combined (`AND`/`OR`/`&&`/`||`, parens, mixed) — the boolean
    /// structure itself is deliberately not preserved. The per-category
    /// filter picker lets admins recombine these facets themselves (every
    /// checked value within a field is OR'd together, every field that has
    /// at least one checked value is AND'd with the others — see
    /// `combinedPredicate(for:)`) rather than being stuck with whatever
    /// fixed expression a topic happened to be written with.
    static func terms(in predicate: String) -> [LogFilterTerm] {
        regexAllMatchGroups(termPattern, in: predicate).compactMap { groups in
            guard groups.count == 3,
                  let field = LogFilterTerm.Field(rawValue: groups[0]),
                  let op = LogFilterTerm.Op(rawValue: groups[1]),
                  !groups[2].isEmpty else { return nil }
            return LogFilterTerm(field: field, op: op, value: groups[2])
        }
    }

    /// Every distinct filter term available for a category's topics,
    /// deduped across topics that happen to share the exact same term
    /// (e.g. two "MDM..." topics that both key off
    /// `subsystem == "com.apple.ManagedClient"`), with the name of every
    /// topic it came from attached — that's what shows up in the UI in
    /// parens next to the value.
    static func filterOptions(for category: String, isMobile: Bool) -> [CatalogFilterOption] {
        guard let topicsForCategory = topics[category] else { return [] }
        var byTerm: [LogFilterTerm: Set<String>] = [:]
        for (topicName, def) in topicsForCategory {
            guard let predicate = def.resolvedPredicate(isMobile: isMobile) else { continue }
            for term in terms(in: predicate) {
                byTerm[term, default: []].insert(topicName)
            }
        }
        return byTerm.map { CatalogFilterOption(term: $0.key, topics: $0.value.sorted()) }
            .sorted { a, b in
                if a.term.field != b.term.field { return a.term.field.sortRank < b.term.field.sortRank }
                return a.term.value.localizedCaseInsensitiveCompare(b.term.value) == .orderedAscending
            }
    }

    /// Builds one combined `log show` predicate from an arbitrary set of
    /// checked filter terms: values checked within the same field (process,
    /// subsystem, or keyword/category) are OR'd together, and every field
    /// that has at least one checked value is *also* OR'd with the others —
    /// checking anything in this picker only ever widens the result, never
    /// narrows it.
    ///
    /// This used to AND different fields together instead (checking a
    /// subsystem value AND a process value required log lines to match
    /// both at once), on the theory that it'd let a topic's own multi-field
    /// predicate — e.g. "Daemon Elevation"'s `subsystem == X AND category ==
    /// Y` — be reconstructed by checking both of its boxes. In practice
    /// that AND applied to *every* checked field regardless of whether the
    /// terms actually came from the same topic, so checking a category's
    /// own topics plus an unrelated hand-typed custom process (e.g. "Jamf
    /// Connect" plus a custom `process == "loginwindow"`) produced
    /// `(jamf connect subsystems) AND (loginwindow)` — a real sysdiagnose
    /// essentially never has a `loginwindow` log line tagged with a Jamf
    /// Connect subsystem, so that combination silently returned nothing,
    /// even though each half worked fine on its own. Every category is
    /// affected the same way, not just this one, since they all share this
    /// one function. OR-ing across fields instead means the checkbox
    /// picker always behaves like "show me anything matching any of
    /// these" — which loses the ability to reconstruct one topic's exact
    /// narrow AND via checkboxes alone, but that's a much safer trade than
    /// combinations silently going empty; a topic that genuinely needs
    /// that narrower query is still reachable via "Custom".
    static func combinedPredicate(for terms: Set<LogFilterTerm>) -> String? {
        guard !terms.isEmpty else { return nil }
        let grouped = Dictionary(grouping: terms, by: { $0.field })
        let clauses: [String] = LogFilterTerm.Field.allCases.compactMap { field -> String? in
            guard let group = grouped[field], !group.isEmpty else { return nil }
            let parts = group.sorted { $0.value.localizedCaseInsensitiveCompare($1.value) == .orderedAscending }
                .map { #"\#($0.field.rawValue) \#($0.op.rawValue) "\#($0.value)""# }
            return parts.count == 1 ? parts[0] : "(" + parts.joined(separator: " OR ") + ")"
        }
        return clauses.count == 1 ? clauses[0] : clauses.joined(separator: " OR ")
    }

    /// Builds a `messageType == x OR messageType == y ...` clause from
    /// whichever levels are checked, or `nil` if none are — an empty
    /// selection means "don't filter by level at all," not "match nothing."
    /// Exact multi-select, not a threshold: picking Error and Fault matches
    /// only those two, nothing in between or below.
    static func levelPredicateClause(for levels: Set<LogLevel>) -> String? {
        guard !levels.isEmpty else { return nil }
        let parts = levels.sorted { $0.sortRank < $1.sortRank }.map { "messageType == \($0.rawValue)" }
        return parts.count == 1 ? parts[0] : "(" + parts.joined(separator: " OR ") + ")"
    }
}

/// One atomic, checkable `field <op> "value"` filter term surfaced in the
/// Troubleshooting tab's per-category picker — either derived from a
/// catalog topic's predicate (via `TroubleshootCatalog.terms(in:)`) or
/// typed in by hand as a custom addition. Identity/hashing is by content
/// only (field + op + value), so the same term always dedupes and toggles
/// consistently regardless of which topic(s) it came from.
struct LogFilterTerm: Hashable {
    enum Field: String, CaseIterable {
        case process, subsystem
        case keyword = "category"

        var displayName: String {
            switch self {
            case .process: return "Process"
            case .subsystem: return "Subsystem"
            case .keyword: return "Keyword"
            }
        }
        var sortRank: Int {
            switch self {
            case .process: return 0
            case .subsystem: return 1
            case .keyword: return 2
            }
        }
    }

    enum Op: String {
        case equals = "=="
        case contains = "CONTAINS"
        case beginsWith = "BEGINSWITH"
    }

    var field: Field
    var op: Op
    var value: String
}

/// A `LogFilterTerm` plus the names of every catalog topic it was pulled
/// from — `topics` is purely for display (the "(Topic Name)" annotation);
/// it doesn't participate in equality/selection.
struct CatalogFilterOption: Identifiable {
    var term: LogFilterTerm
    var topics: [String]
    var id: LogFilterTerm { term }

    /// "(Topic A, Topic B)", or "(Custom)" for a hand-typed addition with
    /// no catalog topic behind it.
    var topicsLabel: String {
        topics.isEmpty ? "(Custom)" : "(\(topics.joined(separator: ", ")))"
    }
}

/// The five severity levels `log show` actually recognizes (its own
/// `messageType` predicate key) — no separate "warning" level exists in the
/// unified log despite the term showing up informally elsewhere. Filtering
/// on this is a plain, exact multi-select: picking "Fault" shows only Fault
/// entries, not Fault-and-anything-more-severe (there isn't a "more severe"
/// above Fault anyway) or Fault-and-everything-less-severe.
enum LogLevel: String, CaseIterable, Identifiable {
    case debug, info, `default`, error, fault
    var id: String { rawValue }
    var displayName: String { rawValue.capitalized }

    /// Debug < Info < Default < Error < Fault — used only to keep a
    /// multi-selection's checkboxes and predicate clause in a stable,
    /// predictable order, not to imply "and above" semantics anywhere.
    var sortRank: Int {
        switch self {
        case .debug: return 0
        case .info: return 1
        case .default: return 2
        case .error: return 3
        case .fault: return 4
        }
    }
}

struct TroubleshootQueryResult {
    var lines: [String] = []
    var command: String = ""
    var error: String?
}

enum LogArchiveService {

    private static let statusItemsPredicate = #"subsystem BEGINSWITH "com.apple.remotemanagement" OR process == "remotemanagementd""#

    /// `log show --style ndjson`'s numeric `messageType` field, straight
    /// from Apple's own `os_log_type_t` (`libkern/os/log.h`):
    /// `OS_LOG_TYPE_DEFAULT = 0x00`, `INFO = 0x01`, `DEBUG = 0x02`,
    /// `ERROR = 0x10` (16), `FAULT = 0x11` (17). There is no 18/"warning" —
    /// that value never appears in real `log show` output; this table
    /// previously invented it and, worse, had 16/17 swapped (fault and
    /// error labeled as each other), which is the same mixup `LogLevel`'s
    /// own predicate-based filtering above correctly avoids — see its
    /// doc comment.
    private static let levelMap: [Int: String] = [0: "default", 1: "info", 2: "debug", 16: "error", 17: "fault"]

    /// Port of `read_logarchive` — runs `log show --archive ... --style ndjson`
    /// and returns parsed entries.
    static func readLogarchive(archivePath: String, predicate: String, lastDays: Int = 30, maxLines: Int = 500) -> [LogEntry] {
        let args = ["show", "--archive", archivePath, "--predicate", predicate, "--style", "ndjson", "--info", "--last", "\(lastDays)d"]
        guard let output = runLog(args, timeout: 180) else { return [] }

        // `log show` prints matches oldest-first. This used to stop as soon
        // as it collected `maxLines` entries, which — on a chatty predicate
        // with more than `maxLines` matches in the window — silently kept
        // only the *oldest* `maxLines` entries and dropped everything more
        // recent, including whatever's happened most recently. That's the
        // opposite of what every caller actually wants ("the last N log
        // lines"), and showed up as Log Stream appearing to cut off hours
        // before the archive's actual most recent matching entry. Collecting
        // everything first and taking the tail end fixes that.
        var entries: [LogEntry] = []
        for line in output.split(separator: "\n") {
            let trimmed = line.trimmingCharacters(in: .whitespaces)
            guard !trimmed.isEmpty, let data = trimmed.data(using: .utf8) else { continue }
            guard let obj = try? JSONSerialization.jsonObject(with: data) as? [String: Any] else { continue }

            var ts = (obj["timestamp"] as? String) ?? ""
            if ts.count > 22 { ts = String(ts.prefix(22)) }

            let processPath = (obj["processImagePath"] as? String) ?? ""
            let process = processPath.split(separator: "/").last.map(String.init) ?? ""

            let msg = (obj["eventMessage"] as? String) ?? ""
            if msg.isEmpty { continue }

            let messageType = (obj["messageType"] as? Int) ?? 0
            entries.append(LogEntry(
                timestamp: ts, process: process,
                subsystem: (obj["subsystem"] as? String) ?? "",
                message: msg,
                level: levelMap[messageType] ?? "default"
            ))
        }
        guard entries.count > maxLines else { return entries }
        return Array(entries.suffix(maxLines))
    }

    /// Port of `read_status_item_logs` — for each keyPath, finds the most recent
    /// log message mentioning it.
    static func readStatusItemLogs(archivePath: String, keyPaths: [String]) -> [String: (timestamp: String, message: String)] {
        guard !keyPaths.isEmpty else { return [:] }
        let entries = readLogarchive(archivePath: archivePath, predicate: statusItemsPredicate, lastDays: 90, maxLines: 3000)
        var result: [String: (timestamp: String, message: String)] = [:]
        for entry in entries.reversed() {
            for kp in keyPaths where result[kp] == nil && entry.message.contains(kp) {
                result[kp] = (entry.timestamp, entry.message)
            }
        }
        return result
    }

    /// Port of `parse_swupdate_status_values` — pulls the last "Reporting status {...}"
    /// block emitted by the software-update status reporter and parses it as
    /// an ASCII plist.
    ///
    /// The original Python tool (and this port, originally) restricted this
    /// to `process == "SoftwareUpdateSubscriber"`, but on at least some OS
    /// versions the exact same "Reporting status {...}" message is emitted
    /// by a different process (`-[SoftwareUpdateStatus ...]` showed up under
    /// `softwareupdated` in one real sysdiagnose) — when that happens, this
    /// query silently finds nothing (or an older, unrelated report from
    /// whenever "SoftwareUpdateSubscriber" itself last logged one) while
    /// `readLogStream`'s query for the same key paths, a few functions
    /// below, already matches several processes/subsystems for exactly this
    /// reason. Matching that same broader set here keeps the two in sync so
    /// this always finds the same, actually-latest report Log Stream shows.
    static func parseSoftwareUpdateStatusValues(archivePath: String) -> [String: String] {
        let args = ["show", "--archive", archivePath,
                    "--predicate", #"(process == "SoftwareUpdateSubscriber" OR process == "softwareupdated" OR process == "SoftwareUpdateNotificationManager" OR subsystem BEGINSWITH "com.apple.remotemanagement" OR process == "remotemanagementd") AND eventMessage CONTAINS "Reporting status {""#,
                    "--style", "syslog", "--info", "--last", "30d"]
        guard let output = runLog(args, timeout: 120), !output.isEmpty else { return [:] }

        guard let idx = output.range(of: "Reporting status {", options: .backwards) else { return [:] }
        // Finds the block's actual closing brace by counting depth instead
        // of assuming the message always ends with a specific trailer like
        // `"} (null)"` — that assumption doesn't hold on every OS version's
        // log format, and when it silently failed to match here, this
        // ended up parsing a *different*, wrong "Reporting status {...}"
        // occurrence (an older, unrelated one) instead of returning
        // nothing, which is how a stale value (e.g. an old
        // "count = 0" for softwareupdate.failure-reason, or a "reason"
        // value from an entirely different report) could show up here
        // even though the real latest report had different data.
        guard let block = extractBalancedDict(startingAt: idx.lowerBound, in: output) else { return [:] }

        let parsed = AsciiPlistParser(block).parse()
        guard let dict = parsed.asDict else { return [:] }

        var out: [String: String] = [:]
        for (key, val) in dict where key.hasPrefix("softwareupdate.") {
            out[key] = formatSoftwareUpdateValue(val)
        }
        return out
    }

    /// Finds the first `{` at or after `searchStart` and returns the
    /// substring through its actual matching `}`, tracking brace depth
    /// rather than assuming any particular trailer text follows the close.
    /// Skips over the contents of quoted strings (honoring `\`-escapes)
    /// while counting, so a literal `{`/`}` inside a reason string can't
    /// throw off the depth count.
    private static func extractBalancedDict(startingAt searchStart: String.Index, in text: String) -> String? {
        guard let braceStart = text.range(of: "{", range: searchStart..<text.endIndex) else { return nil }
        var depth = 0
        var inQuotes = false
        var idx = braceStart.lowerBound
        while idx < text.endIndex {
            let c = text[idx]
            if inQuotes {
                if c == "\\" {
                    idx = text.index(after: idx)
                    if idx >= text.endIndex { break }
                } else if c == "\"" {
                    inQuotes = false
                }
            } else if c == "\"" {
                inQuotes = true
            } else if c == "{" {
                depth += 1
            } else if c == "}" {
                depth -= 1
                if depth == 0 {
                    let end = text.index(after: idx)
                    return String(text[braceStart.lowerBound..<end])
                }
            }
            idx = text.index(after: idx)
        }
        return nil
    }

    private static func formatSoftwareUpdateValue(_ val: PlistValue) -> String {
        switch val {
        case .null: return "—"
        case .bool(let b): return b ? "true" : "false"
        case .int(let i): return i != 0 ? String(i) : "—"
        case .string(let s): return s.trimmingCharacters(in: .whitespaces).isEmpty ? "—" : s.trimmingCharacters(in: .whitespaces)
        case .array(let arr):
            let parts = arr.compactMap { v -> String? in
                let s = v.stringified.trimmingCharacters(in: .whitespaces)
                return s.isEmpty ? nil : s
            }
            return parts.isEmpty ? "—" : parts.joined(separator: ", ")
        case .dict(let d):
            if d["os-version"] != nil || d["build-version"] != nil {
                var parts: [String] = []
                let ov = (d["os-version"]?.asString ?? "").trimmingCharacters(in: .whitespaces)
                let bv = (d["build-version"]?.asString ?? "").trimmingCharacters(in: .whitespaces)
                if !ov.isEmpty { parts.append(ov) }
                if !bv.isEmpty { parts.append("(\(bv))") }
                return parts.isEmpty ? "—" : parts.joined(separator: " ")
            }
            // A "reason" dict (e.g. softwareupdate.failure-reason) — the
            // reason text is usually accompanied by `count` (how many times
            // it's been reported) and `timestamp` (when it was last
            // reported), which used to get silently dropped here in favor
            // of the reason text alone. All three are shown together now.
            if let r = d["reason"] {
                let reasonStr: String
                if let arr = r.asArray {
                    let items = arr.compactMap { v -> String? in
                        let s = v.stringified.trimmingCharacters(in: .whitespaces)
                        return s.isEmpty ? nil : s
                    }
                    reasonStr = items.joined(separator: ", ")
                } else {
                    reasonStr = r.stringified.trimmingCharacters(in: .whitespaces)
                }
                var suffixParts: [String] = []
                if let count = d["count"]?.asInt, count != 0 {
                    suffixParts.append(count == 1 ? "1×" : "\(count)×")
                }
                if let ts = (d["timestamp"]?.asString)?.trimmingCharacters(in: .whitespaces), !ts.isEmpty {
                    suffixParts.append("last \(ts)")
                }
                if reasonStr.isEmpty {
                    return suffixParts.isEmpty ? "—" : suffixParts.joined(separator: ", ")
                }
                return suffixParts.isEmpty ? reasonStr : "\(reasonStr) (\(suffixParts.joined(separator: ", ")))"
            }
            if d.keys.count == 1, let count = d["count"] {
                return "count = \(count.stringified)"
            }
            let parts = d.compactMap { (k, v) -> String? in
                if v.isEmpty { return nil }
                return "\(k): \(v.stringified)"
            }
            return parts.isEmpty ? "—" : parts.joined(separator: "; ")
        default:
            let s = val.stringified.trimmingCharacters(in: .whitespaces)
            return s.isEmpty ? "—" : s
        }
    }

    /// Port of the `/troubleshoot-log` route — runs the "Custom" category's
    /// single free-text process/subsystem query. Predefined categories no
    /// longer go through here — see `runTroubleshootFilterQuery` below.
    ///
    /// `lastArg` is whatever should follow `--last` on the command line
    /// (e.g. `"30m"`, `"7d"`), or `nil` to query all time — the Troubleshooting
    /// tab builds this from its integer amount + minutes/days unit fields.
    static func runTroubleshootQuery(archive: String, category: String, topic: String, lastArg: String?, customType: String, levels: Set<LogLevel> = []) -> TroubleshootQueryResult {
        guard category == "Custom" else {
            return TroubleshootQueryResult(error: "Unknown category: \(category)")
        }
        guard !topic.isEmpty else { return TroubleshootQueryResult(error: "No value provided.") }
        let value = topic.replacingOccurrences(of: "\"", with: "").replacingOccurrences(of: "'", with: "")
        let extraArgs: [String]
        let predicate: String
        if customType.lowercased() == "process" {
            extraArgs = ["--style", "compact"]
            predicate = #"process CONTAINS "\#(value)""#
        } else {
            extraArgs = ["--info"]
            predicate = #"subsystem CONTAINS "\#(value)""#
        }
        return runLogShow(archive: archive, predicate: predicate, extraArgs: extraArgs, lastArg: lastArg, levels: levels)
    }

    /// Runs a query built from a checked set of `LogFilterTerm`s (see
    /// `TroubleshootCatalog.combinedPredicate(for:)`) — this is what backs
    /// a predefined category's checkbox filter picker now that a "topic"
    /// no longer maps to one fixed predicate.
    ///
    /// Terms pulled from different catalog topics can carry different
    /// `extraArgs` (`--info`, `--debug --info`, `--style compact`, ...);
    /// once they're decoupled from any single topic there's no one
    /// obviously-correct combination, so this always uses `--info`, the
    /// most common choice across the catalog and a sensible default for
    /// open-ended exploratory filtering.
    static func runTroubleshootFilterQuery(archive: String, terms: Set<LogFilterTerm>, lastArg: String?, levels: Set<LogLevel> = []) -> TroubleshootQueryResult {
        guard let predicate = TroubleshootCatalog.combinedPredicate(for: terms) else {
            return TroubleshootQueryResult(error: "No filters selected.")
        }
        return runLogShow(archive: archive, predicate: predicate, extraArgs: ["--info"], lastArg: lastArg, levels: levels)
    }

    /// `levels` is an exact multi-select over `log show`'s five `messageType`
    /// values (see `LogLevel`) — an empty set means "don't filter by level
    /// at all." Debug and Info entries aren't retrievable from the archive
    /// without `--debug`/`--info` regardless of what the predicate says, so
    /// whenever any level is checked this forces both flags on rather than
    /// relying on whatever `extraArgs` a topic happened to carry — the
    /// `messageType` clause is then the only thing actually restricting
    /// which levels show up.
    private static func runLogShow(archive: String, predicate: String, extraArgs: [String], lastArg: String?, levels: Set<LogLevel> = []) -> TroubleshootQueryResult {
        guard FileManager.default.fileExists(atPath: archive) else {
            return TroubleshootQueryResult(error: "Logarchive not found or unavailable.")
        }

        let lastArg = (lastArg?.isEmpty ?? true) ? nil : lastArg

        var resolvedArgs = extraArgs
        var resolvedPredicate = predicate
        if let levelClause = TroubleshootCatalog.levelPredicateClause(for: levels) {
            resolvedPredicate = "(\(predicate)) AND \(levelClause)"
            for flag in ["--debug", "--info"] where !resolvedArgs.contains(flag) {
                resolvedArgs.append(flag)
            }
        }

        var args = ["show", "--archive", archive] + resolvedArgs + ["--predicate", resolvedPredicate]
        if let lastArg { args += ["--last", lastArg] }

        let displayExtra = resolvedArgs.joined(separator: " ")
        let lastDisplay = lastArg != nil ? "--last \(lastArg!)" : "(all time)"
        let commandDisplay = "log show --archive <logarchive> \(displayExtra) --predicate '\(resolvedPredicate)' \(lastDisplay)"

        guard let output = runLog(args, timeout: 120) else {
            return TroubleshootQueryResult(error: "Query timed out or failed.")
        }
        var lines = output.split(separator: "\n", omittingEmptySubsequences: false).map(String.init)
        if lines.last == "" { lines.removeLast() }
        // Full result set is kept here — the Troubleshooting tab paginates the
        // display in chunks (see `visibleLineCount`/"Load More") but export
        // always writes this complete, untruncated array.
        return TroubleshootQueryResult(lines: lines, command: commandDisplay, error: nil)
    }

    /// Port of `/log-stream` — filtered log view for a specific status key path.
    static func readLogStream(archive: String, keyPath: String) -> [LogEntry] {
        let predicate: String
        if keyPath.hasPrefix("softwareupdate.") {
            predicate = #"(process == "SoftwareUpdateSubscriber" OR process == "softwareupdated" OR process == "SoftwareUpdateNotificationManager" OR subsystem BEGINSWITH "com.apple.remotemanagement" OR process == "remotemanagementd") AND eventMessage CONTAINS "\#(keyPath)""#
        } else {
            predicate = #"(subsystem BEGINSWITH "com.apple.remotemanagement" OR process == "remotemanagementd") AND eventMessage CONTAINS "\#(keyPath)""#
        }
        return readLogarchive(archivePath: archive, predicate: predicate, lastDays: 1, maxLines: 500)
    }

    /// Simple reference-type box so the background read threads below can hand
    /// their result back across the semaphore-guarded happens-before edge.
    private final class DataBox {
        var data = Data()
    }

    /// Runs `/usr/bin/log` with the given arguments and returns stdout as a string.
    ///
    /// IMPORTANT: macOS pipes have a small kernel buffer (~64KB). `log show`
    /// against a real logarchive can produce megabytes of output, so the child
    /// process will block on write() once the buffer fills unless something is
    /// continuously draining the read end. Waiting for the process to exit
    /// *before* reading the pipe (as a naive implementation might) deadlocks —
    /// the parent waits for exit, the child waits for someone to read, neither
    /// happens until the timeout fires. To avoid that, both pipes are drained
    /// concurrently on background queues while the process runs.
    private static func runLog(_ args: [String], timeout: TimeInterval) -> String? {
        // The single highest-value place to log: every one of this app's
        // `log show`/`log stream` invocations against a sysdiagnose's
        // logarchive funnels through here, and a timeout on a large one
        // previously just returned `nil` with no record of which query,
        // how long it ran, or that a timeout (rather than a genuinely
        // empty result) was the cause.
        let start = Date()
        let commandText = "log " + args.joined(separator: " ")
        DiagnosticsLog.info("Running: \(commandText) (timeout \(Int(timeout))s)")

        let proc = Process()
        proc.executableURL = URL(fileURLWithPath: "/usr/bin/log")
        proc.arguments = args
        let outPipe = Pipe()
        let errPipe = Pipe()
        proc.standardOutput = outPipe
        proc.standardError = errPipe

        do {
            try proc.run()
        } catch {
            DiagnosticsLog.error("Failed to launch: \(commandText) — \(error.localizedDescription)")
            return nil
        }

        let stdoutBox = DataBox()
        let stderrBox = DataBox()
        let doneSemaphore = DispatchSemaphore(value: 0)
        let queue = DispatchQueue(label: "com.devicediag.logread", attributes: .concurrent)

        queue.async {
            stdoutBox.data = outPipe.fileHandleForReading.readDataToEndOfFile()
            doneSemaphore.signal()
        }
        queue.async {
            stderrBox.data = errPipe.fileHandleForReading.readDataToEndOfFile()
        }

        let waitResult = doneSemaphore.wait(timeout: .now() + timeout)
        if waitResult == .timedOut {
            proc.terminate()
            let elapsed = Date().timeIntervalSince(start)
            DiagnosticsLog.error("TIMED OUT after \(String(format: "%.1f", elapsed))s (limit \(Int(timeout))s): \(commandText)")
            return nil
        }

        proc.waitUntilExit()
        let data = stdoutBox.data
        let elapsed = Date().timeIntervalSince(start)
        DiagnosticsLog.info("Finished in \(String(format: "%.1f", elapsed))s, \(data.count) bytes, exit \(proc.terminationStatus): \(commandText)")
        return String(data: data, encoding: .utf8) ?? String(decoding: data, as: UTF8.self)
    }
}
