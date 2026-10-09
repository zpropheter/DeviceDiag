import Foundation

/// Finds the line in an arbitrary sysdiagnose text file whose embedded
/// timestamp is closest to a target time — the core of the Log Stream
/// window's "open another file at this same moment" feature. Sysdiagnose
/// text files don't share one timestamp format (install.log's ISO-ish
/// `2026-08-24 14:32:10-0700` vs. system.log's syslog-style
/// `Aug 24 14:32:10`), so each line is tried against a couple of common
/// patterns rather than assuming one.
enum TimestampLineMatcher {

    // Precompiled once and reused across every line, rather than going
    // through the generic `regexFirstMatch` helper (which recompiles its
    // pattern on every call) — sysdiagnose text files like system.log can
    // run tens of thousands of lines, and this runs on all of them per jump.
    private static let isoRegex = try! NSRegularExpression(
        pattern: #"(\d{4}-\d{2}-\d{2}[ T]\d{2}:\d{2}:\d{2})"#
    )
    private static let syslogRegex = try! NSRegularExpression(
        pattern: #"\b((?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec) +\d{1,2} \d{2}:\d{2}:\d{2})\b"#
    )

    private static let isoFormatter: DateFormatter = {
        let f = DateFormatter()
        f.dateFormat = "yyyy-MM-dd HH:mm:ss"
        f.locale = Locale(identifier: "en_US_POSIX")
        f.timeZone = .current
        return f
    }()

    private static let syslogFormatter: DateFormatter = {
        let f = DateFormatter()
        f.dateFormat = "MMM d HH:mm:ss yyyy"
        f.locale = Locale(identifier: "en_US_POSIX")
        f.timeZone = .current
        return f
    }()

    /// Parses the `log show --style ndjson` timestamp format `LogEntry`
    /// carries (`"yyyy-MM-dd HH:mm:ss.ssssss±hhmm"`, already truncated to
    /// ~22 characters by `LogArchiveService`) — used to turn a clicked
    /// Log Stream row into an anchor `Date` for the companion file pane.
    static func parseLogEntryTimestamp(_ raw: String) -> Date? {
        isoFormatter.date(from: String(raw.prefix(19)))
    }

    /// Extracts a leading ISO-ish timestamp from a raw `log show` output
    /// line — used by the Troubleshooting tab to pin a "moment of interest"
    /// when a result line is clicked. `log show`'s own output always
    /// starts with this format regardless of `--style` (default, compact,
    /// info all share the same leading timestamp), so unlike `nearestLine`
    /// there's no syslog-format fallback to worry about here, and no `near`
    /// reference date is needed since the ISO format already carries its
    /// own year.
    static func leadingISOTimestamp(in line: String) -> Date? {
        guard let iso = firstMatch(isoRegex, in: line) else { return nil }
        return isoFormatter.date(from: iso)
    }

    /// Returns the index into `lines` whose parsed timestamp is nearest
    /// `target`, or nil if no line in the file had a timestamp this could
    /// parse at all (e.g. a plist, or a format not covered here).
    static func nearestLine(to target: Date, in lines: [String]) -> Int? {
        var bestIndex: Int?
        var bestDelta = Double.greatestFiniteMagnitude

        for (idx, line) in lines.enumerated() {
            guard let date = timestamp(in: line, near: target) else { continue }
            let delta = abs(date.timeIntervalSince(target))
            if delta < bestDelta {
                bestDelta = delta
                bestIndex = idx
            }
        }
        return bestIndex
    }

    private static func firstMatch(_ regex: NSRegularExpression, in line: String) -> String? {
        let range = NSRange(line.startIndex..., in: line)
        guard let match = regex.firstMatch(in: line, range: range), match.numberOfRanges > 1,
              let r = Range(match.range(at: 1), in: line) else { return nil }
        return String(line[r])
    }

    /// Tries the ISO-ish pattern first — it carries its own year, so it's
    /// unambiguous. Falls back to the syslog "MMM d HH:mm:ss" pattern, which
    /// has no year at all, so it borrows the target's year — and rolls back
    /// a year if that lands more than ~180 days in the future, which only
    /// matters right at a Dec/Jan boundary (a log line timestamped "Dec 31"
    /// being matched against a target in early January).
    private static func timestamp(in line: String, near target: Date) -> Date? {
        if let iso = firstMatch(isoRegex, in: line), let date = isoFormatter.date(from: iso) {
            return date
        }
        if let syslog = firstMatch(syslogRegex, in: line) {
            let year = Calendar.current.component(.year, from: target)
            guard let date = syslogFormatter.date(from: "\(syslog) \(year)") else { return nil }
            if date.timeIntervalSince(target) > 180 * 86400,
               let rolledBack = syslogFormatter.date(from: "\(syslog) \(year - 1)") {
                return rolledBack
            }
            return date
        }
        return nil
    }
}
