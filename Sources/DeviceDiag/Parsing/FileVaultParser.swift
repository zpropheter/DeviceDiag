import Foundation

/// Decodes FileVault/APFS key-slot state out of a sysdiagnose's `psm`
/// (Password Slot Manager) output — `/usr/bin/psm status` and
/// `/usr/bin/psm list`, run automatically by every sysdiagnose capture, plus
/// whatever `psm` wrote to stderr along the way (its exit code is 1, but the
/// content is legitimate — that's just how `psm` reports this data).
///
/// Nothing else in a sysdiagnose surfaces this: `disks.txt` only reports
/// whether the volume is encrypted, not which credentials — local users, an
/// MDM bootstrap token, a personal/institutional recovery key — can actually
/// unlock it, or whether any of them are close to a lockout.
///
/// All three source files carry raw ANSI color escape codes (`psm`'s own
/// terminal formatting) that have to be stripped before any of this parses
/// cleanly.
enum FileVaultParser {

    /// A slot's combined (console + other) failed-unlock-attempt count has
    /// to cross this fraction of its own max-unlock-attempts before it's
    /// flagged — a couple of stray failed attempts long ago isn't a live
    /// risk, since the counter resets on a successful unlock.
    private static let nearLockoutThreshold = 0.5

    private static let ansiPattern = "\u{1B}\\[[0-9;]*m"

    static func parse(root: URL, isMDMManaged: Bool) -> FileVaultResult {
        var result = FileVaultResult()
        result.isMDMManaged = isMDMManaged

        guard let statusURL = FileLocating.findFile(root, "psm_status.txt") else {
            return result
        }
        let statusText = stripANSI(FileLocating.safeRead(statusURL))
        guard !statusText.isEmpty else { return result }
        result.found = true

        // Parens required around "Enabled" specifically — a disabled Mac's
        // equivalent line (e.g. "(Not Enabled)"/"(Disabled)") still contains
        // "Enabled" as a bare substring in at least one observed wording, so
        // matching that loosely would misreport it as on.
        result.enabled = regexFirstMatch(#"FileVault:\s*\(Enabled\)"#, in: statusText, group: 0) != nil

        // Each slot's own block, keyed by its own `user:` UUID — needed so a
        // slot's `info:` descriptor (OD record vs. recovery key vs.
        // bootstrap token) is matched against that same slot, not just
        // searched for anywhere in the file.
        let slotBlocks = statusText.components(separatedBy: "---*---*---*---")
        var uuidLabels: [String: String] = [:]

        for block in slotBlocks {
            guard let uuid = regexFirstMatch(#"user:\s*([0-9A-Fa-f-]{36})"#, in: block) else { continue }
            if let groups = regexMatchGroups(#"OD record:\s*(\S+)\s*\((\d+)\)"#, in: block), !groups.isEmpty {
                let username = groups[0]
                result.enrolledUsers.append(username)
                uuidLabels[uuid] = username
            } else if block.range(of: "mdm boostrap token") != nil || block.range(of: "mdm bootstrap token") != nil {
                result.hasBootstrapToken = true
                uuidLabels[uuid] = "MDM bootstrap token"
            } else if block.range(of: "personal recovery key") != nil {
                result.hasPersonalRecoveryKey = true
                uuidLabels[uuid] = "Personal recovery key"
            } else if block.range(of: "institutional recovery key") != nil {
                result.hasInstitutionalRecoveryKey = true
                uuidLabels[uuid] = "Institutional recovery key"
            }
        }

        // psm_list.txt's admin line(s) — cross-referenced against the
        // enrolled-username set above to catch an admin account that can't
        // actually unlock the disk at boot.
        if let listURL = FileLocating.findFile(root, "psm_list.txt") {
            let listText = stripANSI(FileLocating.safeRead(listURL))
            let enrolled = Set(result.enrolledUsers)
            for groups in regexAllMatchGroups(#"username:\s*(\S+)\s*\(\d+\)\s*is admin"#, in: listText) {
                guard let admin = groups.first, !enrolled.contains(admin) else { continue }
                result.adminUsersNotEnrolled.append(admin)
            }
        }

        // psm_stderr.txt's per-slot failed-unlock-attempt counters — each
        // entry is delimited by psm's own `-=-=-=-=-=-=-` banner, which
        // splitting on leaves a trailing index number at the start of every
        // segment but otherwise doesn't interfere with the regexes below.
        if let stderrURL = FileLocating.findFile(root, "psm_stderr.txt") {
            let stderrText = stripANSI(FileLocating.safeRead(stderrURL))
            let entries = stderrText.components(separatedBy: "-=-=-=-=-=-=-").dropFirst()
            for entry in entries {
                guard let uuid = regexFirstMatch(#"uuid:\s*([0-9A-Fa-f-]{36})"#, in: entry),
                      let groups = regexMatchGroups(
                          #"failed-unlock-attempts\[console,other\]:\s*(\d+),\s*(\d+).*?max-unlock-attempts:\s*(\d+)"#,
                          in: entry, options: [.dotMatchesLineSeparators]
                      ), groups.count == 3,
                      let console = Int(groups[0]), let other = Int(groups[1]), let maxAttempts = Int(groups[2]),
                      maxAttempts > 0 else { continue }

                let combined = console + other
                guard Double(combined) > nearLockoutThreshold * Double(maxAttempts) else { continue }
                let label = uuidLabels[uuid] ?? "Unknown slot"
                result.nearLockoutSlots.append(FileVaultUnlockAttempt(label: label, failedAttempts: combined, maxAttempts: maxAttempts))
            }
        }

        return result
    }

    private static func stripANSI(_ text: String) -> String {
        guard let re = try? NSRegularExpression(pattern: ansiPattern) else { return text }
        let range = NSRange(text.startIndex..., in: text)
        return re.stringByReplacingMatches(in: text, range: range, withTemplate: "")
    }
}
