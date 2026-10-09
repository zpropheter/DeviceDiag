import Foundation

/// Port of `sysdiag_netcheck.py` — the network health report: interface
/// errors/drops, TCP retransmits, routing, DNS, proxy config, Wi-Fi signal
/// quality, and the active connectivity probes (ping/DNS/curl) that macOS
/// runs as part of every sysdiagnose capture. Feeds the Networking tab.
///
/// Unlike most other parsers here, this one degrades section-by-section
/// rather than all-or-nothing: any individual source file that's missing
/// just yields an empty/nil result for that one section (mirroring the
/// Python script's `read_text` returning `""` for a file that isn't there),
/// so a sysdiagnose missing, say, `proxy-configuration.txt` still gets a
/// full report with every other section intact.
enum NetworkReportParser {

    /// Every file this report (or the Files tab's Networking group) cares
    /// about, as a root-relative path suffix — several of these filenames
    /// aren't unique on their own (`ifconfig.txt` exists under both
    /// `network-info/` and `WiFi/`), so suffix search via
    /// `FileLocating.findPathSuffix` is what disambiguates them, exactly
    /// like the Python script's `find_file(root, suffix)`.
    static let wantedSuffixes: [String] = [
        "network-info/ifconfig.txt",
        "network-info/netstat.txt",
        "network-info/route-info.txt",
        "network-info/dns-configuration.txt",
        "network-info/proxy-configuration.txt",
        "network-info/reachability-info.txt",
        "network-info/interface-advisories.txt",
        "network-info/interface-rank-assertions.txt",
        "network-info/network-information.txt",
        "network-info/get-network-info.txt",
        "network-info/hostname.txt",
        "WiFi/wifi_status.txt",
        "WiFi/network_status.txt",
        "WiFi/awdl_status.txt",
        "WiFi/diagnostics-connectivity.txt",
        "WiFi/diagnostics-environment.txt",
        "WiFi/diagnostics-configuration.txt",
        "WiFi/wifi_scan.txt",
        "WiFi/leaky_ap_stats.txt",
        "WiFi/ifconfig.txt",
    ]

    // MARK: - Loss/error-rate severity scale
    //
    // There's no single official standard for "how much packet loss is
    // bad" — the commonly used network-engineering rule of thumb (aligned
    // with Cisco QoS guidance and ITU-T voice-quality benchmarks), same as
    // the Python script:
    //   < 0.1%   negligible  -- normal background noise
    //   0.1-1%   acceptable  -- fine for most traffic, shown as informational
    //   1-5%     warning     -- real-time traffic (calls/video) starts to suffer
    //   > 5%     failing     -- severe, affects almost everything
    private static let negligibleBelow = 0.1
    private static let warnAt = 1.0
    private static let failAt = 5.0

    static func classifyRate(_ pct: Double?) -> FindingSeverity? {
        guard let pct else { return nil }
        if pct >= failAt { return .fail }
        if pct >= warnAt { return .warn }
        if pct >= negligibleBelow { return .info }
        return .ok
    }

    // MARK: - Entry point

    static func parse(root: URL) -> NetworkReportResult {
        var result = NetworkReportResult()
        var findings: [NetworkFinding] = []
        var seenFindings = Set<String>()

        // De-dupes identical (severity, category, message) triples, same as
        // the Python script's `Findings.add` (e.g. repeated resolver blocks
        // would otherwise double up).
        func addFinding(_ severity: FindingSeverity, _ category: String, _ message: String) {
            let key = "\(severity.rawValue)|\(category)|\(message)"
            guard seenFindings.insert(key).inserted else { return }
            findings.append(NetworkFinding(severity: severity, category: category, message: message))
        }

        // Tries each candidate suffix in turn and returns the first one that
        // resolves to a non-empty file. `ifconfig.txt`/`netstat.txt`/
        // `route-info.txt` are the exact same tool output on iOS as macOS —
        // sysdiagnose just drops them under `logs/Networking/` there instead
        // of `network-info/` (iOS has no `network-info/` folder at all,
        // which is why the Networking tab used to come up mostly empty on
        // iOS). The DNS/proxy/reachability/advisory/rank-assertion files
        // have no iOS candidate because they're `scutil`-based and `scutil`
        // isn't a binary that exists on iOS in the first place — nothing to
        // add there.
        func text(_ suffixes: String...) -> String {
            for suffix in suffixes {
                let t = FileLocating.safeRead(FileLocating.findPathSuffix(root, suffix: suffix))
                if !t.isEmpty { return t }
            }
            return ""
        }
        func lastNonEmptyLine(_ s: String) -> String? {
            let trimmed = s.trimmingCharacters(in: .whitespacesAndNewlines)
            guard !trimmed.isEmpty else { return nil }
            return trimmed.components(separatedBy: .newlines).last
        }

        let ifconfigText: String = {
            let t = text("network-info/ifconfig.txt", "logs/Networking/ifconfig.txt")
            return t.isEmpty ? text("WiFi/ifconfig.txt") : t
        }()
        let netstatText = text("network-info/netstat.txt", "logs/Networking/netstat.txt")
        let routeText = text("network-info/route-info.txt", "logs/Networking/route-info.txt")
        let dnsText = text("network-info/dns-configuration.txt")
        let proxyText = text("network-info/proxy-configuration.txt")
        let reachText = text("network-info/reachability-info.txt")
        let advisoryText = text("network-info/interface-advisories.txt")
        let rankText = text("network-info/interface-rank-assertions.txt")
        let hostnameRaw = text("network-info/hostname.txt", "logs/Networking/hostname.txt")
        let wifiStatusText = text("WiFi/wifi_status.txt")
        let wifiDiagConnText = text("WiFi/diagnostics-connectivity.txt")
        let wifiDiagEnvText = text("WiFi/diagnostics-environment.txt")
        let wifiScanText = text("WiFi/wifi_scan.txt")

        result.found = !ifconfigText.isEmpty || !netstatText.isEmpty
        result.hostname = lastNonEmptyLine(hostnameRaw) ?? "unknown"

        // ---- Interfaces -----------------------------------------------------------
        let interfaces = parseIfconfig(ifconfigText)
        result.interfaces = interfaces
        let active = interfaces.filter { $0.isActive }
        if active.isEmpty {
            addFinding(.fail, "Interface", "No active interface with an IP address found")
        }
        for i in active {
            if let score = i.linkQualityScore, score < 80 {
                addFinding(.warn, "Interface", "\(i.name): link quality degraded (\(score)/100)")
            }
        }

        // ---- Interface error / drop counters --------------------------------------
        let counters = parseNetstatInterfaceCounters(netstatText)
        let relevant: [InterfaceCounterEntry] = {
            let filtered = counters.filter { c in active.contains { $0.name == c.name } }
            return filtered.isEmpty ? counters : filtered
        }()
        result.interfaceCounters = relevant
        for c in relevant {
            for (label, count, pct) in [
                ("input errors", c.inErrors, c.inErrorPct),
                ("output errors", c.outErrors, c.outErrorPct),
                ("dropped packets", c.drops, c.dropPct),
            ] {
                guard count > 0 else { continue }
                let msg = "\(c.name): \(count) \(label) (\(formatPct(pct))% of lifetime packets on that interface)"
                if let sev = classifyRate(pct), sev == .warn || sev == .fail {
                    addFinding(sev, "Interface", msg)
                } else {
                    addFinding(.info, "Interface", msg + " -- negligible, not a concern")
                }
            }
            if c.collisions > 0 {
                addFinding(.info, "Interface", "\(c.name): \(c.collisions) collisions (informational; rare on Wi-Fi/switched networks)")
            }
        }

        // ---- TCP/IP stack stats -----------------------------------------------------
        let stats = parseNetstatStats(netstatText)
        result.tcpStats = stats
        if let sent = stats.packetsSent, sent > 0 {
            if let sev = classifyRate(stats.retransmitRatePct) {
                let pct = stats.retransmitRatePct ?? 0
                if sev == .warn || sev == .fail {
                    addFinding(sev, "TCP", "Elevated TCP retransmit rate: \(formatPct(pct))% of packets sent")
                } else {
                    addFinding(.ok, "TCP", "TCP retransmit rate normal (\(formatPct(pct))%)")
                }
            }
            let dropped = stats.connsDroppedRexmit ?? 0
            let established = stats.connsEstablished ?? 0
            if dropped > 0 {
                var msg = "\(dropped) connections dropped due to retransmit timeout"
                var sev: FindingSeverity = .warn
                if established > 0 {
                    let dropPct = round2(100 * Double(dropped) / Double(established))
                    msg += " (\(formatPct(dropPct))% of \(established) established)"
                    sev = classifyRate(dropPct) ?? .warn
                }
                if sev == .warn || sev == .fail {
                    addFinding(sev, "TCP", msg)
                } else {
                    addFinding(.info, "TCP", msg)
                }
            }
            if let lowMem = stats.droppedLowMemory, lowMem > 0 {
                addFinding(.warn, "TCP", "\(lowMem) packets dropped due to low memory")
            }
        }

        // ---- Routing ------------------------------------------------------------
        let routes = parseRouteInfo(routeText)
        result.routes = routes
        if routes.isEmpty {
            addFinding(.warn, "Routing", "No route information found")
        } else {
            let defaultRoutes = routes.filter { $0.query == "0.0.0.0" || $0.query == "::" }
            if defaultRoutes.isEmpty {
                addFinding(.warn, "Routing", "No default route (0.0.0.0 / ::) found")
            } else {
                for r in defaultRoutes {
                    addFinding(.ok, "Routing", "Default route via \(r.gateway) on \(r.interface)")
                }
            }
        }
        if !advisoryText.contains("No advisories"), let lastLine = lastNonEmptyLine(advisoryText) {
            result.interfaceAdvisory = lastLine
            addFinding(.warn, "Routing", "Interface advisory present (see report)")
        }
        if !rankText.contains("No rank assertions") {
            result.interfaceRankAssertion = lastNonEmptyLine(rankText)
        }

        // ---- DNS ------------------------------------------------------------------
        let resolvers = parseDNSConfig(dnsText)
        result.resolvers = resolvers
        let primary = resolvers.filter { !$0.mdns && !$0.nameservers.isEmpty }
        if primary.isEmpty {
            addFinding(.warn, "DNS", "No standard (non-mDNS) DNS resolver found in configuration")
        } else {
            for r in primary {
                let joined = r.nameservers.joined(separator: ", ")
                if r.isReachable {
                    addFinding(.ok, "DNS", "Primary DNS resolver reachable (\(joined))")
                } else {
                    addFinding(.fail, "DNS", "Primary DNS resolver (\(joined)) is NOT reachable")
                }
            }
        }

        // ---- Proxy ------------------------------------------------------------------
        let proxyKeys = parseProxyConfig(proxyText)
        result.proxyEnabledKeys = proxyKeys
        if proxyKeys.isEmpty {
            addFinding(.ok, "Proxy", "No manual proxy configured")
        } else {
            addFinding(.warn, "Proxy", "A system proxy is configured — verify it isn't causing failures: \(proxyKeys.joined(separator: ", "))")
        }

        // ---- Reachability -----------------------------------------------------------
        let reach = parseReachability(reachText)
        result.reachability = reach
        for r in reach where !r.reachable {
            addFinding(.fail, "Reachability", "\(r.target) reported NOT reachable")
        }

        // ---- Wi-Fi signal -------------------------------------------------------------
        var wifi = parseWiFiStatus(wifiStatusText)
        if let rssiStr = wifi.rssi?.replacingOccurrences(of: " dBm", with: ""),
           let noiseStr = wifi.noise?.replacingOccurrences(of: " dBm", with: ""),
           let rssi = Int(rssiStr), let noise = Int(noiseStr) {
            let snr = rssi - noise
            wifi.snr = snr
            if snr < 15 {
                addFinding(.warn, "Wi-Fi", "Low SNR (\(snr) dB) — weak/noisy Wi-Fi signal")
            } else {
                addFinding(.ok, "Wi-Fi", "SNR healthy (\(snr) dB)")
            }
            if rssi < -70 {
                addFinding(.warn, "Wi-Fi", "Weak RSSI (\(rssi) dBm)")
            }
        }
        if !wifiScanText.isEmpty {
            let n = regexAllMatches(#"^\s*SSID\s*:"#, in: wifiScanText, options: [.anchorsMatchLines]).count
            if n > 0 { wifi.nearbyNetworkCount = n }
        }
        wifi.environmentChecks = parseWiFiEnvironmentChecks(wifiDiagEnvText)
        result.wifi = wifi

        // ---- Active connectivity probes (ping / DNS / curl) --------------------------
        let connRows = parseDiagnosticsTable(wifiDiagConnText)
        result.connectivityTests = connRows
        for r in connRows {
            if !r.passed {
                if r.name.uppercased().contains("AWDL") {
                    // AWDL (peer-to-peer Wi-Fi) has no target without a nearby
                    // Apple device offering it -- a "No" here is routine, not
                    // a sign of a general connectivity problem.
                    addFinding(.info, "Connectivity", "\(r.name): \(r.detail) (expected when no AWDL peer is nearby)")
                } else {
                    addFinding(.fail, "Connectivity", "\(r.name) failed: \(r.detail)")
                }
            } else if let latStr = regexFirstMatch(#"/\s*([\d.]+)\s*ms\s*/"#, in: r.detail), let lat = Double(latStr), lat > 100 {
                addFinding(.warn, "Connectivity", "\(r.name) succeeded but slow: \(latStr)ms — \(r.detail)")
            }
        }
        let countable = connRows.filter { !$0.name.uppercased().contains("AWDL") }
        if !countable.isEmpty, countable.allSatisfy({ $0.passed }) {
            addFinding(.ok, "Connectivity", "All \(countable.count) active connectivity probes passed (excluding AWDL peer-to-peer test)")
        }

        var seenLoss = Set<String>()
        var dedupedLosses: [PingLossEntry] = []
        for l in parsePingLoss(wifiDiagConnText) {
            let key = "\(l.target)|\(l.lossPct)"
            guard seenLoss.insert(key).inserted else { continue }
            dedupedLosses.append(l)
            if let sev = classifyRate(l.lossPct) {
                switch sev {
                case .warn, .fail:
                    addFinding(sev, "Connectivity", "Packet loss to \(l.target): \(formatPct(l.lossPct))%")
                case .info:
                    addFinding(.info, "Connectivity", "Minor packet loss to \(l.target): \(formatPct(l.lossPct))% (below concern threshold)")
                case .ok:
                    break
                }
            }
        }
        result.pingLosses = dedupedLosses

        // ---- VPN & Proxy (SystemConfiguration preferences.plist) --------------------
        // `network-info/preferences.plist` is macOS's copy; `SystemConfiguration/
        // preferences.plist` is the canonical one sysdiagnose also grabs
        // separately; `logs/Networking/preferences.plist` is iOS's location.
        // Same `Sets`/`CurrentSet`/`NetworkServices` shape on both platforms —
        // this is literally the file `scutil` itself reads from, which is
        // why it's usable as a substitute for `scutil --proxy`/`--nc list`
        // on iOS, where `scutil` isn't a binary that exists at all.
        let prefsPlistPath = FileLocating.findPathSuffix(root, suffix: "network-info/preferences.plist")
            ?? FileLocating.findPathSuffix(root, suffix: "logs/Networking/preferences.plist")
            ?? FileLocating.findPathSuffix(root, suffix: "SystemConfiguration/preferences.plist")
        let services = parseNetworkServices(FileLocating.safePlist(prefsPlistPath))
        result.networkServices = services
        for svc in services {
            if svc.isVPN {
                let provider = svc.vpnProvider.map { " (\($0))" } ?? ""
                let onDemand = svc.vpnOnDemand == true ? ", On-Demand enabled" : ""
                addFinding(.info, "VPN", "VPN configured: \(svc.name)\(provider)\(onDemand)")
            }
            if !svc.proxyEnabledKeys.isEmpty {
                addFinding(.warn, "Proxy", "Proxy configured on \(svc.name) — verify it isn't causing failures: \(svc.proxyEnabledKeys.joined(separator: ", "))")
            }
        }

        findings.sort { $0.severity.sortRank < $1.severity.sortRank }
        result.findings = findings
        return result
    }

    // MARK: - Section parsers

    static func parseIfconfig(_ text: String) -> [NetworkInterfaceEntry] {
        var result: [NetworkInterfaceEntry] = []
        for block in blocksStartingWith(#"^\S+: flags=\d+<[^>]*>"#, in: text) {
            guard let groups = regexMatchGroups(#"^(\S+): flags=\d+<([^>]*)>"#, in: block), groups.count == 2 else { continue }
            let name = groups[0]
            let flags = Set(groups[1].split(separator: ",").map(String.init))
            let status = regexFirstMatch(#"status:\s*(\w+)"#, in: block)
            let media = regexFirstMatch(#"media:\s*(.+)"#, in: block)?.trimmingCharacters(in: .whitespaces)
            let type = regexFirstMatch(#"functional type:\s*(\S+)"#, in: block)
            var qualityScore: Int?
            var qualityLabel: String?
            if let qm = regexMatchGroups(#"link quality:\s*(\d+)\s*\((\w+)\)"#, in: block), qm.count == 2 {
                qualityScore = Int(qm[0])
                qualityLabel = qm[1]
            }
            let inet = regexAllMatchGroups(#"^\s*inet (\d+\.\d+\.\d+\.\d+)"#, in: block, options: [.anchorsMatchLines]).compactMap { $0.first }
            let inet6 = regexAllMatchGroups(#"^\s*inet6 (\S+)"#, in: block, options: [.anchorsMatchLines]).compactMap { $0.first }
            result.append(NetworkInterfaceEntry(
                name: name,
                up: flags.contains("UP"),
                running: flags.contains("RUNNING"),
                status: status,
                media: media,
                type: type,
                linkQualityScore: qualityScore,
                linkQualityLabel: qualityLabel,
                ipv4: inet,
                ipv6: inet6
            ))
        }
        return result
    }

    /// Parses the `netstat -i -n -d` table; keeps only the per-interface
    /// `<Link#N>` summary rows (the address-specific rows repeat with `-`).
    static func parseNetstatInterfaceCounters(_ text: String) -> [InterfaceCounterEntry] {
        var rows: [InterfaceCounterEntry] = []
        let lines = text.components(separatedBy: "\n")
        guard let headerIdx = lines.firstIndex(where: { $0.hasPrefix("Name") && $0.contains("Drop") }) else { return rows }
        for line in lines[(headerIdx + 1)...] {
            if line.trimmingCharacters(in: .whitespaces).isEmpty { break }
            if line.hasPrefix("Name") { continue }
            guard line.contains("<Link#") else { continue }
            let parts = line.split(whereSeparator: { $0 == " " || $0 == "\t" }).map(String.init)
            guard parts.count >= 8 else { continue }
            var name = parts[0]
            while name.hasSuffix("*") { name.removeLast() }
            let tail = Array(parts.suffix(6)).compactMap { Int($0) }
            guard tail.count == 6 else { continue }
            let (ipkts, ierrs, opkts, oerrs, coll, drop) = (tail[0], tail[1], tail[2], tail[3], tail[4], tail[5])
            rows.append(InterfaceCounterEntry(
                name: name, inPackets: ipkts, inErrors: ierrs, outPackets: opkts, outErrors: oerrs,
                collisions: coll, drops: drop,
                inErrorPct: ipkts > 0 ? round4(100 * Double(ierrs) / Double(ipkts)) : 0.0,
                outErrorPct: opkts > 0 ? round4(100 * Double(oerrs) / Double(opkts)) : 0.0,
                dropPct: opkts > 0 ? round4(100 * Double(drop) / Double(opkts)) : 0.0
            ))
        }
        return rows
    }

    /// Pulls key retransmit/drop/unreachable counters out of `netstat -s`.
    static func parseNetstatStats(_ text: String) -> TCPStackStats {
        var stats = TCPStackStats()
        let tcpBlock = regexMatchGroups(#"\ntcp:\n(.*?)\n(?:udp:|ip:|icmp:|\z)"#, in: text, options: [.dotMatchesLineSeparators])?.first ?? ""
        let routingBlock = regexMatchGroups(#"\nrouting:\n(.*?)(?:\n#|\z)"#, in: text, options: [.dotMatchesLineSeparators])?.first ?? ""

        func grabInt(_ pattern: String, in t: String) -> Int? {
            regexFirstMatch(pattern, in: t).flatMap { Int($0) }
        }

        stats.packetsSent = grabInt(#"(\d+) packets sent"#, in: tcpBlock)
        stats.dataRetransmitted = grabInt(#"(\d+) data packets? \([\d,]+ bytes\) retransmitted"#, in: tcpBlock)
        stats.retransmitTimeouts = grabInt(#"(\d+) retransmit timeouts"#, in: tcpBlock)
        stats.connsDroppedRexmit = grabInt(#"(\d+) connections? dropped by rexmit timeout"#, in: tcpBlock)
        stats.connsEstablished = grabInt(#"(\d+) connections? established"#, in: tcpBlock)
        stats.connsClosed = grabInt(#"(\d+) connections? closed"#, in: tcpBlock)
        stats.connsClosedDrops = grabInt(#"connections closed \(including (\d+) drops?\)"#, in: tcpBlock)
        stats.embryonicDropped = grabInt(#"(\d+) embryonic connections dropped"#, in: tcpBlock)
        stats.badConnAttempts = grabInt(#"(\d+) bad connection attempts"#, in: tcpBlock)
        stats.dupAcks = grabInt(#"(\d+) duplicate acks"#, in: tcpBlock)
        stats.outOfOrder = grabInt(#"(\d+) out-of-order packets"#, in: tcpBlock)
        stats.droppedLowMemory = grabInt(#"(\d+) received packet dropped due to low memory"#, in: tcpBlock)
        stats.destinationsUnreachable = grabInt(#"(\d+) destinations found unreachable"#, in: routingBlock)

        if let sent = stats.packetsSent, let retrans = stats.dataRetransmitted {
            stats.retransmitRatePct = round2(100 * Double(retrans) / Double(max(sent, 1)))
        }
        return stats
    }

    /// Extracts destination/gateway/interface for each `route get` query.
    static func parseRouteInfo(_ text: String) -> [RouteEntry] {
        let pattern = #"# (/sbin/route.*?get.*?)\n#\n.*?destination:\s*(\S+)(?:\s*\n\s*mask:\s*(\S+))?\s*\n\s*gateway:\s*(\S+)\s*\n\s*interface:\s*(\S+)"#
        var routes: [RouteEntry] = []
        for groups in regexAllMatchGroups(pattern, in: text, options: [.dotMatchesLineSeparators]) {
            guard groups.count == 5 else { continue }
            let cmd = groups[0]
            let dest = groups[1]
            let gw = groups[3]
            let iface = groups[4]
            let query = regexFirstMatch(#"get\s+(?:-inet6\s+)?(\S+)"#, in: cmd) ?? cmd.trimmingCharacters(in: .whitespacesAndNewlines)
            _ = dest // unused beyond confirming the block matched; query comes from the command line, matching the Python script
            routes.append(RouteEntry(query: query, gateway: gw, interface: iface))
        }
        return routes
    }

    /// Parses `scutil --dns` resolver blocks. Only the first (global) DNS
    /// configuration section is used — `scutil` repeats the same resolvers
    /// a second time under "DNS configuration (for scoped queries)", which
    /// would otherwise double every finding.
    static func parseDNSConfig(_ text: String) -> [DNSResolverEntry] {
        let scoped = text.components(separatedBy: "DNS configuration (for scoped queries)").first ?? text
        let pieces = regexSplit(#"\nresolver #\d+\n"#, in: scoped)
        guard pieces.count > 1 else { return [] }
        var resolvers: [DNSResolverEntry] = []
        for block in pieces.dropFirst() {
            let nameservers = regexAllMatchGroups(#"nameserver\[\d+\]\s*:\s*(\S+)"#, in: block).compactMap { $0.first }
            let domain = regexFirstMatch(#"domain\s*:\s*(\S+)"#, in: block)
            let search = regexAllMatchGroups(#"search domain\[\d+\]\s*:\s*(\S+)"#, in: block).compactMap { $0.first }
            let reach = regexFirstMatch(#"reach\s*:\s*0x[0-9a-fA-F]+ \(([^)]*)\)"#, in: block)
            let options = regexFirstMatch(#"options\s*:\s*(\S+)"#, in: block)
            let order = regexFirstMatch(#"order\s*:\s*(\d+)"#, in: block).flatMap { Int($0) }
            resolvers.append(DNSResolverEntry(
                domain: domain,
                searchDomains: search,
                nameservers: nameservers,
                reachableString: reach,
                // Mirrors the Python report's default: no `reach` field at
                // all is treated as reachable, only an explicit
                // "Not Reachable" flips it.
                isReachable: !(reach?.contains("Not Reachable") ?? false),
                mdns: options == "mdns",
                order: order
            ))
        }
        return resolvers
    }

    static func parseProxyConfig(_ text: String) -> [String] {
        let keys = ["HTTPEnable", "HTTPSEnable", "SOCKSEnable", "ProxyAutoConfigEnable", "ProxyAutoDiscoveryEnable"]
        var enabled: [String] = []
        for key in keys {
            if let v = regexFirstMatch("\(key)\\s*:\\s*(\\d)", in: text), v == "1" {
                enabled.append(key)
            }
        }
        return enabled
    }

    /// Same proxy-type keys `parseProxyConfig` looks for in `scutil --proxy`'s
    /// text output, applied instead to a `NetworkServices.<uuid>.Proxies`
    /// plist dict — kept as one shared list so "a proxy is configured"
    /// means the same thing everywhere in this report, whichever source it
    /// came from.
    private static let proxyEnableKeys = ["HTTPEnable", "HTTPSEnable", "SOCKSEnable", "ProxyAutoConfigEnable", "ProxyAutoDiscoveryEnable"]

    /// Parses SystemConfiguration `preferences.plist`'s `NetworkServices`
    /// dict into the VPN/proxy entries worth surfacing. Every network
    /// service (Wi-Fi, Ethernet, Cellular, VPN, ...) carries a `Proxies`
    /// sub-dict, but almost all of them have nothing actually turned on in
    /// it (just inert bypass-list/FTP-passive housekeeping) — only services
    /// that are a VPN, or that have at least one real proxy type enabled,
    /// are kept, everything else would just be noise.
    static func parseNetworkServices(_ plist: PlistValue?) -> [NetworkServiceEntry] {
        guard let services = plist?["NetworkServices"]?.asDict else { return [] }
        var entries: [NetworkServiceEntry] = []
        for (_, service) in services {
            guard let service = service.asDict else { continue }
            let interface = service["Interface"]?.asDict
            let name = interface?["UserDefinedName"]?.asString
                ?? service["UserDefinedName"]?.asString
                ?? "Unnamed Service"
            let interfaceType = interface?["Type"]?.asString ?? interface?["Hardware"]?.asString ?? "Unknown"
            let isVPN = interfaceType == "VPN"

            var vpnProvider: String?
            var vpnOnDemand: Bool?
            if isVPN, let vpn = service["VPN"]?.asDict {
                vpnProvider = vpn["NEProviderBundleIdentifier"]?.asString ?? interface?["SubType"]?.asString
                vpnOnDemand = vpn["OnDemandEnabled"]?.isTruthyActive
            }

            var enabledProxyKeys: [String] = []
            if let proxies = service["Proxies"]?.asDict {
                for key in proxyEnableKeys where proxies[key]?.isTruthyActive == true {
                    enabledProxyKeys.append(key)
                }
            }

            guard isVPN || !enabledProxyKeys.isEmpty else { continue }
            entries.append(NetworkServiceEntry(
                name: name, interfaceType: interfaceType, isVPN: isVPN,
                vpnProvider: vpnProvider, vpnOnDemand: vpnOnDemand, proxyEnabledKeys: enabledProxyKeys
            ))
        }
        return entries.sorted { $0.name < $1.name }
    }

    static func parseReachability(_ text: String) -> [ReachabilityCheckEntry] {
        let pattern = #"# /usr/sbin/scutil.*?-r\s+(\S+)\s*\n#\n.*?flags = 0x[0-9a-fA-F]+ \(([^)]*)\)\nrelease"#
        return regexAllMatchGroups(pattern, in: text, options: [.dotMatchesLineSeparators]).compactMap { groups in
            guard groups.count == 2 else { return nil }
            return ReachabilityCheckEntry(target: groups[0], flags: groups[1], reachable: groups[1].contains("Reachable"))
        }
    }

    static func parseWiFiStatus(_ text: String) -> WiFiStatusInfo {
        var fields: [String: String] = [:]
        for line in text.components(separatedBy: "\n") {
            guard let groups = regexMatchGroups(#"^\s*([A-Za-z0-9 /]+?)\s{2,}:\s*(.*)$"#, in: line), groups.count == 2 else { continue }
            let key = groups[0].trimmingCharacters(in: .whitespaces)
            if fields[key] == nil {
                fields[key] = groups[1].trimmingCharacters(in: .whitespaces)
            }
        }
        var info = WiFiStatusInfo()
        info.interfaceName = fields["Interface Name"]
        info.ssid = fields["SSID"]
        info.rssi = fields["RSSI"]
        info.noise = fields["Noise"]
        info.txRate = fields["Tx Rate"]
        info.phyMode = fields["PHY Mode"]
        info.channel = fields["Channel"]
        info.security = fields["Security"]
        return info
    }

    /// Parses `WiFi/diagnostics-environment.txt`'s check table — same
    /// fixed-width shape as the connectivity probe table below (name,
    /// duration, `Yes`/`No` result, timestamp, description) despite the
    /// file's own (misleading) header row implying a different column
    /// order. Keeps only the checks worth surfacing in the Wi-Fi Signal &
    /// Link card as a second column: **Congested Wi-Fi Channel** always
    /// (channel congestion is useful context either way), and any
    /// `Conflicting ...` / **Hidden Wi-Fi Scan Results** check, but only
    /// when its `Result` actually flags the condition as detected (`Yes`) —
    /// a "no conflict found" row for every one of those checks on every
    /// sysdiagnose would just be noise.
    static func parseWiFiEnvironmentChecks(_ text: String) -> [WiFiEnvironmentCheckEntry] {
        let pattern = #"^(\S.{0,40}?)\s{2,}([\d.]+)\s+(Yes|No)\s+(\d{2}:\d{2}:\d{2}\.\d+)\s+(.*)$"#
        var rows: [WiFiEnvironmentCheckEntry] = []
        for line in text.components(separatedBy: "\n") {
            guard let groups = regexMatchGroups(pattern, in: line), groups.count == 5 else { continue }
            let name = groups[0].trimmingCharacters(in: .whitespaces)
            let isCongestedChannel = name == "Congested Wi-Fi Channel"
            let isTrackedConflictCheck = name == "Hidden Wi-Fi Scan Results" || name.hasPrefix("Conflicting")
            guard isCongestedChannel || isTrackedConflictCheck else { continue }
            let flagged = groups[2] == "Yes"
            guard isCongestedChannel || flagged else { continue }
            rows.append(WiFiEnvironmentCheckEntry(
                name: name, flagged: flagged, timestamp: groups[3], detail: groups[4]
            ))
        }
        return rows
    }

    static func parseDiagnosticsTable(_ text: String) -> [ConnectivityTestEntry] {
        let pattern = #"^(\S.{0,40}?)\s{2,}([\d.]+)\s+(Yes|No)\s+(\d{2}:\d{2}:\d{2}\.\d+)\s+(.*)$"#
        var rows: [ConnectivityTestEntry] = []
        for line in text.components(separatedBy: "\n") {
            guard let groups = regexMatchGroups(pattern, in: line), groups.count == 5 else { continue }
            rows.append(ConnectivityTestEntry(
                name: groups[0].trimmingCharacters(in: .whitespaces),
                passed: groups[2] == "Yes",
                durationSeconds: groups[1],
                timestamp: groups[3],
                detail: groups[4]
            ))
        }
        return rows
    }

    /// Grabs `<pct>% packet loss` lines from ping result blocks, with the
    /// preceding command line (for target) as a fallback when the `PING`
    /// banner line itself isn't present.
    static func parsePingLoss(_ text: String) -> [PingLossEntry] {
        var losses: [PingLossEntry] = []
        for block in blocksStartingWith(#"^/sbin/ping"#, in: text) {
            guard let lossStr = regexFirstMatch(#"([\d.]+)% packet loss"#, in: block), let loss = Double(lossStr) else { continue }
            var target = "?"
            if let t = regexFirstMatch(#"PING (\S+) \("#, in: block) {
                target = t
            } else if let firstLine = block.components(separatedBy: "\n").first,
                      let cmdTarget = regexFirstMatch(#"/sbin/ping.*?\s(\S+)\s*$"#, in: firstLine) {
                target = cmdTarget
            }
            losses.append(PingLossEntry(target: target, lossPct: loss))
        }
        return losses
    }

    // MARK: - Small helpers

    /// Splits `text` into blocks that each start at (and include) a match of
    /// `headerPattern` — the header line stays as part of the block that
    /// follows it. Any text before the first match is dropped entirely,
    /// same net effect as the Python script's `re.split` on a zero-width
    /// lookahead followed by `if not m: continue` on the leftover piece.
    private static func blocksStartingWith(_ headerPattern: String, in text: String) -> [String] {
        guard let re = try? NSRegularExpression(pattern: headerPattern, options: [.anchorsMatchLines]) else { return [] }
        let nsText = text as NSString
        let matches = re.matches(in: text, range: NSRange(location: 0, length: nsText.length))
        var blocks: [String] = []
        for (idx, m) in matches.enumerated() {
            let start = m.range.location
            let end = idx + 1 < matches.count ? matches[idx + 1].range.location : nsText.length
            blocks.append(nsText.substring(with: NSRange(location: start, length: end - start)))
        }
        return blocks
    }

    /// Splits `text` on every match of `pattern`, dropping the matched
    /// delimiter text — a direct port of Python's `re.split(pattern, text)`.
    private static func regexSplit(_ pattern: String, in text: String, options: NSRegularExpression.Options = []) -> [String] {
        guard let re = try? NSRegularExpression(pattern: pattern, options: options) else { return [text] }
        let nsText = text as NSString
        let matches = re.matches(in: text, range: NSRange(location: 0, length: nsText.length))
        guard !matches.isEmpty else { return [text] }
        var pieces: [String] = []
        var lastEnd = 0
        for m in matches {
            pieces.append(nsText.substring(with: NSRange(location: lastEnd, length: m.range.location - lastEnd)))
            lastEnd = m.range.location + m.range.length
        }
        pieces.append(nsText.substring(from: lastEnd))
        return pieces
    }

    private static func round2(_ v: Double) -> Double { (v * 100).rounded() / 100 }
    private static func round4(_ v: Double) -> Double { (v * 10000).rounded() / 10000 }

    /// Formats a rounded percentage the way Python's f-string interpolation
    /// of a `round(x, n)` float prints it — trailing zeros trimmed, but
    /// always at least one digit after the decimal point (`0.0`, not `0`).
    private static func formatPct(_ v: Double) -> String {
        if v == 0 { return "0.0" }
        var s = String(format: "%.4f", v)
        while s.hasSuffix("0") { s.removeLast() }
        if s.hasSuffix(".") { s += "0" }
        return s
    }
}
