import SwiftUI

/// Network health report — a port of `sysdiag_netcheck.py`'s Markdown
/// output as a native tab: interface errors/drops, TCP retransmits,
/// routing, DNS, proxy config, Wi-Fi signal quality, and the active
/// connectivity probes (ping/DNS/curl) every sysdiagnose captures.
struct NetworkingTabView: View {
    let report: NetworkReportResult
    var wifiHistory: WiFiHistoryResult = WiFiHistoryResult()

    @State private var findText = ""
    @State private var committedFindText = ""
    @State private var showFindBar = false
    @FocusState private var findFieldFocused: Bool

    private var filteredFindings: [NetworkFinding] {
        committedFindText.isEmpty ? report.findings : report.findings.filter {
            matchesAny([$0.category, $0.message], query: committedFindText)
        }
    }

    private var filteredInterfaces: [NetworkInterfaceEntry] {
        let active = report.interfaces.filter { $0.isActive }
        guard !committedFindText.isEmpty else { return active }
        return active.filter { matchesAny([$0.name, $0.type ?? "", $0.media ?? ""], query: committedFindText) }
    }

    private var filteredCounters: [InterfaceCounterEntry] {
        committedFindText.isEmpty ? report.interfaceCounters : report.interfaceCounters.filter {
            matchesAny([$0.name], query: committedFindText)
        }
    }

    private var filteredRoutes: [RouteEntry] {
        committedFindText.isEmpty ? report.routes : report.routes.filter {
            matchesAny([$0.query, $0.gateway, $0.interface], query: committedFindText)
        }
    }

    // macOS registers several built-in mDNS/Bonjour resolvers for special
    // reverse-lookup zones (`local`, `254.169.in-addr.arpa`,
    // `8.e.f.ip6.arpa`, etc.) alongside the one real, configured resolver —
    // those are resolved via local multicast rather than a nameserver, so
    // they never have one, and scutil always reports them as
    // "Not Reachable" by definition, not because anything's actually
    // broken. The Python report excludes them from what it displays (same
    // `!mdns && has nameservers` filter used for the "primary resolver"
    // finding); this view was rendering the raw unfiltered list instead.
    private var primaryResolvers: [DNSResolverEntry] {
        report.resolvers.filter { !$0.mdns && !$0.nameservers.isEmpty }
    }

    private var filteredResolvers: [DNSResolverEntry] {
        committedFindText.isEmpty ? primaryResolvers : primaryResolvers.filter {
            matchesAny($0.nameservers + [$0.domain ?? ""], query: committedFindText)
        }
    }

    private var filteredReachability: [ReachabilityCheckEntry] {
        committedFindText.isEmpty ? report.reachability : report.reachability.filter {
            matchesAny([$0.target, $0.flags], query: committedFindText)
        }
    }

    private var filteredConnectivity: [ConnectivityTestEntry] {
        committedFindText.isEmpty ? report.connectivityTests : report.connectivityTests.filter {
            matchesAny([$0.name, $0.detail], query: committedFindText)
        }
    }

    private var filteredWifiHistory: [WiFiHistoryEvent] {
        committedFindText.isEmpty ? wifiHistory.events : wifiHistory.events.filter {
            matchesAny([$0.category, $0.detail], query: committedFindText)
        }
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 16) {
            if showFindBar {
                FindBarView(placeholder: "Find in network report", text: $findText,
                            matchCount: committedFindText.isEmpty ? nil : filteredFindings.count,
                            isFocused: $findFieldFocused) {
                    showFindBar = false
                    findText = ""
                }
            }
            if let error = report.error {
                CardView { EmptyStateView(text: "⚠️ \(error)") }
            } else if !report.found {
                CardView { EmptyStateView(text: "No network configuration files were found in this sysdiagnose.") }
            } else {
                hostCard
                findingsCard
                interfacesCard
                interfaceCountersCard
                tcpStatsCard
                routingCard
                dnsCard
                proxyCard
                networkServicesCard
                reachabilityCard
                wifiCard
                wifiHistoryCard
                connectivityCard
            }
        }
        .environment(\.findQuery, committedFindText)
        .background(FindShortcut { showFindBar = true; findFieldFocused = true })
        .task(id: findText) {
            try? await Task.sleep(nanoseconds: 150_000_000)
            guard !Task.isCancelled else { return }
            committedFindText = findText
        }
    }

    // MARK: - Sections

    private var hostCard: some View {
        HStack {
            Text("📶 Network Health Report").font(.system(size: 14, weight: .semibold))
            Spacer()
            Text("Host: \(report.hostname)").font(.caption).foregroundStyle(.secondary)
        }
        .padding(.horizontal, 4)
    }

    private var findingsCard: some View {
        CardView(title: "Summary of Findings") {
            if filteredFindings.isEmpty {
                EmptyStateView(text: committedFindText.isEmpty ? "No findings collected." : "No findings match \"\(committedFindText)\".")
            } else {
                VStack(spacing: 0) {
                    ForEach(Array(filteredFindings.enumerated()), id: \.1.id) { idx, finding in
                        FindingRow(finding: finding, isLast: idx == filteredFindings.count - 1)
                    }
                }
            }
        }
    }

    @ViewBuilder
    private var interfacesCard: some View {
        CardView(title: "Interfaces") {
            if filteredInterfaces.isEmpty {
                EmptyStateView(text: "No active interfaces with an IP address were found.")
            } else {
                VStack(spacing: 0) {
                    tableHeader(["Interface", "Type", "Status", "Media", "Link Quality", "IPv4"],
                                widths: [90, 70, 70, 110, 110, nil])
                    Divider()
                    ForEach(Array(filteredInterfaces.enumerated()), id: \.1.id) { idx, entry in
                        InterfaceRow(entry: entry, isLast: idx == filteredInterfaces.count - 1)
                    }
                }
            }
        }
    }

    @ViewBuilder
    private var interfaceCountersCard: some View {
        CardView(title: "Interface Errors & Drops (netstat -i)") {
            if filteredCounters.isEmpty {
                EmptyStateView(text: "No interface counters found.")
            } else {
                VStack(alignment: .leading, spacing: 0) {
                    Text("These counters are cumulative totals since the last boot, not from a single test.")
                        .font(.caption2).foregroundStyle(.secondary)
                        .padding(.horizontal, 16).padding(.top, 10)
                    tableHeader(["Interface", "In pkts", "In errs", "Out pkts", "Out errs", "Coll", "Drops"],
                                widths: [80, 80, 90, 80, 90, 50, 90])
                    Divider()
                    ForEach(Array(filteredCounters.enumerated()), id: \.1.id) { idx, entry in
                        CounterRow(entry: entry, isLast: idx == filteredCounters.count - 1)
                    }
                }
            }
        }
    }

    private var tcpStatsCard: some View {
        CardView(title: "TCP/IP Stack Health (netstat -s)") {
            let stats = report.tcpStats
            let rows: [(String, String?)] = [
                ("Packets sent", stats.packetsSent.map(String.init)),
                ("Data packets retransmitted", stats.dataRetransmitted.map(String.init)),
                ("Retransmit timeouts", stats.retransmitTimeouts.map(String.init)),
                ("Connections dropped by rexmit timeout", stats.connsDroppedRexmit.map(String.init)),
                ("Connections closed (with drops)", stats.connsClosedDrops.map(String.init)),
                ("Embryonic connections dropped", stats.embryonicDropped.map(String.init)),
                ("Bad connection attempts", stats.badConnAttempts.map(String.init)),
                ("Duplicate ACKs received", stats.dupAcks.map(String.init)),
                ("Out-of-order packets received", stats.outOfOrder.map(String.init)),
                ("Packets dropped (low memory)", stats.droppedLowMemory.map(String.init)),
                ("Destinations found unreachable", stats.destinationsUnreachable.map(String.init)),
                ("Retransmit rate", stats.retransmitRatePct.map { "\(trimmed($0))%" }),
            ]
            let present = rows.filter { $0.1 != nil }
            if present.isEmpty {
                EmptyStateView(text: "No TCP stats found.")
            } else {
                VStack(spacing: 0) {
                    ForEach(Array(present.enumerated()), id: \.offset) { idx, row in
                        HStack {
                            Text(row.0).font(.system(size: 12)).foregroundStyle(.secondary)
                            Spacer()
                            Text(row.1 ?? "").font(.system(size: 12, design: .monospaced))
                        }
                        .padding(.horizontal, 16).padding(.vertical, 6)
                        if idx != present.count - 1 { Divider().padding(.leading, 16) }
                    }
                }
            }
        }
    }

    @ViewBuilder
    private var routingCard: some View {
        CardView(title: "Routing") {
            VStack(alignment: .leading, spacing: 0) {
                if filteredRoutes.isEmpty {
                    EmptyStateView(text: "No route information found.")
                } else {
                    tableHeader(["Query", "Gateway", "Interface"], widths: [180, nil, 90])
                    Divider()
                    ForEach(Array(filteredRoutes.enumerated()), id: \.1.id) { idx, route in
                        RouteRow(entry: route, isLast: idx == filteredRoutes.count - 1)
                    }
                }
                if let advisory = report.interfaceAdvisory {
                    Text("Interface advisories: \(advisory)")
                        .font(.caption2).foregroundStyle(.orange)
                        .padding(.horizontal, 16).padding(.vertical, 8)
                }
                if let rank = report.interfaceRankAssertion {
                    Text("Interface rank assertions: \(rank)")
                        .font(.caption2).foregroundStyle(.secondary)
                        .padding(.horizontal, 16).padding(.bottom, 8)
                }
            }
        }
    }

    @ViewBuilder
    private var dnsCard: some View {
        CardView(title: "DNS Configuration") {
            if filteredResolvers.isEmpty {
                EmptyStateView(text: "No non-mDNS resolver configuration found.")
            } else {
                VStack(alignment: .leading, spacing: 10) {
                    ForEach(filteredResolvers) { r in
                        VStack(alignment: .leading, spacing: 2) {
                            HighlightedText(text: "Nameservers: \(r.nameservers.joined(separator: ", "))", query: committedFindText)
                                .font(.system(size: 12, design: .monospaced))
                            if !r.searchDomains.isEmpty {
                                Text("Search domain(s): \(r.searchDomains.joined(separator: ", "))")
                                    .font(.caption2).foregroundStyle(.secondary)
                            }
                            if let reach = r.reachableString {
                                Text("Reachability: \(reach)")
                                    .font(.caption2)
                                    .foregroundStyle(r.isReachable ? Color.secondary : Color.red)
                            }
                        }
                    }
                }
                .padding(16)
            }
        }
    }

    private var proxyCard: some View {
        CardView(title: "Proxy Configuration") {
            Text(report.proxyEnabledKeys.isEmpty
                 ? "No manual proxy or PAC configured (direct connection)."
                 : "Manual/auto proxy settings detected: \(report.proxyEnabledKeys.joined(separator: ", "))")
                .font(.system(size: 12))
                .foregroundStyle(report.proxyEnabledKeys.isEmpty ? Color.secondary : Color.orange)
                .padding(16)
        }
    }

    // Real VPN/proxy state pulled straight from SystemConfiguration's own
    // preferences.plist (see NetworkReportParser.parseNetworkServices) —
    // the same file `scutil` itself reads from, which is what makes this
    // possible on iOS at all, where `scutil` isn't a binary that exists to
    // produce the Proxy Configuration card above. Only appears when
    // there's an actual VPN or an enabled proxy to show — most sysdiagnoses
    // have neither, and the Proxy Configuration card above already covers
    // "nothing configured."
    @ViewBuilder
    private var networkServicesCard: some View {
        if !report.networkServices.isEmpty {
            CardView(title: "VPN & Proxy (Configured Services)") {
                VStack(spacing: 0) {
                    ForEach(Array(report.networkServices.enumerated()), id: \.1.id) { idx, svc in
                        NetworkServiceRow(entry: svc, isLast: idx == report.networkServices.count - 1)
                    }
                }
            }
        }
    }

    @ViewBuilder
    private var reachabilityCard: some View {
        CardView(title: "SCNetworkReachability Checks") {
            if filteredReachability.isEmpty {
                EmptyStateView(text: "No reachability probe data found.")
            } else {
                VStack(spacing: 0) {
                    tableHeader(["Target", "Flags"], widths: [180, nil])
                    Divider()
                    ForEach(Array(filteredReachability.enumerated()), id: \.1.id) { idx, r in
                        ReachabilityRow(entry: r, isLast: idx == filteredReachability.count - 1)
                    }
                }
            }
        }
    }

    @ViewBuilder
    private var wifiCard: some View {
        CardView(title: "Wi-Fi Signal & Link") {
            if report.wifi.isEmpty {
                EmptyStateView(text: "No Wi-Fi status data found (may be Ethernet-only).")
            } else {
                HStack(alignment: .top, spacing: 20) {
                    VStack(alignment: .leading, spacing: 4) {
                        wifiField("Interface Name", report.wifi.interfaceName)
                        wifiField("SSID", report.wifi.ssid)
                        wifiField("RSSI", report.wifi.rssi)
                        wifiField("Noise", report.wifi.noise)
                        wifiField("Tx Rate", report.wifi.txRate)
                        wifiField("PHY Mode", report.wifi.phyMode)
                        wifiField("Channel", report.wifi.channel)
                        wifiField("Security", report.wifi.security)
                        if let snr = report.wifi.snr {
                            HStack(spacing: 4) {
                                Text("SNR (computed):").font(.system(size: 12, weight: .semibold))
                                Text("\(snr) dB").font(.system(size: 12, design: .monospaced))
                                Badge(text: snr < 15 ? "weak" : "healthy", color: snr < 15 ? .orange : .green)
                            }
                        }
                        if let n = report.wifi.nearbyNetworkCount {
                            Text("Nearby networks seen in scan: \(n)").font(.caption).foregroundStyle(.secondary)
                        }
                    }
                    // Second column: the handful of environment/conflict
                    // checks from diagnostics-environment.txt worth calling
                    // out — see parseWiFiEnvironmentChecks for which ones
                    // and why. Only takes up space when there's something
                    // to show.
                    if !report.wifi.environmentChecks.isEmpty {
                        Divider().frame(maxHeight: .infinity)
                        VStack(alignment: .leading, spacing: 8) {
                            Text("Environment Checks").font(.system(size: 12, weight: .semibold)).foregroundStyle(.secondary)
                            ForEach(report.wifi.environmentChecks) { check in
                                WiFiEnvironmentCheckRow(entry: check)
                            }
                        }
                        .frame(maxWidth: 280, alignment: .leading)
                    }
                    Spacer(minLength: 0)
                }
                .padding(16)
            }
        }
    }

    // Decoded from any WiFi/CoreCapture bundle's History.txt — a rolling,
    // on-device log of Wi-Fi auth/deauth/reassociation failures that goes
    // back much further than a single sysdiagnose capture. Only appears
    // when at least one such bundle was found and decoded; not every
    // sysdiagnose has one. See WiFiHistoryParser for how the raw
    // uptime-since-boot values get converted to real dates.
    @ViewBuilder
    private var wifiHistoryCard: some View {
        if wifiHistory.found {
            CardView(title: "Historical Wi-Fi Events") {
                VStack(alignment: .leading, spacing: 0) {
                    Text("Decoded from the device's own Wi-Fi debug capture log — covers failures going back further than this single sysdiagnose.")
                        .font(.caption2).foregroundStyle(.secondary)
                        .padding(.horizontal, 16).padding(.top, 10)
                    if filteredWifiHistory.isEmpty {
                        EmptyStateView(text: committedFindText.isEmpty ? "No historical Wi-Fi events decoded." : "No historical Wi-Fi events match \"\(committedFindText)\".")
                    } else {
                        tableHeader(["When", "Event", "Detail"], widths: [160, 190, nil])
                        Divider()
                        ForEach(Array(filteredWifiHistory.enumerated()), id: \.1.id) { idx, event in
                            WiFiHistoryRow(event: event, isLast: idx == filteredWifiHistory.count - 1)
                        }
                    }
                }
            }
        }
    }

    @ViewBuilder
    private var connectivityCard: some View {
        CardView(title: "Active Connectivity Tests") {
            VStack(alignment: .leading, spacing: 0) {
                if filteredConnectivity.isEmpty {
                    EmptyStateView(text: "No active connectivity probe results found.")
                } else {
                    tableHeader(["Test", "Result", "Duration (s)", "Detail"], widths: [110, 70, 90, nil])
                    Divider()
                    ForEach(Array(filteredConnectivity.enumerated()), id: \.1.id) { idx, row in
                        ConnectivityRow(entry: row, isLast: idx == filteredConnectivity.count - 1)
                    }
                }
                if !report.pingLosses.isEmpty {
                    Divider().padding(.top, 4)
                    Text("Ping packet loss").font(.system(size: 12, weight: .semibold))
                        .padding(.horizontal, 16).padding(.top, 10)
                    tableHeader(["Target", "Packet loss"], widths: [180, nil])
                    Divider()
                    ForEach(Array(report.pingLosses.enumerated()), id: \.1.id) { idx, loss in
                        PingLossRow(entry: loss, isLast: idx == report.pingLosses.count - 1)
                    }
                }
            }
        }
    }

    // MARK: - Shared helpers

    private func tableHeader(_ labels: [String], widths: [CGFloat?]) -> some View {
        HStack {
            ForEach(Array(labels.enumerated()), id: \.offset) { idx, label in
                let width = idx < widths.count ? widths[idx] : nil
                Text(label).font(.caption).foregroundStyle(.secondary)
                    .frame(width: width, alignment: .leading)
                if width == nil { Spacer(minLength: 0) }
            }
        }
        .padding(.horizontal, 16).padding(.vertical, 8)
        .background(Color.secondary.opacity(0.06))
    }

    private func wifiField(_ label: String, _ value: String?) -> some View {
        Group {
            if let value {
                HStack(spacing: 4) {
                    Text("\(label):").font(.system(size: 12, weight: .semibold))
                    HighlightedText(text: value, query: committedFindText).font(.system(size: 12, design: .monospaced))
                }
            }
        }
    }
}

/// Trims a `Double` down to Python-style percentage formatting (`0.0`,
/// `1.02`, `35` stays `35`) for display, matching `NetworkReportParser`'s
/// own internal formatting so numbers on screen read the same as the
/// original Markdown report.
private func trimmed(_ v: Double) -> String {
    if v == v.rounded() { return String(format: "%.1f", v) }
    var s = String(v)
    while s.hasSuffix("0") { s.removeLast() }
    if s.hasSuffix(".") { s += "0" }
    return s
}

// MARK: - Row views (standalone structs — keeps each row's type concrete for ForEach)

private struct FindingRow: View {
    let finding: NetworkFinding
    let isLast: Bool
    @Environment(\.findQuery) private var findQuery

    var body: some View {
        VStack(spacing: 0) {
            HStack(alignment: .top, spacing: 8) {
                Text(finding.severity.icon)
                Badge(text: finding.severity.rawValue, color: color(for: finding.severity))
                Text(finding.category).font(.system(size: 11, weight: .semibold)).foregroundStyle(.secondary)
                HighlightedText(text: finding.message, query: findQuery).font(.system(size: 12))
                Spacer(minLength: 0)
            }
            .padding(.horizontal, 16).padding(.vertical, 7)
            if !isLast { Divider().padding(.leading, 16) }
        }
    }

    private func color(for severity: FindingSeverity) -> Color {
        switch severity {
        case .fail: return .red
        case .warn: return .orange
        case .ok: return .green
        case .info: return .secondary
        }
    }
}

private struct InterfaceRow: View {
    let entry: NetworkInterfaceEntry
    let isLast: Bool
    @Environment(\.findQuery) private var findQuery

    var body: some View {
        VStack(spacing: 0) {
            HStack {
                HighlightedText(text: entry.name, query: findQuery).font(.system(size: 12, design: .monospaced)).frame(width: 90, alignment: .leading)
                Text(entry.type ?? "-").font(.caption).frame(width: 70, alignment: .leading)
                Text(entry.status ?? "-").font(.caption).frame(width: 70, alignment: .leading)
                Text(entry.media ?? "-").font(.caption).frame(width: 110, alignment: .leading)
                Text(linkQuality).font(.caption).frame(width: 110, alignment: .leading)
                Text(entry.ipv4.joined(separator: ", ")).font(.system(size: 11, design: .monospaced)).foregroundStyle(.secondary)
                Spacer(minLength: 0)
            }
            .padding(.horizontal, 16).padding(.vertical, 6)
            if !isLast { Divider().padding(.leading, 16) }
        }
    }

    private var linkQuality: String {
        guard let score = entry.linkQualityScore else { return "-" }
        return "\(score) (\(entry.linkQualityLabel ?? ""))"
    }
}

private struct CounterRow: View {
    let entry: InterfaceCounterEntry
    let isLast: Bool

    var body: some View {
        VStack(spacing: 0) {
            HStack {
                Text(entry.name).font(.system(size: 12, design: .monospaced)).frame(width: 80, alignment: .leading)
                Text("\(entry.inPackets)").font(.caption).frame(width: 80, alignment: .leading)
                rateText(entry.inErrors, entry.inErrorPct).frame(width: 90, alignment: .leading)
                Text("\(entry.outPackets)").font(.caption).frame(width: 80, alignment: .leading)
                rateText(entry.outErrors, entry.outErrorPct).frame(width: 90, alignment: .leading)
                Text("\(entry.collisions)").font(.caption).frame(width: 50, alignment: .leading)
                rateText(entry.drops, entry.dropPct).frame(width: 90, alignment: .leading)
                Spacer(minLength: 0)
            }
            .padding(.horizontal, 16).padding(.vertical, 6)
            if !isLast { Divider().padding(.leading, 16) }
        }
    }

    private func rateText(_ count: Int, _ pct: Double) -> some View {
        Text("\(count) (\(trimmed(pct))%)")
            .font(.caption)
            .foregroundStyle(color(for: pct))
    }

    private func color(for pct: Double) -> Color {
        switch NetworkReportParser.classifyRate(pct) {
        case .fail: return .red
        case .warn: return .orange
        default: return .secondary
        }
    }
}

private struct RouteRow: View {
    let entry: RouteEntry
    let isLast: Bool
    @Environment(\.findQuery) private var findQuery

    var body: some View {
        VStack(spacing: 0) {
            HStack {
                HighlightedText(text: entry.query, query: findQuery).font(.system(size: 12, design: .monospaced)).frame(width: 180, alignment: .leading)
                HighlightedText(text: entry.gateway, query: findQuery).font(.system(size: 12, design: .monospaced))
                Spacer(minLength: 0)
                Text(entry.interface).font(.system(size: 12, design: .monospaced)).frame(width: 90, alignment: .leading)
            }
            .padding(.horizontal, 16).padding(.vertical, 6)
            if !isLast { Divider().padding(.leading, 16) }
        }
    }
}

private struct NetworkServiceRow: View {
    let entry: NetworkServiceEntry
    let isLast: Bool

    var body: some View {
        VStack(spacing: 0) {
            HStack(alignment: .top, spacing: 8) {
                VStack(alignment: .leading, spacing: 2) {
                    HStack(spacing: 6) {
                        Text(entry.name).font(.system(size: 12, weight: .semibold))
                        if entry.isVPN { Badge(text: "VPN", color: .purple) }
                    }
                    if let provider = entry.vpnProvider {
                        Text(provider).font(.system(size: 11, design: .monospaced)).foregroundStyle(.secondary)
                    }
                    if let onDemand = entry.vpnOnDemand {
                        Text(onDemand ? "On-Demand enabled" : "On-Demand disabled")
                            .font(.caption2).foregroundStyle(.secondary)
                    }
                }
                Spacer(minLength: 0)
                if !entry.proxyEnabledKeys.isEmpty {
                    Text(entry.proxyEnabledKeys.joined(separator: ", "))
                        .font(.caption).foregroundStyle(.orange)
                }
            }
            .padding(.horizontal, 16).padding(.vertical, 8)
            if !isLast { Divider().padding(.leading, 16) }
        }
    }
}

private struct ReachabilityRow: View {
    let entry: ReachabilityCheckEntry
    let isLast: Bool
    @Environment(\.findQuery) private var findQuery

    var body: some View {
        VStack(spacing: 0) {
            HStack {
                HighlightedText(text: entry.target, query: findQuery).font(.system(size: 12, design: .monospaced)).frame(width: 180, alignment: .leading)
                HighlightedText(text: entry.flags, query: findQuery).font(.caption).foregroundStyle(entry.reachable ? Color.secondary : Color.red)
                Spacer(minLength: 0)
            }
            .padding(.horizontal, 16).padding(.vertical, 6)
            if !isLast { Divider().padding(.leading, 16) }
        }
    }
}

private struct ConnectivityRow: View {
    let entry: ConnectivityTestEntry
    let isLast: Bool
    @Environment(\.findQuery) private var findQuery

    var body: some View {
        VStack(spacing: 0) {
            HStack(alignment: .top) {
                HighlightedText(text: entry.name, query: findQuery).font(.caption).frame(width: 110, alignment: .leading)
                Text(entry.passed ? "✅ Yes" : "❌ No").font(.caption).frame(width: 70, alignment: .leading)
                Text(entry.durationSeconds).font(.system(size: 11, design: .monospaced)).frame(width: 90, alignment: .leading)
                HighlightedText(text: entry.detail, query: findQuery).font(.system(size: 11, design: .monospaced)).foregroundStyle(.secondary)
                Spacer(minLength: 0)
            }
            .padding(.horizontal, 16).padding(.vertical, 6)
            if !isLast { Divider().padding(.leading, 16) }
        }
    }
}

private struct WiFiEnvironmentCheckRow: View {
    let entry: WiFiEnvironmentCheckEntry
    @Environment(\.findQuery) private var findQuery

    var body: some View {
        VStack(alignment: .leading, spacing: 1) {
            HStack(spacing: 4) {
                Text(entry.flagged ? "🟡" : "🟢")
                HighlightedText(text: entry.name, query: findQuery).font(.system(size: 12, weight: .medium))
            }
            HighlightedText(text: entry.detail, query: findQuery)
                .font(.system(size: 11, design: .monospaced))
                .foregroundStyle(.secondary)
        }
    }
}

private struct WiFiHistoryRow: View {
    let event: WiFiHistoryEvent
    let isLast: Bool
    @Environment(\.findQuery) private var findQuery

    private static let formatter: DateFormatter = {
        let f = DateFormatter()
        f.dateFormat = "MMM d, yyyy h:mm:ss a"
        return f
    }()

    private var whenText: String {
        guard let ts = event.timestamp else { return "-" }
        return Self.formatter.string(from: ts)
    }

    var body: some View {
        VStack(spacing: 0) {
            HStack(alignment: .top) {
                Text(whenText).font(.system(size: 11, design: .monospaced)).frame(width: 160, alignment: .leading)
                HighlightedText(text: event.category, query: findQuery)
                    .font(.system(size: 12, weight: .medium))
                    .frame(width: 190, alignment: .leading)
                HighlightedText(text: event.detail.isEmpty ? "-" : event.detail, query: findQuery)
                    .font(.system(size: 11, design: .monospaced))
                    .foregroundStyle(.secondary)
                Spacer(minLength: 0)
            }
            .padding(.horizontal, 16).padding(.vertical, 6)
            .help(event.logged ? "Logged" : "Not logged (e.g. the capture's own trigger event, not a real Wi-Fi event)")
            if !isLast { Divider().padding(.leading, 16) }
        }
    }
}

private struct PingLossRow: View {
    let entry: PingLossEntry
    let isLast: Bool

    var body: some View {
        VStack(spacing: 0) {
            HStack {
                Text(entry.target).font(.system(size: 12, design: .monospaced)).frame(width: 180, alignment: .leading)
                Text("\(trimmed(entry.lossPct))%")
                    .font(.caption)
                    .foregroundStyle(color)
                Spacer(minLength: 0)
            }
            .padding(.horizontal, 16).padding(.vertical, 6)
            if !isLast { Divider().padding(.leading, 16) }
        }
    }

    private var color: Color {
        switch NetworkReportParser.classifyRate(entry.lossPct) {
        case .fail: return .red
        case .warn: return .orange
        default: return .secondary
        }
    }
}
