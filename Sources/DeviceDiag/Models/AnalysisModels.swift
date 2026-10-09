import Foundation

// MARK: - Device Info (macOS)

struct DeviceInfo {
    var serialNumber = "Not found"
    var osVersion = "Not found"
    var buildNumber = "Not found"
    var modelName = "Not found"
    var modelIdentifier = "Not found"
    var hostname = "Not found"
}

// MARK: - Managed Settings (macOS, from config profile payloads)

struct ManagedSettings {
    var managedNotifications: [String] = []
    var pppcIdentifiers: [String] = []
    var managedLoginItems: [String] = []

    var isEmpty: Bool {
        managedNotifications.isEmpty && pppcIdentifiers.isEmpty && managedLoginItems.isEmpty
    }
}

// MARK: - FileVault (macOS, from /usr/bin/psm's status/list/stderr output)

/// One password-slot whose combined (console + other) failed-unlock-attempt
/// count has crossed the "worth flagging" threshold — see
/// `FileVaultParser.nearLockoutThreshold`.
struct FileVaultUnlockAttempt: Identifiable {
    let id = UUID()
    var label: String
    var failedAttempts: Int
    var maxAttempts: Int
}

struct FileVaultResult {
    var found = false
    var error: String?
    var enabled = false

    /// Local (OD-record) usernames with their own enrolled unlock slot.
    var enrolledUsers: [String] = []
    /// Admin usernames (from `psm list`) that do NOT have an enrolled
    /// unlock slot — they can't unlock the disk at boot.
    var adminUsersNotEnrolled: [String] = []

    var hasPersonalRecoveryKey = false
    var hasInstitutionalRecoveryKey = false
    var hasBootstrapToken = false

    /// Whether other already-parsed data (config profiles / DDM
    /// declarations) shows this Mac is MDM-managed — an unmanaged Mac never
    /// has a bootstrap token, so that's only worth flagging when this is true.
    var isMDMManaged = false

    var nearLockoutSlots: [FileVaultUnlockAttempt] = []

    var missingBootstrapToken: Bool { isMDMManaged && !hasBootstrapToken }
    var hasNoRecoveryMechanism: Bool {
        !hasPersonalRecoveryKey && !hasInstitutionalRecoveryKey && !hasBootstrapToken
    }
}

// MARK: - Configuration Profiles (shared shape for macOS + iOS)

struct ConfigProfilePayload: Identifiable {
    let id = UUID()
    var displayName: String
    var domain: String
    var payloadData: String
}

struct ConfigProfileEntry: Identifiable {
    let id = UUID()
    var name: String
    var org: String = ""
    var source: String = ""
    var installDate: String = ""
    var removalDisallowed: Bool = false
    var verified: Bool = false
    var identifier: String = ""
    var uuid: String = ""
    var description: String = ""
    /// macOS only: "Device" or "User", when `system_profiler` reports profiles
    /// grouped by scope (roughly macOS Ventura onward). Empty for mobile
    /// profiles, and for macOS SPX output that isn't grouped at all.
    var scope: String = ""
    var payloads: [ConfigProfilePayload] = []
}

struct ConfigProfilesResult {
    var found = false
    var error: String?
    var profiles: [ConfigProfileEntry] = []
}

// MARK: - MDM Declarations

struct DeclarationStatusGroup: Identifiable {
    let id = UUID()
    var ok: Bool
    var count: Int
    var active: Int
    var valid: String
    var reasons: [String]
}

struct BlueprintDeclaration: Identifiable {
    let id = UUID()
    var uuid: String
    var actType: String
    var cfgType: String
    var activationGroups: [DeclarationStatusGroup]
    var configGroups: [DeclarationStatusGroup]
}

struct StandaloneDeclaration: Identifiable {
    let id = UUID()
    var section: String // "activation" | "configuration" | "management"
    var identifier: String
    var declarationType: String
    var loadState: String
    var active: Int
}

struct StatusItem: Identifiable {
    let id = UUID()
    var keyPath: String
    var needsSync: Bool
    var lastReceivedDate: String
    var lastValue: String = ""
    /// Raw parsed value behind `needsSync`, kept for on-screen debugging
    /// (visible as a tooltip on the sync indicator).
    var rawNeedsSyncDebug: String = ""
}

struct ConduitInfo {
    var lastReceived: String = ""
    var lastProcessed: String = ""
    var consecutiveErrors: Int = 0
}

struct DeclarationsResult {
    var found = false
    var error: String?
    var blueprints: [BlueprintDeclaration] = []
    var standalone: [StandaloneDeclaration] = []
    var conduit = ConduitInfo()
    var statusItems: [StatusItem] = []
}

// MARK: - Mobile (iOS / iPadOS)

struct MobileDeviceInfo {
    var serialNumber = "Not found"
    var udid = "Not found"
    var modelIdentifier = "Not found"
    var modelNumber = "Not found"
    var deviceClass = ""
    var osVersion = "Not found"
    var buildNumber = "Not found"
    var osFamily = "Not found"
    var marketingName = "Not found"
    var isSupervised: Bool?
    var isRTS: Bool?
}

struct MobileEnrollmentInfo {
    var mdmProfileID = ""
    var serverURL = ""
    var isADE: Bool?
    var topic = ""
}

struct ManagedApp: Identifiable {
    let id = UUID()
    var bundleID: String
    var stateRaw: Int
    var state: String
    var flags: String
    var removable: Bool
}

// MARK: - Settings Attribution (iOS only)

struct SettingsAttributionEntry: Identifiable {
    let id = UUID()
    var key: String
    var value: String
    var source: String // "profile" | "declaration" | "default"
    var profileName: String?
    var implicit: Bool = false
    var timestamp: String?
}

struct SettingsAttributionResult {
    var found = false
    var error: String?
    var total = 0
    var profileCount = 0
    var declarationCount = 0
    var defaultCount = 0
    var entries: [SettingsAttributionEntry] = []
}

// MARK: - Network Report (port of sysdiag_netcheck.py)

/// One `ifconfig` interface block.
struct NetworkInterfaceEntry: Identifiable {
    let id = UUID()
    var name: String
    var up: Bool
    var running: Bool
    var status: String?
    var media: String?
    var type: String?
    var linkQualityScore: Int?
    var linkQualityLabel: String?
    var uplinkRate: String?
    var ipv4: [String] = []
    var ipv6: [String] = []

    /// Matches the Python report's "active" filter: has status "active" and
    /// at least one address. Interfaces that fail this (loopback, disabled
    /// tunnels, etc.) are parsed but not shown in the Interfaces table.
    var isActive: Bool { status == "active" && (!ipv4.isEmpty || !ipv6.isEmpty) }
}

/// One row of `netstat -i`'s per-interface `<Link#N>` counters, with the
/// error/drop rates pre-computed as a % of that interface's lifetime
/// packet count (see `NetworkReportParser.classifyRate`).
struct InterfaceCounterEntry: Identifiable {
    let id = UUID()
    var name: String
    var inPackets: Int
    var inErrors: Int
    var outPackets: Int
    var outErrors: Int
    var collisions: Int
    var drops: Int
    var inErrorPct: Double
    var outErrorPct: Double
    var dropPct: Double
}

/// Key counters pulled out of `netstat -s`'s `tcp:`/`routing:` blocks.
struct TCPStackStats {
    var packetsSent: Int?
    var dataRetransmitted: Int?
    var retransmitTimeouts: Int?
    var connsDroppedRexmit: Int?
    var connsEstablished: Int?
    var connsClosed: Int?
    var connsClosedDrops: Int?
    var embryonicDropped: Int?
    var badConnAttempts: Int?
    var dupAcks: Int?
    var outOfOrder: Int?
    var droppedLowMemory: Int?
    var destinationsUnreachable: Int?
    var retransmitRatePct: Double?
}

struct RouteEntry: Identifiable {
    let id = UUID()
    var query: String
    var gateway: String
    var interface: String
}

/// One `scutil --dns` resolver block.
struct DNSResolverEntry: Identifiable {
    let id = UUID()
    var domain: String?
    var searchDomains: [String] = []
    var nameservers: [String] = []
    var reachableString: String?
    var isReachable: Bool
    var mdns: Bool
    var order: Int?
}

struct ReachabilityCheckEntry: Identifiable {
    let id = UUID()
    var target: String
    var flags: String
    var reachable: Bool
}

/// Flattened `wifi_status.txt` fields, plus the SNR this report computes
/// from RSSI/Noise (not present verbatim in the source file).
struct WiFiStatusInfo {
    var interfaceName: String?
    var ssid: String?
    var rssi: String?
    var noise: String?
    var txRate: String?
    var phyMode: String?
    var channel: String?
    var security: String?
    var snr: Int?
    var nearbyNetworkCount: Int?
    /// Environment/conflict checks worth surfacing from
    /// `WiFi/diagnostics-environment.txt` — see `WiFiEnvironmentCheckEntry`.
    var environmentChecks: [WiFiEnvironmentCheckEntry] = []

    var isEmpty: Bool { interfaceName == nil && ssid == nil && rssi == nil }
}

/// One row from `WiFi/diagnostics-environment.txt`'s check table (Congested
/// Wi-Fi Channel, Conflicting Wi-Fi CC, Hidden Wi-Fi Scan Results, and the
/// various "Conflicting ..." PHY/security checks). `flagged` is that row's
/// `Result` column (`Yes`/`No`) — each of these checks is phrased as
/// "was this undesirable condition detected", so `Yes` always means
/// something worth a look, not a pass/fail in the usual sense.
struct WiFiEnvironmentCheckEntry: Identifiable {
    let id = UUID()
    var name: String
    var flagged: Bool
    var timestamp: String
    var detail: String
}

/// One row of the sysdiagnose-collected active connectivity probe table
/// (ping / DNS resolve / curl, run automatically as part of every
/// sysdiagnose capture).
struct ConnectivityTestEntry: Identifiable {
    let id = UUID()
    var name: String
    var passed: Bool
    var durationSeconds: String
    var timestamp: String
    var detail: String
}

struct PingLossEntry: Identifiable {
    let id = UUID()
    var target: String
    var lossPct: Double
}

/// One entry from SystemConfiguration's `preferences.plist` `NetworkServices`
/// dict — the same file `scutil` itself reads on macOS, and (unlike
/// `scutil --proxy`/`--dns`/`-r`, none of which exist as binaries on iOS)
/// present in the same `Sets`/`CurrentSet`/`NetworkServices` shape on both
/// platforms, which is what makes this section possible on iOS at all. Only
/// VPN services and services with at least one proxy type actually enabled
/// are surfaced — every service also carries an inert `Proxies` dict with
/// bypass-list/FTP-passive housekeeping keys that would just be noise if
/// shown for every plain Wi-Fi/Ethernet/Cellular service.
struct NetworkServiceEntry: Identifiable {
    let id = UUID()
    var name: String
    var interfaceType: String
    var isVPN: Bool
    var vpnProvider: String?
    var vpnOnDemand: Bool?
    var proxyEnabledKeys: [String] = []
}

enum FindingSeverity: String {
    case fail = "FAIL", warn = "WARN", ok = "OK", info = "INFO"

    /// Sort order for the findings summary — worst first, same as the
    /// Python report (`Findings.ORDER`).
    var sortRank: Int {
        switch self {
        case .fail: return 0
        case .warn: return 1
        case .ok: return 2
        case .info: return 3
        }
    }

    var icon: String {
        switch self {
        case .fail: return "🔴"
        case .warn: return "🟡"
        case .ok: return "🟢"
        case .info: return "ℹ️"
        }
    }
}

struct NetworkFinding: Identifiable {
    let id = UUID()
    var severity: FindingSeverity
    var category: String
    var message: String
}

struct NetworkReportResult {
    var found = false
    var error: String?
    var hostname: String = "unknown"

    var interfaces: [NetworkInterfaceEntry] = []
    var interfaceCounters: [InterfaceCounterEntry] = []
    var tcpStats = TCPStackStats()
    var routes: [RouteEntry] = []
    var interfaceAdvisory: String?
    var interfaceRankAssertion: String?
    var resolvers: [DNSResolverEntry] = []
    var proxyEnabledKeys: [String] = []
    var reachability: [ReachabilityCheckEntry] = []
    var wifi = WiFiStatusInfo()
    var connectivityTests: [ConnectivityTestEntry] = []
    var pingLosses: [PingLossEntry] = []
    var networkServices: [NetworkServiceEntry] = []
    var findings: [NetworkFinding] = []
}

// MARK: - Historical Wi-Fi Events (decoded from CoreCapture's History.txt)

/// One decoded line from `StateSnapshots/History.txt` inside a WiFiDebug
/// CoreCapture bundle — the raw line looks like
/// `[4]641976.404372\t Net Deauthentication~WCLDeauthDisassoc is_deauth = 1 Reason code=3 - Logged: Yes`.
/// The leading number is seconds-since-boot on a monotonic clock, not a
/// wall-clock time, so `timestamp` is computed by `WiFiHistoryParser` by
/// anchoring it against the bundle's own capture time (see that file for
/// how). `category`/`detail` are the two halves of the description on
/// either side of the `~`.
struct WiFiHistoryEvent: Identifiable, Hashable {
    let id = UUID()
    var timestamp: Date?
    var uptimeSeconds: Double
    var category: String
    var detail: String
    var logged: Bool
    /// Which CoreCapture bundle this came from (there can be more than one
    /// in a single sysdiagnose) — shown as a tooltip, not a column, since
    /// most sysdiagnoses only ever have one.
    var sourceBundle: String
}

struct WiFiHistoryResult {
    var found = false
    var error: String?
    var events: [WiFiHistoryEvent] = []
    /// How many CoreCapture bundles were found and decoded (usually 1).
    var bundleCount = 0
}

// MARK: - File inventory

struct SysdiagFileEntry: Identifiable {
    let id = UUID()
    var name: String
    var description: String
    var path: String?
    var found: Bool
    /// Populated only for "collection" entries that match more than one
    /// underlying file (e.g. launchd's per-UID dumps) — the additional file
    /// paths beyond `path`. Opening this entry reveals all of them selected
    /// together in Finder instead of opening `path` alone.
    var groupedPaths: [String] = []
    /// True when `path` itself is a directory (e.g. the Networking group's
    /// `network-info`/`WiFi` entries, which open straight to that folder in
    /// Finder) — shown with the same folder icon as a grouped collection.
    var isDirectory: Bool = false
}

struct SysdiagFileGroup: Identifiable {
    let id = UUID()
    var group: String
    var files: [SysdiagFileEntry]
}

// MARK: - Troubleshooting / log queries

/// Whether a catalog topic's `log show` predicate works as-is on both
/// platforms, doesn't apply to iOS/iPadOS at all (a macOS-only concept —
/// Gatekeeper, XProtect, LaunchDaemons, a Jamf product with no iOS agent,
/// etc.), or needs a different predicate string on iOS because the
/// process/subsystem names genuinely differ (e.g. macOS's `mdmclient`/
/// `com.apple.ManagedClient` vs. iOS's `mdmd`/`com.apple.ManagedConfiguration`).
enum LogTopicPlatform {
    case both
    case macOSOnly
    case differs(ios: String)
}

struct LogTopicDefinition {
    var extraArgs: [String]
    var predicate: String
    var platform: LogTopicPlatform = .both

    /// The predicate to actually use for this platform, or `nil` if this
    /// topic doesn't apply at all — a macOS-only topic on an iOS
    /// sysdiagnose — and should be left out of that platform's picker
    /// entirely rather than shown with a predicate that can't match anything.
    func resolvedPredicate(isMobile: Bool) -> String? {
        switch platform {
        case .both:
            return predicate
        case .macOSOnly:
            return isMobile ? nil : predicate
        case .differs(let iosPredicate):
            return isMobile ? iosPredicate : predicate
        }
    }
}

struct LogEntry: Identifiable {
    let id = UUID()
    var timestamp: String
    var process: String
    var subsystem: String
    var message: String
    var level: String
}

// MARK: - Top-level analysis result

struct AnalysisResult {
    var name: String
    var analyzedAt: String
    var isMobile: Bool

    // macOS
    var deviceInfo = DeviceInfo()
    var managedSettings = ManagedSettings()
    var fileVault = FileVaultResult()

    // Mobile
    var mobileDeviceInfo = MobileDeviceInfo()
    var mobileEnrollment = MobileEnrollmentInfo()
    var mobileManagedApps: [ManagedApp] = []
    var settingsAttribution = SettingsAttributionResult()

    // Shared
    var sysdiagFiles: [SysdiagFileGroup] = []
    var declarations = DeclarationsResult()
    var configProfiles = ConfigProfilesResult()
    var networkReport = NetworkReportResult()
    var wifiHistory = WiFiHistoryResult()
    var logArchivePath: String?
    var notes: [String] = []

    var rootURL: URL?
    /// Temp directories created while extracting this analysis; removed when the
    /// next analysis starts or the app quits (mirrors `_last_tmp_dirs`).
    var tempDirectories: [URL] = []
}
