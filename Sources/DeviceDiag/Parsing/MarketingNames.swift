import Foundation

enum MarketingNames {
    /// macOS major (or "major.minor" for 10.x) → marketing name.
    static let macOSNames: [String: String] = [
        "10.9": "Mavericks",
        "10.10": "Yosemite",
        "10.11": "El Capitan",
        "10.12": "Sierra",
        "10.13": "High Sierra",
        "10.14": "Mojave",
        "10.15": "Catalina",
        "11": "Big Sur",
        "12": "Monterey",
        "13": "Ventura",
        "14": "Sonoma",
        "15": "Sequoia",
        "26": "Tahoe",
    ]

    /// Returns "macOS <Name>" for a ProductVersion string, or "" if unknown.
    static func macOSMarketingName(_ productVersion: String) -> String {
        let parts = productVersion.split(separator: ".").map(String.init)
        var key = ""
        if parts.first == "10", parts.count >= 2 {
            key = "10.\(parts[1])"
        } else {
            key = parts.first ?? ""
        }
        guard let name = macOSNames[key] else { return "" }
        return "macOS \(name)"
    }

    /// Returns the iOS/iPadOS marketing name given a ProductVersion + DeviceClass.
    static func iosMarketingName(_ productVersion: String, deviceClass: String) -> String {
        let isIPad = deviceClass.lowercased() == "ipad"
        let isIPhone = !deviceClass.isEmpty && !isIPad
        if isIPad { return "iPadOS \(productVersion)" }
        if isIPhone { return "iOS \(productVersion)" }
        let major = productVersion.split(separator: ".").first.map(String.init) ?? ""
        if Int(major) != nil {
            return "iOS \(productVersion) / iPadOS \(productVersion)"
        }
        return "iOS/iPadOS \(productVersion)"
    }
}
