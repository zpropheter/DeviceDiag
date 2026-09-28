import Foundation

/// Minimal recursive-descent parser for Apple's ASCII (NeXTSTEP) plist format.
///
/// Faithful port of the Python `_AsciiPlistParser` in the original Flask app.
/// Used for files like `rmd_inspect_system.txt` and for embedded config-profile
/// payload text that isn't a "real" binary/XML plist.
final class AsciiPlistParser {
    private let text: [Character]
    private var pos: Int = 0
    private let n: Int

    init(_ string: String) {
        self.text = Array(string)
        self.n = text.count
    }

    func parse() -> PlistValue {
        skip()
        return value()
    }

    private func skip() {
        while pos < n {
            let c = text[pos]
            if c == " " || c == "\t" || c == "\n" || c == "\r" {
                pos += 1
            } else if pos + 1 < n && c == "/" && text[pos + 1] == "/" {
                while pos < n && text[pos] != "\n" { pos += 1 }
            } else if pos + 1 < n && c == "/" && text[pos + 1] == "*" {
                pos += 2
                while pos < n - 1 && !(text[pos] == "*" && text[pos + 1] == "/") { pos += 1 }
                pos += 2
            } else {
                break
            }
        }
    }

    private func readQuoted() -> String {
        pos += 1 // consume opening "
        var out = ""
        while pos < n && text[pos] != "\"" {
            if text[pos] == "\\" {
                pos += 1
                if pos < n {
                    out.append(text[pos])
                    pos += 1
                }
            } else {
                out.append(text[pos])
                pos += 1
            }
        }
        if pos < n { pos += 1 } // consume closing "
        return out
    }

    private static let wordTerminators: Set<Character> = [" ", "\t", "\n", "\r", "{", "}", "(", ")", "=", ";", ",", "\""]

    /// Reads a bare (unquoted) word. Coerces "1"/"0" to ints, mirroring the Python parser
    /// so truthy checks (`_norm_active`) work the same way.
    private func readWord() -> PlistValue {
        let start = pos
        while pos < n && !Self.wordTerminators.contains(text[pos]) {
            pos += 1
        }
        let w = String(text[start..<pos])
        if w == "1" { return .int(1) }
        if w == "0" { return .int(0) }
        return .string(w)
    }

    private func value() -> PlistValue {
        skip()
        guard pos < n else { return .null }
        let c = text[pos]
        if c == "{" { return dict() }
        if c == "(" { return array() }
        if c == "\"" { return .string(readQuoted()) }
        return readWord()
    }

    private func dict() -> PlistValue {
        pos += 1 // consume {
        var out: [String: PlistValue] = [:]
        while true {
            skip()
            if pos >= n || text[pos] == "}" {
                if pos < n { pos += 1 }
                break
            }
            let keyVal: PlistValue = text[pos] == "\"" ? .string(readQuoted()) : readWord()
            let key = keyVal.asString ?? ""
            skip()
            if pos < n && text[pos] == "=" { pos += 1 }
            let val = value()
            out[key] = val
            skip()
            if pos < n && text[pos] == ";" { pos += 1 }
        }
        return .dict(out)
    }

    private func array() -> PlistValue {
        pos += 1 // consume (
        var out: [PlistValue] = []
        while true {
            skip()
            if pos >= n || text[pos] == ")" {
                if pos < n { pos += 1 }
                break
            }
            let val = value()
            if case .null = val {} else { out.append(val) }
            skip()
            if pos < n && text[pos] == "," { pos += 1 }
        }
        return .array(out)
    }
}
