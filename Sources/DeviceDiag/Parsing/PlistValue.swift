import Foundation

/// A dynamically-typed plist tree, mirroring the way Python's `plistlib` /
/// the pure-Python ASCII plist parser hand back loosely-typed dict/list/str/int
/// structures. Every parser in this app (ASCII "NeXTSTEP" plists via
/// `AsciiPlistParser`, and binary/XML plists via `PropertyListSerialization`)
/// normalizes into this single type so downstream code can share helpers.
indirect enum PlistValue {
    case string(String)
    case int(Int)
    case bool(Bool)
    case double(Double)
    case date(Date)
    case data(Data)
    case dict([String: PlistValue])
    case array([PlistValue])
    case null

    var asDict: [String: PlistValue]? {
        if case .dict(let d) = self { return d }
        return nil
    }

    var asArray: [PlistValue]? {
        if case .array(let a) = self { return a }
        return nil
    }

    var asString: String? {
        switch self {
        case .string(let s): return s
        case .int(let i): return String(i)
        case .bool(let b): return b ? "1" : "0"
        case .double(let d): return String(d)
        default: return nil
        }
    }

    /// Best-effort string rendering, used anywhere Python code does `str(val)`.
    var stringified: String {
        switch self {
        case .string(let s): return s
        case .int(let i): return String(i)
        case .bool(let b): return b ? "true" : "false"
        case .double(let d): return String(d)
        case .date(let d): return ISO8601DateFormatter().string(from: d)
        case .data: return "<data>"
        case .dict: return "{...}"
        case .array: return "(...)"
        case .null: return ""
        }
    }

    var asInt: Int? {
        switch self {
        case .int(let i): return i
        case .bool(let b): return b ? 1 : 0
        case .string(let s): return Int(s)
        default: return nil
        }
    }

    var asBool: Bool? {
        switch self {
        case .bool(let b): return b
        case .int(let i): return i != 0
        case .string(let s): return s == "1" || s.lowercased() == "true"
        default: return nil
        }
    }

    /// Mirrors Python's `_norm_active`: treats 1 / true / "1" as active.
    var isTruthyActive: Bool {
        switch self {
        case .int(let i): return i == 1
        case .bool(let b): return b == true
        case .string(let s): return s == "1"
        default: return false
        }
    }

    /// A looser truthy check than `isTruthyActive` — trims whitespace and
    /// accepts "true"/"yes" in addition to "1", in case a value comes through
    /// with incidental formatting differences (whitespace, case) that a strict
    /// equality check would miss.
    var isLenientlyTruthy: Bool {
        switch self {
        case .int(let i): return i == 1
        case .bool(let b): return b == true
        case .string(let s):
            let t = s.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
            return t == "1" || t == "true" || t == "yes"
        default: return false
        }
    }

    /// Human-readable dump of the case + raw value, used only for on-screen
    /// debugging when a parsed value doesn't match expectations.
    var debugDescription: String {
        switch self {
        case .string(let s): return "string(\"\(s)\")"
        case .int(let i): return "int(\(i))"
        case .bool(let b): return "bool(\(b))"
        case .double(let d): return "double(\(d))"
        case .date(let d): return "date(\(d))"
        case .data(let d): return "data(\(d.count) bytes)"
        case .dict(let d): return "dict(\(d.count) keys)"
        case .array(let a): return "array(\(a.count) items)"
        case .null: return "null"
        }
    }

    subscript(key: String) -> PlistValue? {
        asDict?[key]
    }

    var isEmpty: Bool {
        switch self {
        case .null: return true
        case .string(let s): return s.isEmpty
        case .dict(let d): return d.isEmpty
        case .array(let a): return a.isEmpty
        default: return false
        }
    }
}

extension PlistValue {
    /// Converts the loosely-typed output of `PropertyListSerialization` (Any)
    /// into a `PlistValue` tree.
    static func from(any value: Any) -> PlistValue {
        if let dict = value as? [String: Any] {
            var out: [String: PlistValue] = [:]
            for (k, v) in dict { out[k] = .from(any: v) }
            return .dict(out)
        }
        if let arr = value as? [Any] {
            return .array(arr.map { .from(any: $0) })
        }
        if let s = value as? String { return .string(s) }
        if let b = value as? Bool { return .bool(b) }
        if let n = value as? NSNumber {
            // NSNumber can box bools too; CFBoolean check via objCType
            if CFGetTypeID(n) == CFBooleanGetTypeID() {
                return .bool(n.boolValue)
            }
            if let intVal = n as? Int { return .int(intVal) }
            return .double(n.doubleValue)
        }
        if let d = value as? Date { return .date(d) }
        if let data = value as? Data { return .data(data) }
        return .null
    }
}
