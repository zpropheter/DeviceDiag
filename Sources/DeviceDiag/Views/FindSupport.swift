import Foundation
import SwiftUI

// MARK: - Shared "find in page" support
//
// Every results tab wires up Cmd+F the same way: a hidden keyboard-shortcut
// button toggles a find bar, which filters/highlights that tab's content.
// The active (debounced) query is broadcast down via
// `.environment(\.findQuery, ...)` so nested row views (InfoRow, table rows,
// etc.) can highlight matches without every call site threading a query
// string through by hand.

private struct FindQueryKey: EnvironmentKey {
    static let defaultValue: String = ""
}

extension EnvironmentValues {
    /// The currently-active (debounced) Cmd+F query for whichever tab is on
    /// screen. Empty when no search is active.
    var findQuery: String {
        get { self[FindQueryKey.self] }
        set { self[FindQueryKey.self] = newValue }
    }
}

/// Renders `text`, highlighting every case-insensitive occurrence of `query`
/// with a yellow background — the standard "find in page" treatment. Falls
/// back to a plain `Text` when there's no active query, so pages pay no
/// AttributedString overhead until someone actually searches. Behaves like a
/// drop-in replacement for `Text(text)`: apply `.font()`, `.foregroundStyle()`,
/// `.textSelection()`, etc. on it exactly as you would on a plain `Text`.
struct HighlightedText: View {
    let text: String
    var query: String

    var body: some View {
        let trimmed = query.trimmingCharacters(in: .whitespacesAndNewlines)
        if trimmed.isEmpty {
            Text(text)
        } else {
            Text(Self.highlight(text, query: trimmed))
        }
    }

    private static func highlight(_ text: String, query: String) -> AttributedString {
        var result = AttributedString()
        var searchStart = text.startIndex
        while searchStart < text.endIndex,
              let match = text.range(of: query, options: .caseInsensitive, range: searchStart..<text.endIndex) {
            if match.lowerBound > searchStart {
                result.append(AttributedString(String(text[searchStart..<match.lowerBound])))
            }
            var highlighted = AttributedString(String(text[match]))
            highlighted.backgroundColor = Color.yellow.opacity(0.55)
            highlighted.foregroundColor = Color.black
            result.append(highlighted)
            searchStart = match.upperBound
        }
        if searchStart < text.endIndex {
            result.append(AttributedString(String(text[searchStart..<text.endIndex])))
        }
        return result
    }
}

/// True if any of `fields` contains `query` (case-insensitive). Keeps
/// per-tab filter predicates one-liners; an empty query always matches.
func matchesAny(_ fields: [String], query: String) -> Bool {
    guard !query.isEmpty else { return true }
    return fields.contains { !$0.isEmpty && $0.localizedCaseInsensitiveContains(query) }
}

/// The reusable Cmd+F find bar UI shown at the top of a tab.
///
/// Most tabs filter their content down to matches, where "N matches" is all
/// that's needed. A few (the file viewer) instead jump between matches in
/// place — passing `currentMatchIndex` and `onNext`/`onPrevious` switches the
/// counter to "M of N" and shows prev/next chevrons; leave them nil for the
/// filtering behavior.
struct FindBarView: View {
    var placeholder: String = "Find in this tab"
    @Binding var text: String
    var matchCount: Int?
    var currentMatchIndex: Int?
    @FocusState.Binding var isFocused: Bool
    var onNext: (() -> Void)?
    var onPrevious: (() -> Void)?
    var onClose: () -> Void

    var body: some View {
        HStack(spacing: 8) {
            Image(systemName: "magnifyingglass").foregroundStyle(.secondary)
            TextField(placeholder, text: $text)
                .textFieldStyle(.plain)
                .focused($isFocused)
                .onSubmit { onNext?() }
            if let matchCount, !text.isEmpty {
                if let currentMatchIndex, matchCount > 0 {
                    Text("\(currentMatchIndex) of \(matchCount)")
                        .font(.caption2)
                        .foregroundStyle(.secondary)
                } else {
                    Text("\(matchCount) match\(matchCount == 1 ? "" : "es")")
                        .font(.caption2)
                        .foregroundStyle(.secondary)
                }
            }
            if let onPrevious {
                Button(action: onPrevious) {
                    Image(systemName: "chevron.up")
                }
                .buttonStyle(.plain)
                .disabled(matchCount == 0 || matchCount == nil)
            }
            if let onNext {
                Button(action: onNext) {
                    Image(systemName: "chevron.down")
                }
                .buttonStyle(.plain)
                .disabled(matchCount == 0 || matchCount == nil)
            }
            Button {
                onClose()
            } label: {
                Image(systemName: "xmark.circle.fill").foregroundStyle(.secondary)
            }
            .buttonStyle(.plain)
        }
        .padding(.horizontal, 12).padding(.vertical, 8)
        .background(Color.secondary.opacity(0.08))
        .clipShape(RoundedRectangle(cornerRadius: 8))
    }
}

/// The hidden Cmd+F trigger used throughout the app. Attach via
/// `.background(FindShortcut { ... })` on a tab's root view to open that
/// tab's find bar and focus it.
struct FindShortcut: View {
    let action: () -> Void
    var body: some View {
        Button("", action: action)
            .keyboardShortcut("f", modifiers: .command)
            .opacity(0)
    }
}
