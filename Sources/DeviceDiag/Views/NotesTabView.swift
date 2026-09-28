import SwiftUI

struct NotesTabView: View {
    let notes: [String]

    @State private var findText = ""
    @State private var committedFindText = ""
    @State private var showFindBar = false
    @FocusState private var findFieldFocused: Bool

    private var filteredNotes: [String] {
        committedFindText.isEmpty ? notes : notes.filter { $0.localizedCaseInsensitiveContains(committedFindText) }
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 16) {
            if showFindBar {
                FindBarView(placeholder: "Find in notes", text: $findText,
                            matchCount: committedFindText.isEmpty ? nil : filteredNotes.count,
                            isFocused: $findFieldFocused) {
                    showFindBar = false
                    findText = ""
                }
            }
            CardView(title: "⚠️ Processing Notes") {
                if filteredNotes.isEmpty {
                    EmptyStateView(text: "No notes match \"\(committedFindText)\".")
                } else {
                    VStack(alignment: .leading, spacing: 8) {
                        ForEach(filteredNotes, id: \.self) { note in
                            HStack(alignment: .top, spacing: 6) {
                                Text("•").foregroundStyle(.secondary)
                                HighlightedText(text: note, query: committedFindText)
                                    .font(.caption).foregroundStyle(.secondary)
                            }
                        }
                    }
                    .padding(16)
                }
            }
        }
        .background(FindShortcut { showFindBar = true; findFieldFocused = true })
        .task(id: findText) {
            try? await Task.sleep(nanoseconds: 150_000_000)
            if !Task.isCancelled { committedFindText = findText }
        }
    }
}
