import AppKit
import SwiftUI
import UniformTypeIdentifiers

/// Equivalent of `index.html` — the drop-a-sysdiagnose landing screen. One
/// instance per open tab, scoped to that tab's own `AnalysisSession` via
/// `sessionID` rather than a single app-wide upload/error state.
struct UploadView: View {
    @EnvironmentObject var appState: AppState
    let sessionID: UUID
    @State private var path: String = ""
    @State private var isTargeted = false

    private var session: AnalysisSession? {
        appState.sessions.first { $0.id == sessionID }
    }

    var body: some View {
        ZStack {
            Color(nsColor: .windowBackgroundColor).ignoresSafeArea()

            VStack(spacing: 24) {
                VStack(spacing: 6) {
                    Text("DeviceDiag")
                        .font(.system(size: 28, weight: .bold))
                    Text("Drop a sysdiagnose archive or folder to get a structured report")
                        .foregroundStyle(.secondary)
                }

                VStack(spacing: 20) {
                    if let error = session?.errorMessage {
                        Text(error)
                            .font(.callout)
                            .foregroundStyle(.red)
                            .padding(12)
                            .frame(maxWidth: .infinity, alignment: .leading)
                            .background(Color.red.opacity(0.08))
                            .clipShape(RoundedRectangle(cornerRadius: 8))
                    }

                    RoundedRectangle(cornerRadius: 10)
                        .strokeBorder(style: StrokeStyle(lineWidth: 2, dash: [6]))
                        .foregroundStyle(isTargeted ? Color.accentColor : .secondary.opacity(0.4))
                        .background((isTargeted ? Color.accentColor.opacity(0.08) : Color.secondary.opacity(0.03)).clipShape(RoundedRectangle(cornerRadius: 10)))
                        .frame(height: 160)
                        .overlay {
                            VStack(spacing: 8) {
                                Text("📦").font(.system(size: 36))
                                Text("Drop a .tar.gz archive or extracted folder")
                                    .font(.headline)
                                Text("or click to choose")
                                    .font(.caption)
                                    .foregroundStyle(.secondary)
                            }
                        }
                        .onTapGesture { chooseFile() }
                        .onDrop(of: [.fileURL], isTargeted: $isTargeted) { providers in
                            handleDrop(providers)
                        }

                    HStack {
                        Rectangle().frame(height: 1).foregroundStyle(.secondary.opacity(0.25))
                        Text("or enter a path directly").font(.caption).foregroundStyle(.secondary)
                        Rectangle().frame(height: 1).foregroundStyle(.secondary.opacity(0.25))
                    }

                    HStack(spacing: 8) {
                        TextField("/path/to/sysdiagnose_2026.01.01_macOS.tar.gz", text: $path)
                            .textFieldStyle(.roundedBorder)
                            .font(.system(.body, design: .monospaced))
                            .onSubmit { analyze() }

                        Button("Analyze") { analyze() }
                            .buttonStyle(.borderedProminent)
                            .disabled(path.trimmingCharacters(in: .whitespaces).isEmpty || (session?.isAnalyzing ?? false))
                    }

                    Text("Accepts .tar.gz archives or already-extracted sysdiagnose folders.")
                        .font(.caption)
                        .foregroundStyle(.secondary)
                        .multilineTextAlignment(.center)
                }
                .padding(28)
                .frame(maxWidth: 560)
                .background(Color(nsColor: .controlBackgroundColor))
                .clipShape(RoundedRectangle(cornerRadius: 14))
                .shadow(color: .black.opacity(0.08), radius: 16, y: 2)
            }
            .padding(32)

            if session?.isAnalyzing ?? false {
                ZStack {
                    Color.black.opacity(0.05)
                    VStack(spacing: 16) {
                        ProgressView()
                            .controlSize(.large)
                        Text("Analyzing sysdiagnose…")
                        Text("Log archive parsing may take 30–60 seconds")
                            .font(.caption)
                            .foregroundStyle(.secondary)
                    }
                    .padding(32)
                    .background(.regularMaterial)
                    .clipShape(RoundedRectangle(cornerRadius: 14))
                }
                .ignoresSafeArea()
            }
        }
        .background(
            // Cmd+R while on the upload screen: clear the form/error so the
            // user can quickly try again after dropping the wrong file. Only
            // live while this view is in the hierarchy (i.e. before an
            // analysis has produced a result), unlike the app-wide Cmd+N.
            Button("") { resetForm() }
                .keyboardShortcut("r", modifiers: .command)
                .opacity(0)
        )
    }

    private func analyze() {
        appState.analyze(path: path, in: sessionID)
    }

    private func resetForm() {
        path = ""
        isTargeted = false
        appState.clearError(sessionID)
    }

    private func chooseFile() {
        let panel = NSOpenPanel()
        panel.canChooseFiles = true
        panel.canChooseDirectories = true
        panel.allowsMultipleSelection = false
        panel.message = "Choose a sysdiagnose .tar.gz archive or an extracted folder"
        if panel.runModal() == .OK, let url = panel.url {
            path = url.path
            analyze()
        }
    }

    /// Waits for every dropped file's URL to load (order preserved) before
    /// acting — with several files dropped at once, the first path fills
    /// in and analyzes on this still-blank tab, and each additional path
    /// opens its own new tab, instead of only ever using whichever single
    /// file happened to load first.
    private func handleDrop(_ providers: [NSItemProvider]) -> Bool {
        guard !providers.isEmpty else { return false }
        let group = DispatchGroup()
        var urlsByIndex: [Int: URL] = [:]
        let lock = NSLock()
        for (idx, provider) in providers.enumerated() {
            group.enter()
            _ = provider.loadObject(ofClass: URL.self) { url, _ in
                if let url {
                    lock.lock()
                    urlsByIndex[idx] = url
                    lock.unlock()
                }
                group.leave()
            }
        }
        group.notify(queue: .main) {
            let paths = urlsByIndex.keys.sorted().map { urlsByIndex[$0]!.path }
            guard let first = paths.first else { return }
            path = first
            appState.openDropped(paths: paths, primarySessionID: sessionID)
        }
        return true
    }
}
