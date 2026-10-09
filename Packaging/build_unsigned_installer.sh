#!/usr/bin/env bash
set -euo pipefail

# Builds an UNSIGNED DeviceDiag.pkg for internal developer testing only.
# No Developer ID certificate or Apple ID needed. This is NOT for wider
# distribution - every tester's Mac will show a Gatekeeper warning on first
# launch (see the instructions this script prints at the end). Once this is
# ready for the fleet via Jamf Pro, use build_app.sh's proper Developer ID
# signing + notarization path instead.

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
APP_NAME="DeviceDiag"
BUNDLE_ID="com.boaz.devicediag"
VERSION="1.0"
DIST_DIR="$REPO_ROOT/dist"
APP_BUNDLE="$DIST_DIR/$APP_NAME.app"
PKG_PATH="$DIST_DIR/$APP_NAME-$VERSION-unsigned.pkg"

cd "$REPO_ROOT"

echo "==> Building Apple Silicon (arm64) release binary..."
swift build -c release

BINARY="$REPO_ROOT/.build/release/$APP_NAME"
if [ ! -f "$BINARY" ]; then
    # In case this is ever switched to a multi-arch build (needs Xcode's
    # XCBuild backend - see build_app.sh's header comment).
    BINARY="$REPO_ROOT/.build/apple/Products/Release/$APP_NAME"
fi
if [ ! -f "$BINARY" ]; then
    echo "error: couldn't find the built binary. Check the swift build output above" >&2
    echo "       for the actual product path and update BINARY in this script." >&2
    exit 1
fi

echo "==> Assembling $APP_BUNDLE..."
rm -rf "$APP_BUNDLE"
mkdir -p "$APP_BUNDLE/Contents/MacOS"
mkdir -p "$APP_BUNDLE/Contents/Resources"

cp "$BINARY" "$APP_BUNDLE/Contents/MacOS/$APP_NAME"
cp "$SCRIPT_DIR/Info.plist" "$APP_BUNDLE/Contents/Info.plist"

if [ -f "$SCRIPT_DIR/AppIcon.icns" ]; then
    cp "$SCRIPT_DIR/AppIcon.icns" "$APP_BUNDLE/Contents/Resources/AppIcon.icns"
else
    echo "    (no Packaging/AppIcon.icns - app will use the generic document icon)"
fi

chmod +x "$APP_BUNDLE/Contents/MacOS/$APP_NAME"

echo "==> Ad-hoc signing (no cert, no Apple ID - required just so this can"
echo "    launch at all on Apple Silicon; does not satisfy Gatekeeper)..."
codesign --force --deep --sign - "$APP_BUNDLE"

echo "==> Building unsigned .pkg..."
mkdir -p "$DIST_DIR"
rm -f "$PKG_PATH"
pkgbuild --install-location /Applications \
    --component "$APP_BUNDLE" \
    --identifier "$BUNDLE_ID.pkg" \
    --version "$VERSION" \
    "$PKG_PATH"

echo
echo "==> Done: $PKG_PATH"
echo
echo "Hand that .pkg to your testers. Since it's unsigned, each of their Macs"
echo "will block it on first launch - tell them to do ONE of:"
echo
echo "  * Right-click (Control-click) DeviceDiag.app in /Applications > Open"
echo "    > Open. Works for unsigned apps too, just needs the extra click"
echo "    instead of a plain double-click."
echo
echo "  * If that doesn't show a bypass option: System Settings > Privacy &"
echo "    Security > scroll down to the blocked-app notice > Open Anyway."
echo
echo "  * Or from Terminal, strip the quarantine flag before opening:"
echo "      xattr -cr \"/Applications/$APP_NAME.app\""
echo
echo "This path is for internal test builds only. For the real fleet"
echo "rollout through Jamf Pro, use build_app.sh's Developer ID signing +"
echo "notarization pipeline instead - otherwise every machine in the fleet"
echo "hits this same warning."
