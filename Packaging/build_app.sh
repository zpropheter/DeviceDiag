#!/usr/bin/env bash
set -euo pipefail

# Builds DeviceDiag.app for distribution: an Apple Silicon (arm64) release
# binary assembled into a real .app bundle using the Info.plist in this
# folder. This does NOT require an .xcodeproj - `swift build` + manual
# bundle assembly is a well-established way to ship a pure-SwiftPM macOS app.
#
# Builds arm64-only by default. If you also need an Intel build, that
# requires SwiftPM's multi-arch path (`--arch arm64 --arch x86_64`), which
# goes through Xcode's XCBuild backend - on some machines that backend isn't
# set up (error: "xcbuild executable ... does not exist or is not
# executable"), usually meaning Command Line Tools are selected instead of
# full Xcode (check `xcode-select -p`; it should point at
# /Applications/Xcode.app/Contents/Developer, and Xcode needs to have been
# launched once to install its additional components). Once that's fixed,
# swap the build line below for:
#   swift build -c release --arch arm64 --arch x86_64
# and change BINARY's first candidate path to
# .build/apple/Products/Release/$APP_NAME.
#
# This script only builds + bundles. It deliberately does not sign or
# notarize automatically (that needs your Developer ID cert / Apple ID
# credentials, which this script doesn't have) - it prints the exact
# commands to run next.
#
# Usage:
#   ./Packaging/build_app.sh

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
APP_NAME="DeviceDiag"
BUNDLE_ID="com.boaz.devicediag"   # <-- keep in sync with Info.plist
VERSION="1.0"
DIST_DIR="$REPO_ROOT/dist"
APP_BUNDLE="$DIST_DIR/$APP_NAME.app"

cd "$REPO_ROOT"

echo "==> Building Apple Silicon (arm64) release binary..."
swift build -c release

BINARY="$REPO_ROOT/.build/release/$APP_NAME"
if [ ! -f "$BINARY" ]; then
    # In case this is ever switched to the multi-arch path above.
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
    echo "    (no Packaging/AppIcon.icns yet - app will use the generic document icon)"
fi

chmod +x "$APP_BUNDLE/Contents/MacOS/$APP_NAME"

echo "==> Built: $APP_BUNDLE"
echo
echo "Next steps (run manually - need your signing cert / Apple ID):"
echo
echo "  1) Sign with your Developer ID cert + Hardened Runtime:"
echo "       codesign --deep --force --options runtime \\"
echo "         --entitlements \"$SCRIPT_DIR/DeviceDiag.entitlements\" \\"
echo "         --sign \"Developer ID Application: <Your Org Name> (<TEAMID>)\" \\"
echo "         \"$APP_BUNDLE\""
echo
echo "  2) Verify the signature:"
echo "       codesign --verify --deep --strict --verbose=2 \"$APP_BUNDLE\""
echo
echo "  3) Zip it for notarization:"
echo "       mkdir -p \"$DIST_DIR\""
echo "       ditto -c -k --keepParent \"$APP_BUNDLE\" \"$DIST_DIR/$APP_NAME.zip\""
echo
echo "  4) Submit for notarization and wait for the result:"
echo "       xcrun notarytool submit \"$DIST_DIR/$APP_NAME.zip\" \\"
echo "         --apple-id <you@jamf.com> --team-id <TEAMID> \\"
echo "         --password <app-specific-password> --wait"
echo
echo "  5) Staple the ticket so it works offline / on first launch:"
echo "       xcrun stapler staple \"$APP_BUNDLE\""
echo
echo "  6) Build a signed .pkg for Jamf Pro:"
echo "       pkgbuild --install-location /Applications \\"
echo "         --component \"$APP_BUNDLE\" \\"
echo "         --identifier \"$BUNDLE_ID.pkg\" --version \"$VERSION\" \\"
echo "         --sign \"Developer ID Installer: <Your Org Name> (<TEAMID>)\" \\"
echo "         \"$DIST_DIR/$APP_NAME-$VERSION.pkg\""
echo
echo "  Then upload $APP_NAME-$VERSION.pkg as a Package in Jamf Pro and scope"
echo "  a policy or Self Service item to it. Bump VERSION here (and in"
echo "  Info.plist) each time you re-run this for a new release."
