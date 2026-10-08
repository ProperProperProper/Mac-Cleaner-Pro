#!/bin/bash
# Build "Mac Cleaner Pro.app" (pure Rust) and install it.
#   ./build_app.sh            build + install to /Applications (or ~/Applications if not writable)
#   ./build_app.sh --no-install
# The bundle is ad-hoc signed with a STABLE identifier so firewall rules
# (e.g. LuLu) and privacy permissions keep matching across rebuilds.
set -euo pipefail
cd "$(dirname "$0")"

APP_NAME="Mac Cleaner Pro"
BIN="mac-cleaner-pro"
IDENT="com.local.mac-cleaner-pro"
VERSION="$(grep -m1 '^version' Cargo.toml | cut -d'"' -f2)"

cargo build --release

OUT="target/bundle/$APP_NAME.app"
rm -rf "$OUT"
mkdir -p "$OUT/Contents/MacOS" "$OUT/Contents/Resources"
cp "target/release/$BIN" "$OUT/Contents/MacOS/$BIN"
cp icon.icns "$OUT/Contents/Resources/icon.icns"
cat > "$OUT/Contents/Info.plist" <<PLIST
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>CFBundleName</key><string>$APP_NAME</string>
    <key>CFBundleDisplayName</key><string>$APP_NAME</string>
    <key>CFBundleExecutable</key><string>$BIN</string>
    <key>CFBundleIdentifier</key><string>$IDENT</string>
    <key>CFBundleIconFile</key><string>icon.icns</string>
    <key>CFBundlePackageType</key><string>APPL</string>
    <key>CFBundleShortVersionString</key><string>$VERSION</string>
    <key>CFBundleVersion</key><string>$VERSION</string>
    <key>CFBundleInfoDictionaryVersion</key><string>6.0</string>
    <key>LSMinimumSystemVersion</key><string>13.0</string>
    <key>NSHighResolutionCapable</key><true/>
    <key>LSApplicationCategoryType</key><string>public.app-category.utilities</string>
</dict>
</plist>
PLIST
codesign --force --deep --sign - --identifier "$IDENT" "$OUT"
codesign --verify --verbose=1 "$OUT"
echo "built: $OUT"

[[ "${1:-}" == "--no-install" ]] && exit 0

if [[ -w /Applications ]]; then DEST_DIR=/Applications; else DEST_DIR="$HOME/Applications"; mkdir -p "$DEST_DIR"; fi
DEST="$DEST_DIR/$APP_NAME.app"

# Keep one backup of whatever was installed before (outside git: backup/ is ignored).
if [[ -d "$DEST" && ! -d "backup/$APP_NAME (previous).app" ]]; then
    mkdir -p backup
    ditto "$DEST" "backup/$APP_NAME (previous).app"
    echo "backed up previous app to backup/$APP_NAME (previous).app"
fi
pkill -x "$BIN" 2>/dev/null || true
rm -rf "$DEST"
ditto "$OUT" "$DEST"
echo "installed: $DEST"

# Point an enabled weekly job at the installed binary (same label as before).
"$DEST/Contents/MacOS/$BIN" --update-schedule
