#!/usr/bin/env bash
# Waffers — The layer that protects you
# WordPress.org Distribution Build Script
set -e

BUILD_DIR="/tmp/waffers-dist"
DIST_ZIP="$(pwd)/waffers.zip"
LEGACY_ZIP="$(pwd)/php-armor.zip"

echo "[*] Cleaning previous build artifacts..."
rm -f "$DIST_ZIP" "$LEGACY_ZIP"
rm -rf "$BUILD_DIR"
mkdir -p "$BUILD_DIR/waffers"

echo "[*] Staging production plugin files for Waffers..."
cp waffers.php "$BUILD_DIR/waffers/"
cp php-armor.php "$BUILD_DIR/waffers/"
cp readme.txt "$BUILD_DIR/waffers/"
cp early-waf.php "$BUILD_DIR/waffers/"
cp uninstall.php "$BUILD_DIR/waffers/"
cp -r includes "$BUILD_DIR/waffers/"
cp -r admin "$BUILD_DIR/waffers/"
cp -r languages "$BUILD_DIR/waffers/"

echo "[*] Purging development clutter (.DS_Store, test files, temp cache)..."
find "$BUILD_DIR/waffers" -name ".*" -not -name "." -delete 2>/dev/null || true
find "$BUILD_DIR/waffers" -name "*.pyc" -delete 2>/dev/null || true
find "$BUILD_DIR/waffers" -name "__pycache__" -delete 2>/dev/null || true

echo "[*] Compressing to WordPress repository-compliant ZIP..."
(cd "$BUILD_DIR" && zip -r -q "$DIST_ZIP" waffers/)
cp "$DIST_ZIP" "$LEGACY_ZIP"

echo "[*] Cleaning temporary staging..."
rm -rf "$BUILD_DIR"

echo "[+] Success! Production archive generated: $DIST_ZIP"
unzip -l "$DIST_ZIP"
