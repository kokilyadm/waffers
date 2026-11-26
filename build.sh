#!/usr/bin/env bash
# Waffers — The layer that protects you
# WordPress.org Distribution Build Script
set -e

BUILD_DIR="/tmp/waffers-dist"
DIST_ZIP="$(pwd)/waffers.zip"
SLUG_ZIP="$(pwd)/waffers-the-layer-that-protects-you.zip"
LEGACY_ZIP="$(pwd)/php-armor.zip"

echo "[*] Cleaning previous build artifacts..."
rm -f "$DIST_ZIP" "$SLUG_ZIP" "$LEGACY_ZIP"
rm -rf "$BUILD_DIR"
mkdir -p "$BUILD_DIR/waffers-the-layer-that-protects-you"

echo "[*] Staging production plugin files for Waffers..."
cp waffers.php "$BUILD_DIR/waffers-the-layer-that-protects-you/"
cp php-armor.php "$BUILD_DIR/waffers-the-layer-that-protects-you/"
cp readme.txt "$BUILD_DIR/waffers-the-layer-that-protects-you/"
cp early-waf.php "$BUILD_DIR/waffers-the-layer-that-protects-you/"
cp uninstall.php "$BUILD_DIR/waffers-the-layer-that-protects-you/"
cp -r includes "$BUILD_DIR/waffers-the-layer-that-protects-you/"
cp -r admin "$BUILD_DIR/waffers-the-layer-that-protects-you/"
cp -r languages "$BUILD_DIR/waffers-the-layer-that-protects-you/"

echo "[*] Purging development clutter (.DS_Store, test files, temp cache)..."
find "$BUILD_DIR/waffers-the-layer-that-protects-you" -name ".*" -not -name "." -delete 2>/dev/null || true
find "$BUILD_DIR/waffers-the-layer-that-protects-you" -name "*.pyc" -delete 2>/dev/null || true
find "$BUILD_DIR/waffers-the-layer-that-protects-you" -name "__pycache__" -delete 2>/dev/null || true

echo "[*] Compressing to WordPress repository-compliant ZIP..."
(cd "$BUILD_DIR" && zip -r -q "$SLUG_ZIP" waffers-the-layer-that-protects-you/)
cp "$SLUG_ZIP" "$DIST_ZIP"
cp "$SLUG_ZIP" "$LEGACY_ZIP"

echo "[*] Cleaning temporary staging..."
rm -rf "$BUILD_DIR"

echo "[+] Success! Production archive generated: $SLUG_ZIP"
unzip -l "$SLUG_ZIP"
