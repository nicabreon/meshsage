#!/bin/bash
set -e
OUTPUT_DIR="./build/macos"
mkdir -p "$OUTPUT_DIR"

echo "🚀 Compiling Meshsage Runtime for macOS (arm64)..."
CGO_ENABLED=1 \
GOOS=darwin \
GOARCH=arm64 \
go build -ldflags="-checklinkname=0" -buildmode=c-shared -o "$OUTPUT_DIR/libmeshsage.dylib" ./cmd/libmeshsage

echo "✅ Compiled dynamic library build/macos/libmeshsage.dylib"

# Copy to Flutter macos runner directory
FLUTTER_MACOS="../meshsage_flutter/macos"
if [ -d "$FLUTTER_MACOS" ]; then
    cp "$OUTPUT_DIR/libmeshsage.dylib" "$FLUTTER_MACOS/"
    echo "✅ Dynamic library successfully copied to Flutter macOS project!"
else
    echo "⚠️ Flutter macOS directory not found!"
fi
