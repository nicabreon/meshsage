#!/bin/bash
set -e

SDK_PATH=$(xcrun --sdk iphonesimulator --show-sdk-path)
OUTPUT_DIR="./build/ios"
mkdir -p "$OUTPUT_DIR"

echo "🚀 Compiling Meshsage Go core for iOS Simulator (arm64)..."

# Target triple for simulator
TARGET="arm64-apple-ios12.0-simulator"

CGO_ENABLED=1 \
CC="$(xcrun --sdk iphonesimulator --find clang)" \
CXX="$(xcrun --sdk iphonesimulator --find clang++)" \
CGO_CFLAGS="-target $TARGET -isysroot $SDK_PATH" \
CGO_LDFLAGS="-target $TARGET -isysroot $SDK_PATH" \
GOOS=ios \
GOARCH=arm64 \
go build -ldflags="-checklinkname=0" -buildmode=c-archive -o "$OUTPUT_DIR/libmeshsage.a" ./cmd/libmeshsage

echo "✅ Compiled static library build/ios/libmeshsage.a"

# Copy to Flutter ios runner search path
FLUTTER_IOS="../meshsage_flutter/ios/Runner"
if [ -d "$FLUTTER_IOS" ]; then
    cp "$OUTPUT_DIR/libmeshsage.a" "$FLUTTER_IOS/"
    cp "$OUTPUT_DIR/libmeshsage.h" "$FLUTTER_IOS/"
    echo "✅ Static library and headers successfully copied to Flutter iOS project!"
else
    echo "⚠️ Flutter iOS Runner directory not found!"
fi
