#!/bin/bash
set -e

NDK_PATH="/Users/nicabreon/Library/Android/sdk/ndk/30.0.14904198"
TOOLCHAIN="$NDK_PATH/toolchains/llvm/prebuilt/darwin-x86_64"

# Create build output directories
OUTPUT_DIR="./build/android"
mkdir -p "$OUTPUT_DIR/arm64-v8a"
mkdir -p "$OUTPUT_DIR/armeabi-v7a"
mkdir -p "$OUTPUT_DIR/x86_64"
mkdir -p "$OUTPUT_DIR/x86"

echo "🚀 Starting Meshsage native compilation for Android using NDK Clang..."

echo "1/4 Building for arm64-v8a (64-bit ARM, API=24)..."
CGO_ENABLED=1 \
CC="$TOOLCHAIN/bin/aarch64-linux-android24-clang" \
CXX="$TOOLCHAIN/bin/aarch64-linux-android24-clang++" \
GOOS=android \
GOARCH=arm64 \
go build -ldflags="-checklinkname=0" -buildmode=c-shared -o "$OUTPUT_DIR/arm64-v8a/libmeshsage.so" ./cmd/libmeshsage

echo "2/4 Building for armeabi-v7a (32-bit ARM, API=24)..."
CGO_ENABLED=1 \
CC="$TOOLCHAIN/bin/armv7a-linux-androideabi24-clang" \
CXX="$TOOLCHAIN/bin/armv7a-linux-androideabi24-clang++" \
GOOS=android \
GOARCH=arm \
go build -ldflags="-checklinkname=0" -buildmode=c-shared -o "$OUTPUT_DIR/armeabi-v7a/libmeshsage.so" ./cmd/libmeshsage

echo "3/4 Building for x86_64 (64-bit Intel Emulator, API=24)..."
CGO_ENABLED=1 \
CC="$TOOLCHAIN/bin/x86_64-linux-android24-clang" \
CXX="$TOOLCHAIN/bin/x86_64-linux-android24-clang++" \
GOOS=android \
GOARCH=amd64 \
go build -ldflags="-checklinkname=0" -buildmode=c-shared -o "$OUTPUT_DIR/x86_64/libmeshsage.so" ./cmd/libmeshsage

echo "4/4 Building for x86 (32-bit Intel Emulator, API=24)..."
CGO_ENABLED=1 \
CC="$TOOLCHAIN/bin/i686-linux-android24-clang" \
CXX="$TOOLCHAIN/bin/i686-linux-android24-clang++" \
GOOS=android \
GOARCH=386 \
go build -ldflags="-checklinkname=0" -buildmode=c-shared -o "$OUTPUT_DIR/x86/libmeshsage.so" ./cmd/libmeshsage

echo "✅ Native libraries compiled successfully!"

# Auto copy to Flutter directories
FLUTTER_JNILIBS="../meshsage_flutter/android/app/src/main/jniLibs"
if [ -d "$FLUTTER_JNILIBS" ] || [ -d "../meshsage_flutter" ]; then
    echo "📦 Packaging native libraries into Flutter project..."
    mkdir -p "$FLUTTER_JNILIBS/arm64-v8a"
    mkdir -p "$FLUTTER_JNILIBS/armeabi-v7a"
    mkdir -p "$FLUTTER_JNILIBS/x86_64"
    mkdir -p "$FLUTTER_JNILIBS/x86"
    
    cp "$OUTPUT_DIR/arm64-v8a/libmeshsage.so" "$FLUTTER_JNILIBS/arm64-v8a/"
    cp "$OUTPUT_DIR/armeabi-v7a/libmeshsage.so" "$FLUTTER_JNILIBS/armeabi-v7a/"
    cp "$OUTPUT_DIR/x86_64/libmeshsage.so" "$FLUTTER_JNILIBS/x86_64/"
    cp "$OUTPUT_DIR/x86/libmeshsage.so" "$FLUTTER_JNILIBS/x86/"
    
    echo "✅ Native libraries loaded successfully to Flutter Android JNI folder!"
else
    echo "ℹ️ Flutter project path at $FLUTTER_JNILIBS not initialized yet, compiled libraries saved locally in ./build/android/"
fi
