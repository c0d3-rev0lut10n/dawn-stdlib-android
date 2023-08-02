#!/bin/bash
RANLIB='~/Android/Sdk/ndk/25.2.9519653/toolchains/llvm/prebuilt/linux-x86_64/bin/llvm-ranlib'
env RANLIB_armv7-linux-androideabi=$RANLIB RANLIB_aarch64-linux-android=$RANLIB RANLIB_x86_64-linux-android=$RANLIB RANLIB_i686-linux-android=$RANLIB ANDROID_NDK_HOME=~/Android/Sdk/ndk/25.2.9519653/ cargo ndk -t armeabi-v7a -t arm64-v8a -t x86 -t x86_64 build --release
