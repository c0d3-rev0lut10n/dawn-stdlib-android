#!/bin/bash

#	Copyright (c) 2023 Laurenz Werner
#	
#	This file is part of Dawn.
#	
#	Dawn is free software: you can redistribute it and/or modify
#	it under the terms of the GNU General Public License as published by
#	the Free Software Foundation, either version 3 of the License, or
#	(at your option) any later version.
#	
#	Dawn is distributed in the hope that it will be useful,
#	but WITHOUT ANY WARRANTY; without even the implied warranty of
#	MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#	GNU General Public License for more details.
#	
#	You should have received a copy of the GNU General Public License
#	along with Dawn.  If not, see <http://www.gnu.org/licenses/>.

# info function
notice() { printf "\033[0;32m%s\n\033[0m" "[INFO]: $*" >&1; }

NDK_PATH=~/Android/Sdk/ndk
NDKS=($(ls $NDK_PATH | sort -r))
notice "Available NDK versions: ${NDKS[*]}"
notice "Building against NDK version: ${NDKS[0]}"

RANLIB="$NDK_PATH/${NDKS[0]}/toolchains/llvm/prebuilt/linux-x86_64/bin/llvm-ranlib"
env RANLIB_armv7-linux-androideabi=$RANLIB RANLIB_aarch64-linux-android=$RANLIB RANLIB_x86_64-linux-android=$RANLIB RANLIB_i686-linux-android=$RANLIB ANDROID_NDK_HOME="$NDK_PATH/${NDKS[0]}" cargo ndk -t armeabi-v7a -t arm64-v8a -t x86 -t x86_64 build --release
