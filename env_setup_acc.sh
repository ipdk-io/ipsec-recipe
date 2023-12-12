#!/bin/bash
#
# Copyright 2023 Intel Corporation
# SPDX-License-Identifier: Apache 2.0
#
# Script to setup environment variables facilitating IPsec-Recipe compilation
#

set -e

# Define directories
DEPS_INSTALL_DIR="PLUGIN_DEP_INSTALL"
DEPS_SRC_DIR="PLUGIN_DEP_SRC"

# Create directories if they don't exist
mkdir -p "${DEPS_INSTALL_DIR}"
mkdir -p "${DEPS_SRC_DIR}"

# Define environment variables
export DEPS_INSTALL=$PWD/${DEPS_INSTALL_DIR}
export SRC_DIR=$PWD/${DEPS_SRC_DIR}
export CMAKE_PREFIX="-DCMAKE_INSTALL_PREFIX=$DEPS_INSTALL"
export LD_LIBRARY_PATH="$DEPS_INSTALL/lib:$LD_LIBRARY_PATH"
export PKG_CONFIG_PATH="${DEPS_INSTALL}/lib/pkgconfig:$DEPS_INSTALL/lib/pkgconfig:$PKG_CONFIG_PATH"
export LDFLAGS="$LDFLAGS -Wl,-rpath-link=$DEPS_INSTALL/lib" 
export C_INCLUDE_PATH=$DEPS_INSTALL/include
export CPLUS_INCLUDE_PATH=$DEPS_INSTALL/include
export LIBRARY_PATH=$DEPS_INSTALL/lib
export PATH=$DEPS_INSTALL/bin:$PATH
export LD_LIBRARY_PATH=$DEPS_INSTALL/lib:$DEPS_INSTALL/lib64:$LD_LIBRARY_PATH
export PKG_CONFIG_PATH=$DEPS_INSTALL/lib/pkgconfig:$DEPS_INSTALL/lib64/pkgconfig
export C_INCLUDE_PATH=$DEPS_INSTALL/include
export CPLUS_INCLUDE_PATH=$DEPS_INSTALL/include

# Check if NUM_CORES and NUM_THREADS are already set
if [[ -n $NUM_CORES && -n $NUM_THREADS ]]; then
    echo "NUM_CORES and NUM_THREADS already set."
    exit 0
fi

# Check if nproc command exists
if command -v nproc &> /dev/null; then
    NUM_CORES=$(nproc --all)
    if [[ "$NUM_CORES" -gt 4 ]]; then
        NUM_THREADS=$((NUM_CORES / 4))
        NUM_THREADS=-j$NUM_THREADS
    else
        NUM_THREADS=-j${NUM_CORES}
    fi
else
    NUM_CORES=1
    NUM_THREADS=-j1
fi

# Export NUM_CORES and NUM_THREADS
export NUM_CORES
export NUM_THREADS

# Print all the environment variables set in this script
echo ""
echo "Updated Environment Variables ..."
echo "DEPS_INSTALL=${DEPS_INSTALL}"
echo "SRC_DIR=${SRC_DIR}"
echo "CMAKE_PREFIX=${CMAKE_PREFIX}"
echo "LD_LIBRARY_PATH=${LD_LIBRARY_PATH}"
echo "PKG_CONFIG_PATH=${PKG_CONFIG_PATH}"
echo "LDFLAGS=${LDFLAGS}"
echo "C_INCLUDE_PATH=${C_INCLUDE_PATH}"
echo "CPLUS_INCLUDE_PATH=${CPLUS_INCLUDE_PATH}"
echo "LIBRARY_PATH=${LIBRARY_PATH}"
echo "PATH=${PATH}"
echo "NUM_CORES=${NUM_CORES}"
echo "NUM_THREADS=${NUM_THREADS}"
echo ""
