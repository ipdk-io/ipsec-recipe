#!/bin/bash
#
# Copyright 2023-2024 Intel Corporation
# SPDX-License-Identifier: GPL-3.0-or-later
#
# Script to clone, build, and install ipsec-recipe dependencies
#

set -e

# gflags repo clone, build and install
MODULE="gflags"
echo "####  Cloning, Building and Installing the '$MODULE' module ####"
mkdir -p ${DEPS_SRC}/$MODULE
git clone https://github.com/gflags/gflags.git  ${DEPS_SRC}/$MODULE
cd $DEPS_SRC/$MODULE
git checkout 827c769e5fc98e0f2a34c47cef953cc6328abced
mkdir -p $DEPS_SRC/$MODULE/build
cd $DEPS_SRC/$MODULE/build
cmake -DBUILD_SHARED_LIBS=ON $CMAKE_PREFIX ..
make $NUM_THREADS
sudo make $NUM_THREADS install
sudo ldconfig

# glog repo clone, build and install
MODULE="glog"
echo "####  Cloning, Building and Installing the '$MODULE' module ####"
mkdir -p ${DEPS_SRC}/$MODULE
git clone https://github.com/google/glog.git  ${DEPS_SRC}/$MODULE
cd $DEPS_SRC/$MODULE
git checkout 503e3dec8d1fe071376befc62119a837c26612a3
mkdir -p $DEPS_SRC/$MODULE/build
cd $DEPS_SRC/$MODULE/build
cmake $CMAKE_PREFIX -DCMAKE_CXX_FLAGS=-I$(INSTALL_DIR)/include -Dgflags_DIR:PATH=$INSTALL_DIR/lib/cmake/gflags ..
make $NUM_THREADS
sudo make $NUM_THREADS install
sudo ldconfig

# abseil-cpp repo clone, build and install
MODULE="abseil-cpp"
echo "####  Cloning, Building and Installing the '$MODULE' module ####"
mkdir -p ${DEPS_SRC}/$MODULE
git clone https://github.com/abseil/abseil-cpp.git  ${DEPS_SRC}/$MODULE
cd $DEPS_SRC/$MODULE
git checkout ec0d76f1d012cc1a4b3b08dfafcfc5237f5ba2c9
mkdir -p $DEPS_SRC/$MODULE/build
cd $DEPS_SRC/$MODULE/build
cmake -DBUILD_TESTING=OFF $CMAKE_PREFIX ..
make $NUM_THREADS
sudo make $NUM_THREADS install
sudo ldconfig

# cctz repo clone, build and install
MODULE="cctz"
echo "####  Cloning, Building and Installing the '$MODULE' module ####"
mkdir -p ${DEPS_SRC}/$MODULE
git clone https://github.com/google/cctz.git  ${DEPS_SRC}/$MODULE
cd $DEPS_SRC/$MODULE
git checkout 02918d62329ef440935862719829d061a5f4beba
mkdir -p $DEPS_SRC/$MODULE/build
cd $DEPS_SRC/$MODULE/build
cmake -DBUILD_TESTING=OFF -DCMAKE_POSITION_INDEPENDENT_CODE=ON $CMAKE_PREFIX ..
make $NUM_THREADS
sudo make $NUM_THREADS install
sudo ldconfig

# protobuf repo clone, build and install
MODULE="protobuf"
echo "####  Cloning, Building and Installing the '$MODULE' module ####"
mkdir -p ${DEPS_SRC}/$MODULE
git clone https://github.com/google/protobuf.git  ${DEPS_SRC}/$MODULE
cd ${DEPS_SRC}/$MODULE
git checkout tags/v3.19.4
mkdir -p $DEPS_SRC/$MODULE/build
cd $DEPS_SRC/$MODULE/build
cmake -Dprotobuf_BUILD_TESTS=OFF -DCMAKE_POSITION_INDEPENDENT_CODE=ON $CMAKE_PREFIX ../cmake
sudo make $NUM_THREADS
sudo make $NUM_THREADS install
sudo ldconfig

# nlohmann repo clone, build and install
MODULE="json"
echo "####  Cloning, Building and Installing the '$MODULE' module ####"
mkdir -p ${DEPS_SRC}/$MODULE
git clone https://github.com/nlohmann/json.git  ${DEPS_SRC}/$MODULE
cd $DEPS_SRC/$MODULE
git checkout 760304635dc74a5bf77903ad92446a6febb85acf
mkdir -p $DEPS_SRC/$MODULE/build
cd $DEPS_SRC/$MODULE/build
cmake $CMAKE_PREFIX ..
make $NUM_THREADS
sudo make $NUM_THREADS install
sudo ldconfig

# grpc repo clone, build and install
MODULE="grpc"
echo "####  Cloning, Building and Installing the '$MODULE' module ####"
mkdir -p ${DEPS_SRC}/$MODULE
git clone https://github.com/google/grpc.git  ${DEPS_SRC}/$MODULE
cd ${DEPS_SRC}/$MODULE
git checkout tags/v1.48.0
git submodule update --init --recursive
mkdir build
cd build
cmake \
	-DgRPC_BUILD_TESTS=OFF \
	-DBUILD_SHARED_LIBS=ON \
	-DgRPC_INSTALL=ON \
	-DCMAKE_POSITION_INDEPENDENT_CODE=ON $CMAKE_PREFIX ..
sudo make $NUM_THREADS
sudo make $NUM_THREADS install
sudo ldconfig

set +e
