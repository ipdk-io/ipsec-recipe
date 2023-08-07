mkdir PLUGIN_DEP_INSTALL
export DEPS_INSTALL=$PWD/PLUGIN_DEP_INSTALL
mkdir PLUGIN_DEP_SRC
export SRC_DIR=$PWD/PLUGIN_DEP_SRC
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

# First check if NUM_CORES and NUM_THREADS are already set, and exit if so.
   if [[ -n $NUM_CORES && -n $NUM_THREADS ]]
   then
      echo "NUM_CORES and NUM_THREADS already set."
      return
   fi

   nproc_exist=$(command -v nproc)
   if [ -n "$nproc_exist" ];
   then
       NUM_CORES=$(nproc --all)
       echo "Num cores on a system: $NUM_CORES"
       if [ "$NUM_CORES" -gt 4 ]
       then
           NUM_THREADS=$((NUM_CORES / 4))
           NUM_THREADS=-j$NUM_THREADS
       else
           NUM_THREADS=-j${NUM_CORES}
       fi
    else
        NUM_CORES=1
        NUM_THREADS=-j1
    fi
