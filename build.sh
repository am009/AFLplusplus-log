#!/bin/bash

# change llvm version
# sudo rm /usr/bin/llvm-config
# sudo ln -s ../lib/llvm-17/bin/llvm-config /usr/bin/llvm-config
# llvm-config --version

# build compile commands json
# make clean
# NO_NYX=1 bear -- make source-only

# AFL_DEBUG=1 
NO_NYX=1 make source-only # && sudo make install
