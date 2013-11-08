#!/bin/sh

# This script is intended to be run just after hitting a soft reset on the data
# node.

set -e

# make sure we are in the util directory
if [ -d util ]; then cd util; fi

# ensure all the stuff we need is available
./acquire.py forward -h > /dev/null
../build/proto2bytes -h > /dev/null
kst2 --version &> /dev/null

# restart daemon
killall leafysd
../build/leafysd -A 192.168.1.2
echo "Waiting for daemon to spool up..."
sleep 2

# setup default channels
./debug_tool.py subsamples --constant chip 2

# start KST streaming
./acquire.py forward start -f -t subsample
if [ -e ../kst_subsamples.raw ]; then
    rm ../kst_subsamples.raw
fi
set +e
kst2 ./demo.kst & ../build/proto2bytes -s -A > ../kst_subsamples.raw
rm ../kst_subsamples.raw
