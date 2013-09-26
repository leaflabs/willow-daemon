#!/bin/sh

set -e

# make sure we are in the util directory
if [ -d util ]; then cd util; fi

# ensure all the stuff we need is available
./acquire.py forward -h > /dev/null
../build/proto2bytes -h > /dev/null
kst2 --version &> /dev/null

# ok, actually do it
./acquire.py forward start -f -t subsample
if [ -e ../kst_subsamples.raw ]; then
    rm ../kst_subsamples.raw
fi
kst2 ./kst_subsamples.kst & ../build/proto2bytes -s -A > ../kst_subsamples.raw
rm ../kst_subsamples.data
