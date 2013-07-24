import sys

import h5py
import matplotlib.pyplot as plt
import numpy

def usage(exit_val=1):
    print 'plot_hdf5.py <hdf5_file> <start_channel> [<end_channel>]'
    sys.exit(exit_val)

if len(sys.argv) != 3 and len(sys.argv) != 4:
    usage()

try:
    f = sys.argv[1]
    ch_s = int(sys.argv[2])
    if len(sys.argv) == 4:
        ch_end = int(sys.argv[3])
    else:
        ch_end = ch_s
    nchannels = ch_end - ch_s + 1
    if nchannels > 32:
        print 'specify at most 32 channels'
        raise ValueError
except:
    usage()
h5f = h5py.File(f)
for dset in h5f:
    break
dset = h5f[dset]
print 'file:', f, 'channels: %d--%d' % (ch_s, ch_end)

assert dset.dtype == numpy.dtype([('ph_flags', '|u1'),
                                  ('samp_index', '<u4'),
                                  ('chip_live', '<u4'),
                                  ('samples', '<u2', (1120,))])
samp_index = 1
samples = 3

chdata = []
idxs = []
for data in dset:
    idxs.append(data[samp_index])
    chdata.append(data[samples][ch_s:ch_end + 1])

plt.figure(1)

maxwidth = 8
if nchannels < maxwidth:
    nrows = 1
    ncols = nchannels
else:
    nrows = nchannels / maxwidth
    ncols = maxwidth

print 'nrows:',nrows,'ncols:',ncols

for fignum in xrange(1, nrows * ncols + 1):
    plt.subplot(nrows, ncols, fignum)
    plt.plot(idxs, [chd[fignum - 1] for chd in chdata])
plt.show()
