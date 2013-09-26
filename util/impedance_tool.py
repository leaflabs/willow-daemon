#!/usr/bin/env python
"""
This is a script to measure probe impedances on a per-channel basis.

DO NOT run this script during acquisition to disk or readback from disk.

It requires the h5py and numpy packages. On debian::

    apt-get install python-h5py python-numpy

Impedance Measurement Process (paraphrased):

    1. start streaming
    2. parse chip_alive to determine which chips to test
    3. setup channels for first chip
    4. collect 1 second of contiguous data for chip
    5. run FFT on each returned channel, store result
    6. setup next chip and back to #4
    7. when done, return channel map to defaults and stop streaming

TODO:
 - real math with units, not "impedance factor"
 - currently full-sample streams are saved to disk, even though only sub-sample
   streams are required. this is an open feature request for the daemon.
 - loading and re-ordering HDF5 data is super slow. scales with number of chips 
   being measured.
 - there are several magic numbers sprinkled around, eg to decode the command
   status enum. these should be replaced with human readable values. see TODO
   tags.

See the '-h' usage for more info.
"""

from __future__ import print_function
import argparse
import collections
import os
import sys
import time
import tempfile
import socket

import h5py
import numpy
import numpy.fft

from daemon_control import *
from debug_tool import read_request, write_request, set_channel_list, modules

# ========== Helpers =========== #
def amplitude2impedance(amp):
    """
    TODO:
    This returns the impedance "factor", which I just now made up. Sort of a
    proxy for resistance until I do the actual math.
    """
    max_amp = float(2**15) # rail-to-rail amplitude for 16bit ADC
    if amp == 0:
        return 'open'
    imp = max_amp/amp - 1.0
    if imp > 10**7: # 10,000,000 Ohm MAX!!! that's a lota impedence
        return 'open'
    elif imp <= 0.01: # very small, probably numerical
        return 'short'
    else:
        return imp
    return max(max_amp/amp - 1.0, 0)

def calculate_impedences(waveforms, verbose=False):
    if verbose:
        for k in waveforms.keys():
            print("\t\t%d: %d %d %d ..." % (k,
                waveforms[k][0],
                waveforms[k][1],
                waveforms[k][2],))
    amplitudes = dict()
    for k in waveforms.keys():
        wf = waveforms[k]
        onekhz_index = int(1000 * len(wf)/30000)
        fourier = numpy.fft.rfft(wf)
        #freqs = numpy.fft.fftfreq(wf.size, d=1/30000.)
        #print "%d: %f" % (onekhz_index, freqs[onekhz_index])
        onekhz = fourier[onekhz_index] * 2.0 / len(wf)
        amplitudes[k] = (onekhz, amplitude2impedance(abs(onekhz)))
    return amplitudes

def get_chips_alive():
    mask = read_request(modules['daq'], 4)
    return [i for i in range(32) if (mask & (0x1 << i))]

def get_sata_mode():
    return read_request(modules['sata'], 1)

def configure_dac(enable, power, scale, enall, chan):
    """
    Sets up the Intan registers relating to impedance measurements on all
    attached chips.

    This function assumes that the DAQ module (in FPGA) is already enabled.

    Parameters:

        enable: the impedance check mode enable bit
        power: the DAC power enable bit
        scale: 2 bits, sets the amplitude of the DAC injection signal
            0 (0b00) for 0.1pF capacitor
            1 (0b01) for 1.0pF capacitor
            3 (0b11) for 10pF capacitor
        enall: LEAVE THIS FALSE, only used for electroplating
        chan: 7-bit channel select register

    See page 20 of the Intan RHD2000 datasheet for more details.
    """
    assert(not enall)
    # convert parameters to bit masks
    enable = enable and 0b1 or 0x0
    power = enable and (0b1 << 6) or 0x0
    enall = enall and (0b1 << 2) or 0x0
    scale = (scale & 0b11) << 3
    chan = chan & 0b11111
    # first set DAC configuration register
    cmd = ((0x1 << 24) |        # aux command write enable
           (0xFF << 16) |       # all chips (required by h/w)
           (0b10000101 << 8) |  # write to register 5 (DAC config)
           (enable | power | enall | scale))   # settings
    assert(write_request(modules['daq'], 5, cmd) is not None)
    # then set DAC channel select register
    cmd = ((0x1 << 24) |        # aux command write enable
           (0xFF << 16) |       # all chips
           (0b10000111 << 8) |  # write to register 7 (DAC chan select)
           (chan))              # channel select
    assert(write_request(modules['daq'], 5, cmd) is not None)
    # clear intan command register
    assert(write_request(modules['daq'], 5, 0) is not None)

def configure_streaming(enable, force_dac_reset=True, ip_addr='127.0.0.1',
        ip_port=7654):
    cmd = ControlCommand(type=ControlCommand.FORWARD)
    cmd.forward.enable = enable
    cmd.forward.force_daq_reset = force_dac_reset
    cmd.forward.sample_type = 1 # BOARD_SUBSAMPLE
    cmd.forward.dest_udp_addr4 = \
        struct.unpack('!l', socket.inet_aton(ip_addr))[0]
    cmd.forward.dest_udp_port = ip_port
    reply = do_control_cmd(cmd)
    assert(reply is not None)
    assert(reply.type == 2)       # TODO: SUCCESS

def save_stream(nsamples, temp_directory, chan, attempts=3):
    fpath = os.path.join(temp_directory, "chan_%d.h5" % chan)
    cmd = ControlCommand(type=ControlCommand.STORE)
    cmd.store.path = os.path.abspath(fpath)
    cmd.store.nsamples = nsamples
    cmd.store.backend = STORE_HDF5
    for i in range(attempts):
        reply = do_control_cmd(cmd)
        assert(reply is not None)
        if reply.store.status == 1:         # TODO: DONE
            break
        elif reply.store.status in [3, 4]:  # TODO: PKTDROP or TIMEOUT
            print(reply)
            print("Retrying...")
        else:   # ERR
            print(reply)
            raise Exception("Oh no!")    
    if reply.store.status != 1:             # TODO: DONE
        raise Exception("Timed out!")
    return fpath

def load_chip_data_from_hdf5(fpath, chips):
    data = dict()
    with h5py.File(fpath, 'r', driver='core') as f:
        d = f['wired-dataset']
        count = d.shape[0]
        for c in chips:
            data[c] = numpy.zeros((count,), dtype='u2')
        print("\tLoading and re-ordering data (slow!)...")
        for i in range(count):
            for c in chips:
                data[c][i] = d[i][3][c]
        """ DEBUG
        i = 0
        for sample in d:
            print sample[3][0]
            for c in chips:
                data[c][i] = sample[3][c]
            i = i+1
        """
    return data

def process_data(fpath, chips, currentmode, verbose=False):
    data = load_chip_data_from_hdf5(fpath, chips)
    print("\tCalculating imedances...")
    results = calculate_impedences(data, verbose)
    if verbose:
        for k in chips:
            print("\t\tChip %02d: %s" % (k, results[k]))
    return results

# ========== Commands =========== #

def run(chips, channels, samples, pause, currentmode, force=False,
        keepfiles=False, verbose=False):
    currentmode = {"low":0, "medium":1, "high":3}[currentmode]
    if verbose:
        print("chips: %s" % chips)
        print("channels: %s" % channels)
        print("samples: %s" % samples)
        print("pause: %s" % pause)
        print("currentmode: " + bin(currentmode))
        print("keepfiles: %s" % keepfiles)
        print("force: %s" % force)
        print("-----------------------------------------------")

    # check that SATA is disabled
    if get_sata_mode() != 0:
        print("Looks like SATA is running! mode=%d" % get_sata_mode())
        print("Halting; this check can not be overridden.")
        sys.exit(-1)
    elif verbose:
        print("SATA mode was 0.")

    # start sub-sample streaming
    configure_streaming(True)
    if not force:
        # check chip_alive against chips[]
        alive_chips = get_chips_alive()
        if verbose:
            print("alive_chips: %s" % alive_chips)
        for c in chips:
            if not c in alive_chips:
                print("alive_chips: %s" % alive_chips)
                print("Told to measure chip %d, but it isn't alive." % c)
                print("Halting; use --force to override")
                sys.exit(-1)
    else:
        print("Skipping chip alive check.")

    temp_directory = tempfile.mkdtemp(
        prefix="wired_impedance_%s_" % (time.strftime("%Y%m%d")))
    results = {}
    for chan in channels:
        print("Acquiring data for channel %d:" % chan)
        # setup chips for channel
        set_channel_list([(chip, chan) for chip in range(32)])
        # enable DAC injection
        configure_dac(True, True, currentmode, False, chan)
        # pause for DAC to stabilize
        if verbose:
            print("\tSleeping for %f seconds..." % pause)
        time.sleep(pause)
        # save N samples contiguous data for channel to disk
        if verbose:
            print("\tCollecting %d samples..." % samples)
        fpath = save_stream(samples, temp_directory, chan)
        # disable DAC injection
        configure_dac(False, 0, 0, 0, 0)
        # load data and determine impedances for each chip; print and store
        # result
        results[chan]= process_data(fpath, chips, currentmode, verbose)
        if not keepfiles:
            # delete data file
            os.unlink(fpath)
    
    if not keepfiles:
        os.rmdir(temp_directory)

    print("Done measuring, cleaning up...")
    # disable dac
    configure_dac(False, False, 0, False, 0)
    # return channel map to defaults
    set_channel_list([(chip, 0) for chip in range(32)])
    # stop streaming
    configure_streaming(False)
    # pretty print results
    print("============== Results ==============")
    for chip in chips:
        print("Chip %02d:" % chip)
        for channel in channels:
            print("\tChannel %02d: %s" % (channel, results[channel][chip][1]))
    print("=====================================")
    if keepfiles:
        print("Raw files retained and available at %s" % temp_directory)


# ========== Script/Args =========== #
def main():
    parser = argparse.ArgumentParser(
        description="Measures probe impedances.",
        epilog="Kapow.")
    parser.add_argument("-v", "--verbose", action="store_true")
    parser.add_argument("-c", "--chips", type=int, nargs='+',
        default=range(32),
        help="which chips to check (defaults to all)")
    parser.add_argument("--channels", type=int, nargs='+', default=range(32),
        help="which channels (for each chip) to check (defaults to all)")
    parser.add_argument("-s", "--samples", type=int, default=15000,
        help="how many samples to measure")
    parser.add_argument("-p", "--pause", type=float, default=0.5,
        help="how long to pause before capturing samples (per channel)")
    parser.add_argument("-m", "--currentmode",
        choices=['low', 'medium', 'high'],
        default='low', help="strength of injected DAC current")
    parser.add_argument("-f", "--force", action="store_true",
        help="collect measurements regardless of chip_alive status")
    parser.add_argument("-k", "--keepfiles", action="store_true",
        help="don't delete temporary HDF5 files from disk")
   
    args = parser.parse_args()
    if len(args.chips) == 0:
        print("fail: need to test at least one chip")
        sys.exit(-1)
    if len(args.channels) == 0:
        print("fail: need to test at least one channel")
        sys.exit(-1)
    bad_numbers = [c for c in (args.chips+args.channels) if (c<0 or c>=32)]
    if len(bad_numbers) != 0:
        print("fail: bad chip or channel indexes: %s" % bad_numbers)
        sys.exit(-1)
    run(**(args.__dict__))

if __name__ == '__main__':
    main()

