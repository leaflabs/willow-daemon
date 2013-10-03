#!/usr/bin/env python
"""
Copyright: (C) 2013 LeafLabs, LLC
License: MIT License
Author: bnewbold
Date: September 2013
Project: SNG Wired Leaf (SNG4)

This is a script to measure probe impedances on a per-channel basis.

DO NOT run this script during acquisition to disk or readback from disk.

This script requires the h5py and numpy packages. On debian::

    apt-get install python-h5py python-numpy

Impedance Measurement Recipe (paraphrased):

    1. sanity check datanode status
    2. start streaming
    3. setup channels for first channel (all chips)
    4. collect ~0.5 seconds of contiguous data for channel (across all chips)
    5. run FFT on each returned channel, store result
    6. setup next chip and back to #4
    7. when done, return channel map to defaults and stop streaming

TODO:
 - impedance calculation should be reviewed by SNG staff.
 - currently full-sample streams are saved to disk, even though only sub-sample
   streams are required. this is an open feature request for the daemon.
 - loading and re-ordering HDF5 data is super slow. scales with number of chips 
   being measured.
 - there are several magic numbers sprinkled around, eg to decode the command
   status enum. these should be replaced with human readable values. see TODO
   tags.
 - as an extra feature, the ability to automatically tune the capacitorscale
   parameter and re-run impedance measurements to get the most accurate
   measurement.

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


# ========== Calculations =========== #
def volts2impedance(volts, capacitorscale):
    """
    See pages 28 to 30 of the Intan RHD2000 Series datasheet.

    Formula for impedance:

        (impedance ohms) = (amplitude volts) / (current amps)

    The example given in the Intan datasheet is that with the 1.0pF capacitor
    selected (capacitorscale=1), a 1MOhm total impedance would result in a
    3.8mV signal amplitude.

    This conversion assumes:
      - 1kHz sine max amplitude DAC waveform
      - "normal" ADC and amplifier configuration
    """
    cap2current = {0: 0.38 * 10**-9,  # 0.1pF capacitor
                   1: 3.8 * 10**-9,   # 1.0pF capacitor
                   3: 38.0 * 10**-9}  # 10.0pF capacitor

    if volts < 10**-6:
        # dodge a divide-by-zero or numerical glitch
        return 'open (null data)'

    impedance = volts / cap2current[capacitorscale]

    if impedance > 10**7:
        # above 10 MOhm, assume we've got an open circuit 
        return 'open (> 10 MOhm)'
    elif impedance <= 0.1: # very small, probably numerical
        return 'short (< 0.1 Ohm)'
    else:
        return impedance

def amp2volts(amplitude, nsamples):
    """
    Converts a complex FFT amplitude at 1KHz to a sinewave amplitude in volts
    (normal amplitude, not peak-to-peak).

    The conversion factor between ADC counts and volts is 0.195 microvolts per
    count.
    """
    return abs(amplitude * 2 / nsamples) * 0.195 * 10**-6

def calculate_impedences(waveforms, capacitorscale, verbose=False):
    """
    This function iterates through all the waveforms passed in, and for each
    calculates the 1kHz sine amplitude present (using an FFT), and then
    calculates the probe impedance in Ohms from that.

        waveforms: a dictionary with integer keys corresponding to chip indexes
            and values as single dimensional 16bit unsigned integer numpy
            arrays (waveform data)
        capacitorscale: the Intan capacitor selection register (passed through
            to amplitude2impedance)

    Returns a dictionary with integer keys (chip indexes) and values that are a
    3-tuple of the measured impedance in Ohms, the 1kHz sine-wave
    amplitude (not peak to peak), and  the complex FFT amplitude at 1Khz. The
    impedance value is either a float or a string starting with 'open' or
    'short'.

    This function can be tested with the following snippet, which should report
    an impedance of about 1MOhm. It generates a 3.8mV 1kHz sine waveform and
    calculates the impedance assuming the 1.0pF capacitor was selected.

        >>> w = [int((numpy.sin(t*3.141592/15)*3.8*0.001/(0.195*10**-6)))
               +2**15+numpy.random.random_integers(-20,20)
               for t in range(15000)]
        >>> calculate_impedences({5:w}, 1, True)
        {5: (999968.20706330962,
          0.0037998791868405768,
          (-46838.651388999962-142495461.80852485j))}

    """
    if verbose:
        for k in waveforms.keys():
            print("\t\tChip %d values: %d %d %d ..." % (k,
                waveforms[k][0],
                waveforms[k][1],
                waveforms[k][2],))
    amplitudes = dict()
    for k in waveforms.keys():
        wf = waveforms[k]
        onekhz_index = int(1000 * len(wf)/30000)
        fourier = numpy.fft.rfft(wf)
        #freqs = numpy.fft.fftfreq(wf.size, d=1/30000.)
        #print("%d: %f" % (onekhz_index, freqs[onekhz_index]))
        onekhz_amp = fourier[onekhz_index]
        volts = amp2volts(onekhz_amp, len(wf))
        amplitudes[k] = (volts2impedance(volts, capacitorscale),
                         volts,
                         onekhz_amp)
    return amplitudes

# ========== Helpers =========== #
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

def load_chip_data_from_hdf5(fpath, chips, channel):
    data = dict()
    with h5py.File(fpath, 'r', driver='core') as f:
        d = f['wired-dataset']
        count = d.shape[0]
        for c in chips:
            data[c] = numpy.zeros((count,), dtype='u2')
        print("\tLoading and re-ordering data (slow!)...")
        for i in range(count):
            for c in chips:
                data[c][i] = d[i][3][c*32 + channel]
        """ DEBUG
        i = 0
        for sample in d:
            print sample[3][0]
            for c in chips:
                data[c][i] = sample[3][c]
            i = i+1
        """
    return data

def process_data(fpath, chips, capacitorscale, channel, verbose=False):
    data = load_chip_data_from_hdf5(fpath, chips, channel)
    print("\tCalculating impedances...")
    results = calculate_impedences(data, capacitorscale, verbose)
    if verbose:
        for k in chips:
            print("\t\tChip %02d: %s" % (k, results[k]))
    return results

# ========== Commands =========== #

def run(chips, channels, samples, pause, capacitorscale, force=False,
        keepfiles=False, verbose=False):
    capacitorscale = {"low":0, "medium":1, "high":3}[capacitorscale]
    if verbose:
        print("chips: %s" % chips)
        print("channels: %s" % channels)
        print("samples: %s" % samples)
        print("pause: %s" % pause)
        print("capacitorscale: " + bin(capacitorscale))
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
        configure_dac(True, True, capacitorscale, False, chan)
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
        results[chan]= process_data(fpath, chips, capacitorscale, chan, verbose)
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
            print("\tChannel %02d: %s" % (channel, results[channel][chip][0]))
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
    parser.add_argument("-m", "--capacitorscale",
        choices=['low', 'medium', 'high'],
        default='low', help="determines the strength of injected DAC current")
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

