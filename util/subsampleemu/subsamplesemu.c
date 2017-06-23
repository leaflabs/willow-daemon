/* Copyright (c) 2017 LeafLabs, LLC.
 *
 * This program is free software: you can redistribute it and/or
 * modify it under the terms of version 2 of the GNU General Public
 * License as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

/*
 * subsampleemu: a subsamples stream emulator
 *
 * subsampleemu is a tool that writes an emulated subsamples stream to
 * stdout, as would be output by proto2bytes.
 *
 * The emulated stream contains a 12 bit-excursion 1 Khz sine wave in
 * channel 0, with channels 1 through 31 containing the value 0.  The
 * samples are represented as 16-bit unsigned integers, to match the
 * sample format of the Willow datanode.
 */

#include <pulse/simple.h>
#include <pulse/error.h>
#include <pulse/gccmacro.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <math.h>
#include <time.h>
#include <string.h>

#define FREQUENCY 1000
#define SAMPLE_SEND_HZ 20
#define NUMBERSECOND 10
#define SAMPLE_RATE 30000
#define BLOCKSIZE (SAMPLE_RATE/FREQUENCY * 50)
#define CHANNELS_PER_CHIP 32

uint16_t outbuf[CHANNELS_PER_CHIP * BLOCKSIZE];

int main (int argc, char **argv) {
  size_t i;
  int ret = 1;

  if (argc == 1 || (argc == 2 && !strcmp(argv[1], "-A"))) {
    /*
     * We allow a "-A" argument for compatibility with the
     * streaming plugins.
     */
  } else {
    fprintf(stderr, "usage: %s [-A]\n", argv[0]);
    goto done;
  }

  /*
   * precompute a sine wave while striding through
   * outbuf to populate willow subchannel 0
   */
  for (i = 0; i < (sizeof(outbuf) / sizeof(int16_t));
                   i += CHANNELS_PER_CHIP) {
    /* scale to 16 bits and convert to unsigned to match datanode */
    outbuf[i] = (uint16_t)((1 << 12) *
                sinf(FREQUENCY * 2.0 * M_PI *
                     (float)(i / CHANNELS_PER_CHIP) / (float)(SAMPLE_RATE)) -
                (1 << 15));
  }

  /*
   * output the emulated subsamples stream continuously
   */
  while(1) {
    if (write(STDOUT_FILENO, outbuf, sizeof(outbuf)) < 0) {
      goto done;
    }
  }
  ret = 0;

done:
  return ret;
}
