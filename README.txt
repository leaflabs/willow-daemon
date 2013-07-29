This are the sources for leafysd, the WiredLeaf electrophysiology daemon.

For the impatient
-----------------

On Ubuntu 12.04:

1. Install mandatory dependencies:

    $ sudo apt-get install libprotobuf-dev libprotobuf-c0-dev \
         libhdf5-serial-dev protobuf-c-compiler scons python \
         libevent-dev

2. Install optional dependencies:

    $ sudo apt-get install check python-protobuf protobuf-compiler \
         python-h5py python-matplotlib

3. Compile everything:

    $ scons

4. Now you can run the daemon, ./build/leafysd. Use "./build/leafysd -h" for
   help with command line arguments.

You can install some useful programs later, if you want:

   $ sudo apt-get install hdf5-tools hdfviewer

Mandatory dependencies
----------------------

You can't build the daemon without these. If you only install these, you can
build just the daemon with

    $ scons SKIP_TESTS=1 SKIP_UTIL=1

The compiled daemon is build/leafysd. The shared library and its headers are in
build/libsng.

- scons:
  http://www.scons.org/

- HDF5's C library:
  http://www.hdfgroup.org/

- Google's protocol buffers (libprotobuf) and compiler:
  https://code.google.com/p/protobuf/

- C bindings to protobuf (protobuf-c), and compiler:
  https://code.google.com/p/protobuf-c/

- Python 2.7 (_not_ 3):
  http://www.python.org/

- libevent:
  http://libevent.org/

Optional dependencies and useful tools
--------------------------------------

You can build the daemon without these, but you won't be able to run tests or
use the utility programs (under util/). With these installed, you can build
everything with

    $ scons

- check: unit test framework for C:
  http://check.sourceforge.net/.

- Google's protocol buffer Python bindings and compiler:
  https://code.google.com/p/protobuf/

- Python bindings to the HDF5 library:
  https://code.google.com/p/h5py/

- Python matplotlib, for graphing HDF5 file contents:
  http://matplotlib.org/

- HDF5's command line utilities (h5*) and Java-based file viewer (hdfviewer):
  http://www.hdfgroup.org/downloads/index.html

Repository contents
-------------------

- README.txt: this file.

- SConstruct, site_scons/: build system files.

- lib/: Helper libraries used by the daemon and libsng.

- libsng/: Sources for shared library used by SNG to interact with the daemon.

- proto/: Google protobuf message files. These are kept separate from
  the source tree, as we may need to share them with others.

  The build system takes care of ensuring that the generated headers
  are available ("proto/foo.proto" gets included as
  "proto/foo.pb-c.h") and that the generated C sources get built and
  linked into the final program.

- src/: Daemon source code.

- test/: Test code.

  To run tests, run scons, then run build/run_tests.py:

      $ scons
      $ ./build/run-tests.py

  Tests written in C are placed in subdirectories that begin with
  'test-'. Tests written in Python are executable scripts that begin with
  'test_' and end with '.py'.

  Tests may use the headers provided by lib/ and libsng/. They may run the
  compiled daemon and any of the utilities in util/.

  Test programs are a pain to run individually; they need a special
  environment. Use run-tests.py.

- util/: Miscellaneous helper utilities.
