What's this?
------------

This is the source code repository for the project codenamed
"Wired-Leaf". To build, install scons and run

    $ scons

from this directory. The output will go under build/.

Build dependencies
------------------

- scons

- HDF5

- Google protocol buffers (libprotobuf)

- C bindings to protobuf (protobuf-c), and compiler

- Python bindings for protobuf (protobuf), and compiler

- python

- check: unit test framework for C, http://check.sourceforge.net/.
  This is only required to build the test cases, not the daemon
  itself. To skip building the test cases, build with:

    $ scons SKIP_TESTS=y

- libevent

On Ubuntu 12.04, the mandatory build dependencies are:

   $ sudo apt-get install libprotobuf-dev libprotobuf-c0-dev \
        libhdf5-serial-dev protobuf-c-compiler scons python \
        protobuf-c-compiler protobuf-compiler libevent-dev

The optional build dependencies (you can still build the daemon
without these, but you won't be able to build tests or run Python
scripts that speak protobuf):

   $ sudo apt-get install check python-protobuf

Other useful tools
------------------

HDF5 tools and Java-based file viewer:

$ sudo apt-get install hdf5-tools hdfviewer

Python dependencies for contrib/plot_hdf5.py:

$ sudo apt-get install python-h5py python-matplotlib

Repository contents
-------------------

- README.txt: this file.

- SConstruct, site_scons/: build system files.

- lib/: Helper libraries used by the daemon.

- libsng/: Sources for shared library used by SNG to interact with the daemon.

- proto/: Google protobuf message files. These are kept separate from
  the source tree, as we may need to share them with others.

  The build system takes care of ensuring that the generated headers
  are available ("proto/foo.proto" gets included as
  "proto/foo.pb-c.h") and that the generated C sources get built and
  linked into the final program.

- src/: daemon source code; uses contents of lib/.

- test/: Test cases and utilities, one per subdirectory. These use the contents
  of lib/, and may run and interact with the daemon as built from src/.
