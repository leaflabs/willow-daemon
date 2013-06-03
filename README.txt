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

- python

- check: unit test framework for C, http://check.sourceforge.net/.
  This is only required to build the test cases, not the daemon
  itself. To skip building the test cases, build with:

    $ scons SKIP_TESTS=y

- libevent

On Ubuntu 12.04:

   $ sudo apt-get install libprotobuf-dev libprotobuf-c0-dev \
        libhdf5-serial-dev protobuf-c-compiler scons python check \
        protobuf-c-compiler protobuf-compiler libevent-dev

Repository contents
-------------------

- README.txt: this file.

- SConstruct, site_scons/: build system files.

- lib/: Helper libraries used by the daemon.

- proto/: Google protobuf message files. These are kept separate from
  the source tree, as we may need to share them with others.

  The build system takes care of ensuring that the generated headers
  are available ("proto/foo.proto" gets included as
  "proto/foo.pb-c.h") and that the generated C sources get built and
  linked into the final program.

- src/: daemon source code; uses contents of lib/.

- test/: Test cases, one per subdirectory. These use the contents of
  lib/, and may run and interact with the daemon as built from src/.
