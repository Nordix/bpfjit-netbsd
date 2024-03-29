# bpfjit

Just-In-Time compiler for Berkeley Packet Filter extracted from NetBSD.

Manpage: https://man.netbsd.org/bpfjit.4

bpfjit depends on sljit: https://github.com/zherczeg/sljit/

This repo contains the bpfjit files and their history extracted from the NetBSD
repo at https://github.com/NetBSD/src. The files are patched to be able to build
using the latest version of sljit. There are also some changes to be able to use
this library together with libpcap.

See the script `update.sh` for details about how the file history is extracted,
and the patch files in `patches/` for reason of each change.

## Build configurations

Bpfjit can be configured at build time using following defines:

* `SLJIT_VERBOSE` - Enabled by default in sljit

  Unless disabled bpfjit will print generated machine code to stderr.
  Recommended to be disabled in production and requires disabling in **both** bpfjit and sljit.

* `BPFJIT_USE_UDIV` - Disabled by default in bpfjit

  Generate *udiv* instructions instead of function calls for divide or modulus handling.

## Build using Make

Building bpfjit requires a static library `sljit` and its header files to be
installed on the system. The Makefile provides build targets to build and
install `sljit` for testing.

```
# Optional:
# Download, build and install dependency sljit
sudo make EXTRA_CPPFLAGS="-DSLJIT_VERBOSE=0" install-sljit

# Build and install bpfjit
sudo make CPPFLAGS="-DSLJIT_VERBOSE=0" install
```

The libraries can also be built and installed to a local directory,
this avoids the need of `sudo`:

```
# Prepare a local installation
mkdir /tmp/stage

# Download, build and install dependency sljit
PREFIX=/tmp/stage make install-sljit

# Build and install bpfjit
PREFIX=/tmp/stage make install

# Optional: Build and run tests
PREFIX=/tmp/stage make test

# Optional: Build and run tests that requires package `libpcap-dev`
PREFIX=/tmp/stage make test-with-pcap
```

## Build using CMake

The library can also be built using CMake and the configs provides
build and install targets. During the build generation step the
dependency `sljit` with be searched for and needs to be installed
on the system as a prerequisite.

```
# Optional:
# Download, build and install dependency sljit
sudo make EXTRA_CPPFLAGS="-DSLJIT_VERBOSE=0" install-sljit

# Build bpjfit
mkdir -p build && cd build
cmake -D CMAKE_C_FLAGS="-DSLJIT_VERBOSE=0" ..
make

# Install bpfjit
sudo make install
```

The library can also be installed to a local directory,
this avoids the need of `sudo` and both DESTDIR and prefix are
handled.

```
# Prepare a local installation
mkdir /tmp/stage

# Download, build and install dependency sljit
PREFIX=/tmp/stage make install-sljit

# Build bpfjit
mkdir -p build && cd build
cmake -DCMAKE_PREFIX_PATH=/tmp/stage ..
make

# Install bpfjit using prefix
# This avoids usage of paths containing `/usr/local/`
cmake --install . --prefix /tmp/stage

# Optional: Build and run tests
make bpfjit-test
./bpfjit-test

# Optional: Build and run tests that requires package `libpcap-dev`
make bpfjit-test-with-pcap
./bpfjit-test-with-pcap
```
