# bpfjit

Just-In-Time compiler for Berkeley Packet Filter extracted from NetBSD.

Manpage: https://man.netbsd.org/bpfjit.4

bpfjit depends on sljit: https://github.com/zherczeg/sljit/

This repo contains the bpfjit files and their history extracted from the NetBSD
repo at https://github.com/NetBSD/src. The files are patched to be able
to build using the latest sljit. See the script `update.sh` for details
about code changes and how the file history is extracted.

## Build using Make

Building bpfjit requires a static library `sljit` and its header files to be
installed on the system. The Makefile provides build targets to build and
install `sljit` for testing.

```
# Optional:
# Download, build and install dependency sljit
sudo make install-sljit

# Build and install bpjit
sudo make install
```

The libraries can also be built and installed to a local directory,
this avoids the need of `sudo`:

```
# Prepare a local installation
mkdir /tmp/stage

# Download, build and install dependency sljit
PREFIX=/tmp/stage make install-sljit

# Build and install bpjit
PREFIX=/tmp/stage make install

# Build and run test
PREFIX=/tmp/stage make test
```
