This is bpfjit extracted from NetBSD.

bpfjit = Just-In-Time compiler for Berkeley Packet Filter

Manpage: https://man.netbsd.org/bpfjit.4

bpfjit depends on sljit: https://github.com/zherczeg/sljit/

This repo contains the bpfjit files and their history extracted from the NetBSD
repo at https://github.com/NetBSD/src. The files are patched to be able
to build using the latest sljit. See the script `update.sh` for details
about code changes and how the file history is extracted.

TODO:

- Add Makefile.
