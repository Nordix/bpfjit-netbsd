This is bpfjit extracted from NetBSD.

bpfjit = Just-In-Time compiler for Berkeley Packet Filter

Manpage: https://man.netbsd.org/bpfjit.4

bpfjit depends on sljit: https://github.com/zherczeg/sljit/

This repo contains the bpfjit files and their history extracted from the NetBSD
repo at https://github.com/NetBSD/src. See the script `update.sh` for details
about how their history is extracted.

TODO:

- Add Makefile.

- Make sure bpfjit can be built using the latest sljit. (Add minimal patch if
  necessary.)
