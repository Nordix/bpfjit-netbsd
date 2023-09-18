# Copyright (c) 2021, Ericsson Software Technology
#
# Copying and distribution of this file, with or without modification,
# are permitted in any medium without royalty provided the copyright
# notice and this notice are preserved.  This file is offered as-is,
# without any warranty.

PREFIX?=/usr/local
CPPFLAGS += -Isrc/ -I$(DESTDIR)$(PREFIX)/include/
CFLAGS += -O2 -Wall -Werror

# The sljit commit (hash, branch or tag) that is downloaded and installed
# by the make target: install-sljit
USE_SLJIT_COMMIT?=master

lib=libbpfjit.a
src=src/net/bpfjit.c
headers=src/net/bpf.h src/net/bpfjit.h

obj=$(src:.c=.o)

$(lib): $(obj)
	$(AR) rcs $@ $^

.PHONY: install
install: $(lib)
	install -d $(DESTDIR)$(PREFIX)/lib
	install -m 644 $(lib) $(DESTDIR)$(PREFIX)/lib
	install -d $(DESTDIR)$(PREFIX)/include/net
	install -m 644 $(headers) $(DESTDIR)$(PREFIX)/include/net

# Optional:
# Download, build and install dependency sljit

sljit = libsljit.a

$(sljit):
	curl -L https://github.com/zherczeg/sljit/archive/$(USE_SLJIT_COMMIT).tar.gz | \
		tar xz --one-top-level=sljit --strip=1
	$(MAKE) -C sljit
	$(AR) rvs $@ sljit/bin/sljitLir.o

.PHONY: install-sljit
install-sljit: $(sljit)
	install -d $(DESTDIR)$(PREFIX)/lib
	install -m 644 $(sljit) $(DESTDIR)$(PREFIX)/lib
	install -d $(DESTDIR)$(PREFIX)/include
	install -m 644 sljit/sljit_src/sljitLir.h \
                       sljit/sljit_src/sljitConfig.h \
                       sljit/sljit_src/sljitConfigInternal.h \
                       sljit/sljit_src/sljitConfigCPU.h \
                       $(DESTDIR)$(PREFIX)/include

# Test of library

bpfjit-test: test/test.o
	$(CC) $< -o $@ -L$(DESTDIR)$(PREFIX)/lib -lbpfjit -lsljit

bpfjit-test-with-pcap: test/test-with-pcap.o test/pcap-helpers.o
	$(CC) $^ -o $@ -L$(DESTDIR)$(PREFIX)/lib -Wl,-rpath=$(DESTDIR)$(PREFIX)/lib -lbpfjit -lsljit -lpcap

.PHONY: test
test: bpfjit-test
	./bpfjit-test

.PHONY: test-with-pcap
test-with-pcap: bpfjit-test-with-pcap
	./bpfjit-test-with-pcap

.PHONY: clean
clean:
	rm -rf $(obj) $(lib) bpfjit-test bpfjit-test-with-pcap sljit $(sljit) \
		test/test.o test/test-with-pcap.o test/pcap-helpers.o
