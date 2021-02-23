PREFIX?=/usr/local
CPPFLAGS += -Isrc/ -I$(DESTDIR)$(PREFIX)/include/
CFLAGS += -O2 -Wall

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
	curl -L https://github.com/zherczeg/sljit/archive/master.tar.gz | \
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
                       $(DESTDIR)$(PREFIX)/include

# Test of library

bpfjit-test: test/main.o
	$(CC) $< -o $@ -L$(DESTDIR)$(PREFIX)/lib -lbpfjit -lsljit

.PHONY: test
test: bpfjit-test
	./bpfjit-test

.PHONY: clean
clean:
	rm -rf $(obj) $(lib) bpfjit-test sljit $(sljit) test/main.o
