/* Copyright (c) 2021, Ericsson Software Technology
 *
 * Copying and distribution of this file, with or without modification,
 * are permitted in any medium without royalty provided the copyright
 * notice and this notice are preserved.  This file is offered as-is,
 * without any warranty. */

/* This include order verifies that we can include `pcap/bpf.h` before `net/bpf.h` */
#include "pcap-helpers.h"
#include <net/bpf.h>
#include <net/bpfjit.h>

#include <assert.h>
#include <sys/socket.h>
#include <sys/types.h>

/* Compile a PCAP filter expression to a BPF filter. */
struct bpf_program* pcap_filter_compile(const char* filter, size_t snaplen) {
    int linktype = 1;  /* LINKTYPE_ETHERNET */
    int optimize = 1;
    bpf_u_int32 mask = 0xffffffff;

    struct bpf_program *program = malloc(sizeof(struct bpf_program));
    assert(program);

    pcap_t *p = pcap_open_dead(linktype, snaplen);
    assert(p);
    int ret = pcap_compile(p, program, filter, optimize, mask);
    assert(ret >= 0);
    pcap_close(p);

    return program;
}

/* Free bpf_program memory */
void pcap_free_program(struct bpf_program *program) {
    pcap_freecode(program);
    free(program);
}

/* Create a new BPF program instance.
 * This function only exist to test the include order
 * of libpcap's header pcap/bpf.h and our net/bpf.h */
void* bpf_program_create(const struct bpf_insn* instructions, size_t count) {
    return bpfjit_generate_code(NULL, instructions, count);
}
