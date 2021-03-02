/* Copyright (c) 2021, Ericsson Software Technology
 *
 * Copying and distribution of this file, with or without modification,
 * are permitted in any medium without royalty provided the copyright
 * notice and this notice are preserved.  This file is offered as-is,
 * without any warranty. */

#ifndef _PCAP_HELPERS_H_
#define _PCAP_HELPERS_H_

#include <stdint.h>
#include <stdlib.h>

/* This will verify that we can include `pcap/bpf.h` before `net/bpf.h` */
#include <pcap/bpf.h>
#include <pcap/pcap.h>

/**
 * Compile a PCAP filter expression to a BPF filter.
 * filter:  Packet filter according to pcap-filter(7).
 * snaplen: Snapshot length in bytes.
 */
struct bpf_program*
pcap_filter_compile(const char* filter, size_t snaplen);

/**
 * Free bpf_program memory
 * program: BPF instruction stream.
 **/
void
pcap_free_program(struct bpf_program *program);

/**
 * Create a new BPF program instance.
 * instructions: BPF instruction stream.
 * count: Number of instructions in stream.
 * Returns a PCAP program instance, or NULL on failure.
 */
void*
bpf_program_create(const struct bpf_insn* instructions, size_t count);

#endif /* _PCAP_HELPERS_H_ */
