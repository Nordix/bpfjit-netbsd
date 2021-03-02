/* Copyright (c) 2021, Ericsson Software Technology
 *
 * Copying and distribution of this file, with or without modification,
 * are permitted in any medium without royalty provided the copyright
 * notice and this notice are preserved.  This file is offered as-is,
 * without any warranty. */

#include <assert.h>
#include <stdint.h>
#include <sys/types.h>
#include <net/bpf.h>
#include <net/bpfjit.h>

#include "pcap-helpers.h"

/* Helper for calling a filter function. */
static inline
unsigned int jitcall(bpfjit_func_t fn, const uint8_t *pkt,
                     unsigned int wirelen, unsigned int buflen) {
    bpf_args_t args;

    args.pkt = pkt;
    args.wirelen = wirelen;
    args.buflen = buflen;

    return fn(NULL, &args);
}

/* Test of compiling a pcap filter and generating a filter function. */
void tc_generate_libpcap_filter_function() {

    struct bpf_program *program;
    const char *filter = "udp port 123"; /* ntp */
    int snaplen = 65535;

    /* Compile filter */
    program = pcap_filter_compile(filter, snaplen);
    assert(program);

    /* Generate function */
    bpfjit_func_t code;
    code = (bpfjit_func_t)bpf_program_create(program->bf_insns, program->bf_len);

    /* Test of generated filter function */

    /* UDP package: 216.27.185.42 → 192.168.50.50 NTP NTP Version 3 */
    /* Paste and decode at https://hpd.gasmi.net/ */
    uint8_t pkt[90] = {
        0x00, 0xd0, 0x59, 0x6c, 0x40, 0x4e, 0x00, 0x0c, 0x41, 0x82, 0xb2, 0x53,
        0x08, 0x00, 0x45, 0x00, 0x00, 0x4c, 0xa2, 0x22, 0x40, 0x00, 0x32, 0x11,
        0x22, 0x5e, 0xd8, 0x1b, 0xb9, 0x2a, 0xc0, 0xa8, 0x32, 0x32, 0x00, 0x7b,
        0x00, 0x7b, 0x00, 0x38, 0x70, 0xe1, 0x1a, 0x02, 0x0a, 0xee, 0x00, 0x00,
        0x07, 0xa4, 0x00, 0x00, 0x0b, 0xa3, 0xa4, 0x43, 0x3e, 0xc2, 0xc5, 0x02,
        0x01, 0x81, 0xe5, 0x79, 0x18, 0x19, 0xc5, 0x02, 0x04, 0xec, 0xec, 0x42,
        0xee, 0x92, 0xc5, 0x02, 0x04, 0xeb, 0xd9, 0x5e, 0x8d, 0x54, 0xc5, 0x02,
        0x04, 0xeb, 0xd9, 0x69, 0xb1, 0x74};

    assert(jitcall(code, pkt, 1, 1) == 0);   // No match after first byte
    assert(jitcall(code, pkt, 35, 35) == 0); // ..
    assert(jitcall(code, pkt, 36, 36) != 0); // Match after source port = 123
    assert(jitcall(code, pkt, 90, 90) != 0); // ..

    bpfjit_free_code(code);
    pcap_free_program(program);
}

int main(int argc, char *argv[]) {

    tc_generate_libpcap_filter_function();

    return 0;
}
