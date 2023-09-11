/* Copyright (c) 2021, Ericsson Software Technology
 *
 * Copying and distribution of this file, with or without modification,
 * are permitted in any medium without royalty provided the copyright
 * notice and this notice are preserved.  This file is offered as-is,
 * without any warranty. */

#include <assert.h>
#include <stdint.h>
#include <string.h>
#include <sys/types.h>
#include <net/bpf.h>
#include <net/bpfjit.h>

static uint8_t deadbeef_at_5[16] = {
    0, 0xf1, 2, 0xf3, 4, 0xde, 0xad, 0xbe, 0xef, 0xff
};

/*
 * Compile and run a filter program.
 */
static inline unsigned int
exec_prog(struct bpf_insn *insns, size_t insn_count, unsigned char pkt[],
          size_t pktsize) {
    bpfjit_func_t fn;
    bpf_args_t args;
    unsigned int res;

    args.pkt = (const uint8_t *)pkt;
    args.buflen = pktsize;
    args.wirelen = pktsize;

    fn = bpfjit_generate_code(NULL, insns, insn_count);

    res = fn(NULL, &args);

    bpfjit_free_code(fn);

    return res;
}

static inline
unsigned int jitcall(bpfjit_func_t fn, const uint8_t *pkt, unsigned int wirelen,
                     unsigned int buflen) {
    bpf_args_t args;

    args.pkt = pkt;
    args.wirelen = wirelen;
    args.buflen = buflen;

    return fn(NULL, &args);
}

/*
 * Testcases
 */

/* Test that JIT compilation of an empty bpf program fails */
void tc_bpfjit_empty() {
    struct bpf_insn dummy = {};
    bpfjit_func_t code;

    code = bpfjit_generate_code(NULL, &dummy, 0);
    assert(code == NULL);
}

/* Test JIT compilation of a trivial bpf program */
void tc_bpfjit_ret_k() {
    static struct bpf_insn insns[] = {
        BPF_STMT(BPF_RET+BPF_K, 17)
    };

    uint8_t pkt[1]; /* the program doesn't read any data */
    size_t insn_count = sizeof(insns) / sizeof(insns[0]);

    assert(exec_prog(insns, insn_count, pkt, 1) == 17);
}

/* Test JIT compilation of a program with bad BPF_RET fails */
void tc_bpfjit_bad_ret_k() {
    static struct bpf_insn insns[] = {
        BPF_STMT(BPF_RET+BPF_K+0x8000, 13)
    };

    size_t insn_count = sizeof(insns) / sizeof(insns[0]);

    uint8_t pkt[1]; /* the program doesn't read any data */

    /*
     * The point of this test is checking a bad instruction of
     * a valid class and with a valid BPF_RVAL data.
     */
    const uint16_t rcode = insns[0].code;
    assert(BPF_CLASS(rcode) == BPF_RET &&
           (BPF_RVAL(rcode) == BPF_K || BPF_RVAL(rcode) == BPF_A));

    /* Current implementation generates code. */
    assert(exec_prog(insns, insn_count, pkt, 1) == 13);
}

/* Test JIT compilation of BPF_ALU+BPF_ADD+BPF_K */
void tc_bpfjit_alu_add_k() {
    static struct bpf_insn insns[] = {
        BPF_STMT(BPF_LD+BPF_IMM, 3),
        BPF_STMT(BPF_ALU+BPF_ADD+BPF_K, 2),
        BPF_STMT(BPF_RET+BPF_A, 0)
    };

    uint8_t pkt[1]; /* the program doesn't read any data */
    size_t insn_count = sizeof(insns) / sizeof(insns[0]);

    assert(exec_prog(insns, insn_count, pkt, 1) == 5);
}

/* Test JIT compilation of BPF_ALU+BPF_SUB+BPF_K */
void tc_bpfjit_alu_sub_k() {
    static struct bpf_insn insns[] = {
        BPF_STMT(BPF_LD+BPF_IMM, 1),
        BPF_STMT(BPF_ALU+BPF_SUB+BPF_K, 2),
        BPF_STMT(BPF_RET+BPF_A, 0)
    };

    uint8_t pkt[1]; /* the program doesn't read any data */
    size_t insn_count = sizeof(insns) / sizeof(insns[0]);

    assert(exec_prog(insns, insn_count, pkt, 1) == UINT32_MAX);
}

/* Test JIT compilation of BPF_ALU+BPF_MUL+BPF_K */
void tc_bpfjit_alu_mul_k() {
    static struct bpf_insn insns[] = {
        BPF_STMT(BPF_LD+BPF_IMM, UINT32_C(0xffffffff)),
        BPF_STMT(BPF_ALU+BPF_MUL+BPF_K, 3),
        BPF_STMT(BPF_RET+BPF_A, 0)
    };

    uint8_t pkt[1]; /* the program doesn't read any data */
    size_t insn_count = sizeof(insns) / sizeof(insns[0]);

    assert(exec_prog(insns, insn_count, pkt, 1) == 0xfffffffd);
}

/* Test JIT compilation of BPF_ALU+BPF_DIV+BPF_K with k=0 */
void tc_bpfjit_alu_div0_k() {
    static struct bpf_insn insns[] = {
        BPF_STMT(BPF_ALU+BPF_DIV+BPF_K, 0),
        BPF_STMT(BPF_RET+BPF_A, 0)
    };

    uint8_t pkt[1]; /* the program doesn't read any data */
    size_t insn_count = sizeof(insns) / sizeof(insns[0]);

    assert(exec_prog(insns, insn_count, pkt, 1) == 0);
}

/* Test JIT compilation of BPF_ALU+BPF_DIV+BPF_K with k=1 */
void tc_bpfjit_alu_div1_k() {
    static struct bpf_insn insns[] = {
        BPF_STMT(BPF_LD+BPF_IMM, 7),
        BPF_STMT(BPF_ALU+BPF_DIV+BPF_K, 1),
        BPF_STMT(BPF_RET+BPF_A, 0)
    };

    uint8_t pkt[1]; /* the program doesn't read any data */
    size_t insn_count = sizeof(insns) / sizeof(insns[0]);

    assert(exec_prog(insns, insn_count, pkt, 1) == 7);
}

/* Test JIT compilation of BPF_ALU+BPF_DIV+BPF_K with k=2 */
void tc_bpfjit_alu_div2_k() {
    static struct bpf_insn insns[] = {
        BPF_STMT(BPF_LD+BPF_IMM, 7),
        BPF_STMT(BPF_ALU+BPF_DIV+BPF_K, 2),
        BPF_STMT(BPF_RET+BPF_A, 0)
    };

    uint8_t pkt[1]; /* the program doesn't read any data */
    size_t insn_count = sizeof(insns) / sizeof(insns[0]);

    assert(exec_prog(insns, insn_count, pkt, 1) == 3);
}

/* Test JIT compilation of BPF_ALU+BPF_DIV+BPF_K with k=4 */
void tc_bpfjit_alu_div4_k() {
    static struct bpf_insn insns[] = {
        BPF_STMT(BPF_LD+BPF_IMM, UINT32_C(0xffffffff)),
        BPF_STMT(BPF_ALU+BPF_DIV+BPF_K, 4),
        BPF_STMT(BPF_RET+BPF_A, 0)
    };

    uint8_t pkt[1]; /* the program doesn't read any data */
    size_t insn_count = sizeof(insns) / sizeof(insns[0]);

    assert(exec_prog(insns, insn_count, pkt, 1) == 0x3fffffff);
}

/* Test JIT compilation of BPF_ALU+BPF_DIV+BPF_K with k=10 */
void tc_bpfjit_alu_div10_k() {
    static struct bpf_insn insns[] = {
        BPF_STMT(BPF_LD+BPF_IMM, UINT32_C(4294843849)),
        BPF_STMT(BPF_ALU+BPF_DIV+BPF_K, 10),
        BPF_STMT(BPF_RET+BPF_A, 0)
    };

    uint8_t pkt[1]; /* the program doesn't read any data */
    size_t insn_count = sizeof(insns) / sizeof(insns[0]);

    assert(exec_prog(insns, insn_count, pkt, 1) == 429484384);
}

/* Test JIT compilation of BPF_ALU+BPF_DIV+BPF_K with k=10000 */
void tc_bpfjit_alu_div10000_k() {
    static struct bpf_insn insns[] = {
        BPF_STMT(BPF_LD+BPF_IMM, UINT32_C(4294843849)),
        BPF_STMT(BPF_ALU+BPF_DIV+BPF_K, 10000),
        BPF_STMT(BPF_RET+BPF_A, 0)
    };

    uint8_t pkt[1]; /* the program doesn't read any data */
    size_t insn_count = sizeof(insns) / sizeof(insns[0]);

    assert(exec_prog(insns, insn_count, pkt, 1) == 429484);
}

/* Test JIT compilation of BPF_ALU+BPF_DIV+BPF_K with k=7609801 */
void tc_bpfjit_alu_div7609801_k() {
    static struct bpf_insn insns[] = {
        BPF_STMT(BPF_LD+BPF_IMM, UINT32_C(4294967295)),
        BPF_STMT(BPF_ALU+BPF_DIV+BPF_K, UINT32_C(7609801)),
        BPF_STMT(BPF_RET+BPF_A, 0)
    };

    uint8_t pkt[1]; /* the program doesn't read any data */
    size_t insn_count = sizeof(insns) / sizeof(insns[0]);

    assert(exec_prog(insns, insn_count, pkt, 1) == 564);
}

/* Test JIT compilation of BPF_ALU+BPF_DIV+BPF_K with k=0x80000000 */
void tc_bpfjit_alu_div80000000_k() {
    static struct bpf_insn insns[] = {
        BPF_STMT(BPF_LD+BPF_IMM, UINT32_C(0xffffffde)),
        BPF_STMT(BPF_ALU+BPF_DIV+BPF_K, UINT32_C(0x80000000)),
        BPF_STMT(BPF_RET+BPF_A, 0)
    };

    uint8_t pkt[1]; /* the program doesn't read any data */
    size_t insn_count = sizeof(insns) / sizeof(insns[0]);

    assert(exec_prog(insns, insn_count, pkt, 1) == 1);
}

/* Test JIT compilation of BPF_ALU+BPF_MOD+BPF_K with k=0 */
void tc_bpfjit_alu_mod0_k() {
    static struct bpf_insn insns[] = {
        BPF_STMT(BPF_ALU+BPF_MOD+BPF_K, 0),
        BPF_STMT(BPF_RET+BPF_A, 0)
    };

    uint8_t pkt[1]; /* the program doesn't read any data */
    size_t insn_count = sizeof(insns) / sizeof(insns[0]);

    assert(exec_prog(insns, insn_count, pkt, 1) == 0);
}

/* Test JIT compilation of BPF_ALU+BPF_MOD+BPF_K with k=1 */
void tc_bpfjit_alu_mod1_k() {
    static struct bpf_insn insns[] = {
        BPF_STMT(BPF_LD+BPF_IMM, 7),
        BPF_STMT(BPF_ALU+BPF_MOD+BPF_K, 1),
        BPF_STMT(BPF_RET+BPF_A, 0)
    };

    uint8_t pkt[1]; /* the program doesn't read any data */
    size_t insn_count = sizeof(insns) / sizeof(insns[0]);

    assert(exec_prog(insns, insn_count, pkt, 1) == 0);
}

/* Test JIT compilation of BPF_ALU+BPF_MOD+BPF_K with k=2 */
void tc_bpfjit_alu_mod2_k() {
    static struct bpf_insn insns[] = {
        BPF_STMT(BPF_LD+BPF_IMM, 7),
        BPF_STMT(BPF_ALU+BPF_MOD+BPF_K, 2),
        BPF_STMT(BPF_RET+BPF_A, 0)
    };

    uint8_t pkt[1]; /* the program doesn't read any data */
    size_t insn_count = sizeof(insns) / sizeof(insns[0]);

    assert(exec_prog(insns, insn_count, pkt, 1) == 1);
}

/* Test JIT compilation of BPF_ALU+BPF_MOD+BPF_K with k=4 */
void tc_bpfjit_alu_mod4_k() {
    static struct bpf_insn insns[] = {
        BPF_STMT(BPF_LD+BPF_IMM, UINT32_C(0xffffffff)),
        BPF_STMT(BPF_ALU+BPF_MOD+BPF_K, 4),
        BPF_STMT(BPF_RET+BPF_A, 0)
    };

    uint8_t pkt[1]; /* the program doesn't read any data */
    size_t insn_count = sizeof(insns) / sizeof(insns[0]);

    assert(exec_prog(insns, insn_count, pkt, 1) == 3);
}

/* Test JIT compilation of BPF_ALU+BPF_MOD+BPF_K with k=10 */
void tc_bpfjit_alu_mod10_k() {
    static struct bpf_insn insns[] = {
        BPF_STMT(BPF_LD+BPF_IMM, UINT32_C(4294843849)),
        BPF_STMT(BPF_ALU+BPF_MOD+BPF_K, 10),
        BPF_STMT(BPF_RET+BPF_A, 0)
    };

    uint8_t pkt[1]; /* the program doesn't read any data */
    size_t insn_count = sizeof(insns) / sizeof(insns[0]);

    assert(exec_prog(insns, insn_count, pkt, 1) == 9);
}

/* Test JIT compilation of BPF_ALU+BPF_MOD+BPF_K with k=10000 */
void tc_bpfjit_alu_mod10000_k() {
    static struct bpf_insn insns[] = {
        BPF_STMT(BPF_LD+BPF_IMM, UINT32_C(4294843849)),
        BPF_STMT(BPF_ALU+BPF_MOD+BPF_K, 10000),
        BPF_STMT(BPF_RET+BPF_A, 0)
    };

    uint8_t pkt[1]; /* the program doesn't read any data */
    size_t insn_count = sizeof(insns) / sizeof(insns[0]);

    assert(exec_prog(insns, insn_count, pkt, 1) == 3849);
}

/* Test JIT compilation of BPF_ALU+BPF_MOD+BPF_K with k=7609801 */
void tc_bpfjit_alu_mod7609801_k() {
    static struct bpf_insn insns[] = {
        BPF_STMT(BPF_LD+BPF_IMM, UINT32_C(4294967295)),
        BPF_STMT(BPF_ALU+BPF_MOD+BPF_K, UINT32_C(7609801)),
        BPF_STMT(BPF_RET+BPF_A, 0)
    };

    uint8_t pkt[1]; /* the program doesn't read any data */
    size_t insn_count = sizeof(insns) / sizeof(insns[0]);

    assert(exec_prog(insns, insn_count, pkt, 1) == 3039531);
}
/* Test JIT compilation of BPF_ALU+BPF_MOD+BPF_K with k=80000000 */
void tc_bpfjit_alu_mod80000000_k() {
    static struct bpf_insn insns[] = {
        BPF_STMT(BPF_LD+BPF_IMM, UINT32_C(0xffffffde)),
        BPF_STMT(BPF_ALU+BPF_MOD+BPF_K, UINT32_C(0x80000000)),
        BPF_STMT(BPF_RET+BPF_A, 0)
    };

    uint8_t pkt[1]; /* the program doesn't read any data */
    size_t insn_count = sizeof(insns) / sizeof(insns[0]);

    assert(exec_prog(insns, insn_count, pkt, 1) == UINT32_C(0x7fffffde));
}

/* Test JIT compilation of BPF_ALU+BPF_AND+BPF_K */
void tc_bpfjit_alu_and_k() {
    static struct bpf_insn insns[] = {
        BPF_STMT(BPF_LD+BPF_IMM, 0xdead),
        BPF_STMT(BPF_ALU+BPF_AND+BPF_K, 0xbeef),
        BPF_STMT(BPF_RET+BPF_A, 0)
    };

    uint8_t pkt[1]; /* the program doesn't read any data */
    size_t insn_count = sizeof(insns) / sizeof(insns[0]);

    assert(exec_prog(insns, insn_count, pkt, 1) == (0xdead&0xbeef));
}

/* Test JIT compilation of BPF_ALU+BPF_OR+BPF_K */
void tc_bpfjit_alu_or_k() {
    static struct bpf_insn insns[] = {
        BPF_STMT(BPF_LD+BPF_IMM, 0xdead0000),
        BPF_STMT(BPF_ALU+BPF_OR+BPF_K, 0x0000beef),
        BPF_STMT(BPF_RET+BPF_A, 0)
    };

    uint8_t pkt[1]; /* the program doesn't read any data */
    size_t insn_count = sizeof(insns) / sizeof(insns[0]);

    assert(exec_prog(insns, insn_count, pkt, 1) == 0xdeadbeef);
}

/* Test JIT compilation of BPF_ALU+BPF_XOR+BPF_K */
void tc_bpfjit_alu_xor_k() {
    static struct bpf_insn insns[] = {
        BPF_STMT(BPF_LD+BPF_IMM, 0xdead0f0f),
        BPF_STMT(BPF_ALU+BPF_XOR+BPF_K, 0x0000b1e0),
        BPF_STMT(BPF_RET+BPF_A, 0)
    };

    uint8_t pkt[1]; /* the program doesn't read any data */
    size_t insn_count = sizeof(insns) / sizeof(insns[0]);

    assert(exec_prog(insns, insn_count, pkt, 1) == 0xdeadbeef);
}

/* Test JIT compilation of BPF_ALU+BPF_LSH+BPF_K */
void tc_bpfjit_alu_lsh_k() {
    static struct bpf_insn insns[] = {
        BPF_STMT(BPF_LD+BPF_IMM, 0xdeadbeef),
        BPF_STMT(BPF_ALU+BPF_LSH+BPF_K, 16),
        BPF_STMT(BPF_RET+BPF_A, 0)
    };

    uint8_t pkt[1]; /* the program doesn't read any data */
    size_t insn_count = sizeof(insns) / sizeof(insns[0]);

    assert(exec_prog(insns, insn_count, pkt, 1) == 0xbeef0000);
}

/* Test JIT compilation of BPF_ALU+BPF_LSH+BPF_K  with k=0 */
void tc_bpfjit_alu_lsh0_k() {
    static struct bpf_insn insns[] = {
        BPF_STMT(BPF_LD+BPF_IMM, 0xdeadbeef),
        BPF_STMT(BPF_ALU+BPF_LSH+BPF_K, 0),
        BPF_STMT(BPF_RET+BPF_A, 0)
    };

    uint8_t pkt[1]; /* the program doesn't read any data */
    size_t insn_count = sizeof(insns) / sizeof(insns[0]);

    assert(exec_prog(insns, insn_count, pkt, 1) == 0xdeadbeef);
}

/* Test JIT compilation of BPF_ALU+BPF_RSH+BPF_K */
void tc_bpfjit_alu_rsh_k() {
    static struct bpf_insn insns[] = {
        BPF_STMT(BPF_LD+BPF_IMM, 0xdeadbeef),
        BPF_STMT(BPF_ALU+BPF_RSH+BPF_K, 16),
        BPF_STMT(BPF_RET+BPF_A, 0)
    };

    uint8_t pkt[1]; /* the program doesn't read any data */
    size_t insn_count = sizeof(insns) / sizeof(insns[0]);

    assert(exec_prog(insns, insn_count, pkt, 1) == 0x0000dead);
}

/* Test JIT compilation of BPF_ALU+BPF_RSH+BPF_K with k=0 */
void tc_bpfjit_alu_rsh0_k() {
    static struct bpf_insn insns[] = {
        BPF_STMT(BPF_LD+BPF_IMM, 0xdeadbeef),
        BPF_STMT(BPF_ALU+BPF_RSH+BPF_K, 0),
        BPF_STMT(BPF_RET+BPF_A, 0)
    };

    uint8_t pkt[1]; /* the program doesn't read any data */
    size_t insn_count = sizeof(insns) / sizeof(insns[0]);

    assert(exec_prog(insns, insn_count, pkt, 1) == 0xdeadbeef);
}

/* Test JIT compilation of modulo logic of BPF_ALU+BPF_K operations */
void tc_bpfjit_alu_modulo_k() {
    static struct bpf_insn insns[] = {
        BPF_STMT(BPF_LD+BPF_IMM, UINT32_C(0x7fffff77)),

        /* (7FFFFF77 * 0FFFFF77) = 07FFFFB2,F0004951 */
        BPF_STMT(BPF_ALU+BPF_MUL+BPF_K, UINT32_C(0x0fffff77)),

        /* 07FFFFB2,F0004951 << 1 = 0FFFFF65,E00092A2 */
        BPF_STMT(BPF_ALU+BPF_LSH+BPF_K, 1),

        /* 0FFFFF65,E00092A2 + DDDDDDDD = 0FFFFF66,BDDE707F */
        BPF_STMT(BPF_ALU+BPF_ADD+BPF_K, UINT32_C(0xdddddddd)),

        /* 0FFFFF66,BDDE707F - FFFFFFFF = 0FFFFF65,BDDE7080 */
        BPF_STMT(BPF_ALU+BPF_SUB+BPF_K, UINT32_C(0xffffffff)),

        /* 0FFFFF65,BDDE7080 | 0000030C = 0FFFFF65,BDDE738C */
        BPF_STMT(BPF_ALU+BPF_OR+BPF_K, UINT32_C(0x0000030c)),

        /* -0FFFFF65,BDDE738C mod(2^64) = F000009A,42218C74 */
        BPF_STMT(BPF_ALU+BPF_NEG, 0),

        /* F000009A,42218C74 & FFFFFF0F = F000009A,42218C04 */
        BPF_STMT(BPF_ALU+BPF_AND+BPF_K, UINT32_C(0xffffff0f)),

        /* F000009A,42218C74 >> 3 = 1E000013,48443180 */
        /* 00000000,42218C74 >> 3 = 00000000,08443180 */
        BPF_STMT(BPF_ALU+BPF_RSH+BPF_K, 3),

        /* 00000000,08443180 * 7FFFFF77 = 042218BB,93818280 */
        BPF_STMT(BPF_ALU+BPF_MUL+BPF_K, UINT32_C(0x7fffff77)),

        /* 042218BB,93818280 / DEAD = 000004C0,71CBBBC3 */
        /* 00000000,93818280 / DEAD = 00000000,0000A994 */
        BPF_STMT(BPF_ALU+BPF_DIV+BPF_K, UINT32_C(0xdead)),

        BPF_STMT(BPF_RET+BPF_A, 0)
    };

    bpfjit_func_t code;
    uint8_t pkt[1]; /* the program doesn't read any data */

    size_t insn_count = sizeof(insns) / sizeof(insns[0]);

    code = bpfjit_generate_code(NULL, insns, insn_count);
    assert(code != NULL);

    assert(jitcall(code, pkt, 1, 1) != UINT32_C(0x71cbbbc3));
    assert(jitcall(code, pkt, 1, 1) == UINT32_C(0x0000a994));

    bpfjit_free_code(code);
}

/* Test JIT compilation of BPF_ALU+BPF_ADD+BPF_X */
void tc_bpfjit_alu_add_x() {
    static struct bpf_insn insns[] = {
        BPF_STMT(BPF_LD+BPF_IMM, 3),
        BPF_STMT(BPF_LDX+BPF_W+BPF_IMM, 2),
        BPF_STMT(BPF_ALU+BPF_ADD+BPF_X, 0),
        BPF_STMT(BPF_RET+BPF_A, 0)
    };

    uint8_t pkt[1]; /* the program doesn't read any data */
    size_t insn_count = sizeof(insns) / sizeof(insns[0]);

    assert(exec_prog(insns, insn_count, pkt, 1) == 5);
}

/* Test JIT compilation of BPF_ALU+BPF_SUB+BPF_X */
void tc_bpfjit_alu_sub_x() {
    static struct bpf_insn insns[] = {
        BPF_STMT(BPF_LD+BPF_IMM, 1),
        BPF_STMT(BPF_LDX+BPF_W+BPF_IMM, 2),
        BPF_STMT(BPF_ALU+BPF_SUB+BPF_X, 0),
        BPF_STMT(BPF_RET+BPF_A, 0)
    };

    uint8_t pkt[1]; /* the program doesn't read any data */
    size_t insn_count = sizeof(insns) / sizeof(insns[0]);

    assert(exec_prog(insns, insn_count, pkt, 1) == UINT32_MAX);
}

/* Test JIT compilation of BPF_ALU+BPF_MUL+BPF_X */
void tc_bpfjit_alu_mul_x() {
    static struct bpf_insn insns[] = {
        BPF_STMT(BPF_LD+BPF_IMM, UINT32_C(0xffffffff)),
        BPF_STMT(BPF_LDX+BPF_W+BPF_IMM, 3),
        BPF_STMT(BPF_ALU+BPF_MUL+BPF_X, 0),
        BPF_STMT(BPF_RET+BPF_A, 0)
    };

    uint8_t pkt[1]; /* the program doesn't read any data */
    size_t insn_count = sizeof(insns) / sizeof(insns[0]);

    assert(exec_prog(insns, insn_count, pkt, 1) == 0xfffffffd);
}

/* Test JIT compilation of BPF_ALU+BPF_DIV+BPF_X with X=0 */
void tc_bpfjit_alu_div0_x() {
    static struct bpf_insn insns[] = {
        BPF_STMT(BPF_LDX+BPF_W+BPF_IMM, 0),
        BPF_STMT(BPF_ALU+BPF_DIV+BPF_X, 0),
        BPF_STMT(BPF_RET+BPF_A, 0)
    };

    uint8_t pkt[1]; /* the program doesn't read any data */
    size_t insn_count = sizeof(insns) / sizeof(insns[0]);

    assert(exec_prog(insns, insn_count, pkt, 1) == 0);
}

/* Test JIT compilation of BPF_ALU+BPF_DIV+BPF_X with X=1 */
void tc_bpfjit_alu_div1_x() {
    static struct bpf_insn insns[] = {
        BPF_STMT(BPF_LD+BPF_IMM, 7),
        BPF_STMT(BPF_LDX+BPF_W+BPF_IMM, 1),
        BPF_STMT(BPF_ALU+BPF_DIV+BPF_X, 0),
        BPF_STMT(BPF_RET+BPF_A, 0)
    };

    uint8_t pkt[1]; /* the program doesn't read any data */
    size_t insn_count = sizeof(insns) / sizeof(insns[0]);

    assert(exec_prog(insns, insn_count, pkt, 1) == 7);
}

/* Test JIT compilation of BPF_ALU+BPF_DIV+BPF_X with X=2 */
void tc_bpfjit_alu_div2_x() {
    static struct bpf_insn insns[] = {
        BPF_STMT(BPF_LD+BPF_IMM, 7),
        BPF_STMT(BPF_LDX+BPF_W+BPF_IMM, 2),
        BPF_STMT(BPF_ALU+BPF_DIV+BPF_X, 0),
        BPF_STMT(BPF_RET+BPF_A, 0)
    };

    uint8_t pkt[1]; /* the program doesn't read any data */
    size_t insn_count = sizeof(insns) / sizeof(insns[0]);

    assert(exec_prog(insns, insn_count, pkt, 1) == 3);
}

/* Test JIT compilation of BPF_ALU+BPF_DIV+BPF_X with X=4 */
void tc_bpfjit_alu_div4_x() {
    static struct bpf_insn insns[] = {
        BPF_STMT(BPF_LD+BPF_IMM, UINT32_C(0xffffffff)),
        BPF_STMT(BPF_LDX+BPF_W+BPF_IMM, 4),
        BPF_STMT(BPF_ALU+BPF_DIV+BPF_X, 0),
        BPF_STMT(BPF_RET+BPF_A, 0)
    };

    uint8_t pkt[1]; /* the program doesn't read any data */
    size_t insn_count = sizeof(insns) / sizeof(insns[0]);

    assert(exec_prog(insns, insn_count, pkt, 1) == 0x3fffffff);
}

/* Test JIT compilation of BPF_ALU+BPF_DIV+BPF_X with X=10 */
void tc_bpfjit_alu_div10_x() {
    static struct bpf_insn insns[] = {
        BPF_STMT(BPF_LD+BPF_IMM, UINT32_C(4294843849)),
        BPF_STMT(BPF_LDX+BPF_W+BPF_IMM, 10),
        BPF_STMT(BPF_ALU+BPF_DIV+BPF_X, 0),
        BPF_STMT(BPF_RET+BPF_A, 0)
    };

    uint8_t pkt[1]; /* the program doesn't read any data */
    size_t insn_count = sizeof(insns) / sizeof(insns[0]);

    assert(exec_prog(insns, insn_count, pkt, 1) == 429484384);
}

/* Test JIT compilation of BPF_ALU+BPF_DIV+BPF_X with X=10000 */
void tc_bpfjit_alu_div10000_x() {
    static struct bpf_insn insns[] = {
        BPF_STMT(BPF_LD+BPF_IMM, UINT32_C(4294843849)),
        BPF_STMT(BPF_LDX+BPF_W+BPF_IMM, 10000),
        BPF_STMT(BPF_ALU+BPF_DIV+BPF_X, 0),
        BPF_STMT(BPF_RET+BPF_A, 0)
    };

    uint8_t pkt[1]; /* the program doesn't read any data */
    size_t insn_count = sizeof(insns) / sizeof(insns[0]);

    assert(exec_prog(insns, insn_count, pkt, 1) == 429484);
}

/* Test JIT compilation of BPF_ALU+BPF_DIV+BPF_X with X=7609801 */
void tc_bpfjit_alu_div7609801_x() {
    static struct bpf_insn insns[] = {
        BPF_STMT(BPF_LD+BPF_IMM, UINT32_C(4294967295)),
        BPF_STMT(BPF_LDX+BPF_W+BPF_IMM, UINT32_C(7609801)),
        BPF_STMT(BPF_ALU+BPF_DIV+BPF_X, 0),
        BPF_STMT(BPF_RET+BPF_A, 0)
    };

    uint8_t pkt[1]; /* the program doesn't read any data */
    size_t insn_count = sizeof(insns) / sizeof(insns[0]);

    assert(exec_prog(insns, insn_count, pkt, 1) == 564);
}

/* Test JIT compilation of BPF_ALU+BPF_DIV+BPF_X with X=0x80000000 */
void tc_bpfjit_alu_div80000000_x() {
    static struct bpf_insn insns[] = {
        BPF_STMT(BPF_LD+BPF_IMM, UINT32_C(0xffffffde)),
        BPF_STMT(BPF_LDX+BPF_W+BPF_IMM, UINT32_C(0x80000000)),
        BPF_STMT(BPF_ALU+BPF_DIV+BPF_X, 0),
        BPF_STMT(BPF_RET+BPF_A, 0)
    };

    uint8_t pkt[1]; /* the program doesn't read any data */
    size_t insn_count = sizeof(insns) / sizeof(insns[0]);

    assert(exec_prog(insns, insn_count, pkt, 1) == 1);
}

/* Test JIT compilation of BPF_ALU+BPF_MOD+BPF_X with X=0 */
void tc_bpfjit_alu_mod0_x() {
    static struct bpf_insn insns[] = {
        BPF_STMT(BPF_LDX+BPF_W+BPF_IMM, 0),
        BPF_STMT(BPF_ALU+BPF_MOD+BPF_X, 0),
        BPF_STMT(BPF_RET+BPF_A, 0)
    };

    uint8_t pkt[1]; /* the program doesn't read any data */
    size_t insn_count = sizeof(insns) / sizeof(insns[0]);

    assert(exec_prog(insns, insn_count, pkt, 1) == 0);
}

/* Test JIT compilation of BPF_ALU+BPF_MOD+BPF_X with X=1 */
void tc_bpfjit_alu_mod1_x() {
    static struct bpf_insn insns[] = {
        BPF_STMT(BPF_LD+BPF_IMM, 7),
        BPF_STMT(BPF_LDX+BPF_W+BPF_IMM, 1),
        BPF_STMT(BPF_ALU+BPF_MOD+BPF_X, 0),
        BPF_STMT(BPF_RET+BPF_A, 0)
    };

    uint8_t pkt[1]; /* the program doesn't read any data */
    size_t insn_count = sizeof(insns) / sizeof(insns[0]);

    assert(exec_prog(insns, insn_count, pkt, 1) == 0);
}

/* Test JIT compilation of BPF_ALU+BPF_MOD+BPF_X with X=2 */
void tc_bpfjit_alu_mod2_x() {
    static struct bpf_insn insns[] = {
        BPF_STMT(BPF_LD+BPF_IMM, 7),
        BPF_STMT(BPF_LDX+BPF_W+BPF_IMM, 2),
        BPF_STMT(BPF_ALU+BPF_MOD+BPF_X, 0),
        BPF_STMT(BPF_RET+BPF_A, 0)
    };

    uint8_t pkt[1]; /* the program doesn't read any data */
    size_t insn_count = sizeof(insns) / sizeof(insns[0]);

    assert(exec_prog(insns, insn_count, pkt, 1) == 1);
}

/* Test JIT compilation of BPF_ALU+BPF_MOD+BPF_X with X=4 */
void tc_bpfjit_alu_mod4_x() {
    static struct bpf_insn insns[] = {
        BPF_STMT(BPF_LD+BPF_IMM, UINT32_C(0xffffffff)),
        BPF_STMT(BPF_LDX+BPF_W+BPF_IMM, 4),
        BPF_STMT(BPF_ALU+BPF_MOD+BPF_X, 0),
        BPF_STMT(BPF_RET+BPF_A, 0)
    };

    uint8_t pkt[1]; /* the program doesn't read any data */
    size_t insn_count = sizeof(insns) / sizeof(insns[0]);

    assert(exec_prog(insns, insn_count, pkt, 1) == 3);
}

/* Test JIT compilation of BPF_ALU+BPF_MOD+BPF_X with X=10 */
void tc_bpfjit_alu_mod10_x() {
    static struct bpf_insn insns[] = {
        BPF_STMT(BPF_LD+BPF_IMM, UINT32_C(4294843849)),
        BPF_STMT(BPF_LDX+BPF_W+BPF_IMM, 10),
        BPF_STMT(BPF_ALU+BPF_MOD+BPF_X, 0),
        BPF_STMT(BPF_RET+BPF_A, 0)
    };

    uint8_t pkt[1]; /* the program doesn't read any data */
    size_t insn_count = sizeof(insns) / sizeof(insns[0]);

    assert(exec_prog(insns, insn_count, pkt, 1) == 9);
}

/* Test JIT compilation of BPF_ALU+BPF_MOD+BPF_X with X=10000 */
void tc_bpfjit_alu_mod10000_x() {
    static struct bpf_insn insns[] = {
        BPF_STMT(BPF_LD+BPF_IMM, UINT32_C(4294843849)),
        BPF_STMT(BPF_LDX+BPF_W+BPF_IMM, 10000),
        BPF_STMT(BPF_ALU+BPF_MOD+BPF_X, 0),
        BPF_STMT(BPF_RET+BPF_A, 0)
    };

    uint8_t pkt[1]; /* the program doesn't read any data */
    size_t insn_count = sizeof(insns) / sizeof(insns[0]);

    assert(exec_prog(insns, insn_count, pkt, 1) == 3849);
}

/* Test JIT compilation of BPF_ALU+BPF_MOD+BPF_X with X=7609801 */
void tc_bpfjit_alu_mod7609801_x() {
    static struct bpf_insn insns[] = {
        BPF_STMT(BPF_LD+BPF_IMM, UINT32_C(4294967295)),
        BPF_STMT(BPF_LDX+BPF_W+BPF_IMM, UINT32_C(7609801)),
        BPF_STMT(BPF_ALU+BPF_MOD+BPF_X, 0),
        BPF_STMT(BPF_RET+BPF_A, 0)
    };

    uint8_t pkt[1]; /* the program doesn't read any data */
    size_t insn_count = sizeof(insns) / sizeof(insns[0]);

    assert(exec_prog(insns, insn_count, pkt, 1) == 3039531);
}

/* Test JIT compilation of BPF_ALU+BPF_MOD+BPF_X with X=0x80000000 */
void tc_bpfjit_alu_mod80000000_x() {
    static struct bpf_insn insns[] = {
        BPF_STMT(BPF_LD+BPF_IMM, UINT32_C(0xffffffde)),
        BPF_STMT(BPF_LDX+BPF_W+BPF_IMM, UINT32_C(0x80000000)),
        BPF_STMT(BPF_ALU+BPF_MOD+BPF_X, 0),
        BPF_STMT(BPF_RET+BPF_A, 0)
    };

    uint8_t pkt[1]; /* the program doesn't read any data */
    size_t insn_count = sizeof(insns) / sizeof(insns[0]);

    assert(exec_prog(insns, insn_count, pkt, 1) == UINT32_C(0x7fffffde));
}

/* Test JIT compilation of BPF_ALU+BPF_AND+BPF_X */
void tc_bpfjit_alu_and_x() {
    static struct bpf_insn insns[] = {
        BPF_STMT(BPF_LD+BPF_IMM, 0xdead),
        BPF_STMT(BPF_LDX+BPF_W+BPF_IMM, 0xbeef),
        BPF_STMT(BPF_ALU+BPF_AND+BPF_X, 0),
        BPF_STMT(BPF_RET+BPF_A, 0)
    };

    uint8_t pkt[1]; /* the program doesn't read any data */
    size_t insn_count = sizeof(insns) / sizeof(insns[0]);

    assert(exec_prog(insns, insn_count, pkt, 1) == (0xdead&0xbeef));
}

/* Test JIT compilation of BPF_ALU+BPF_OR+BPF_X */
void tc_bpfjit_alu_or_x() {
    static struct bpf_insn insns[] = {
        BPF_STMT(BPF_LD+BPF_IMM, 0xdead0000),
        BPF_STMT(BPF_LDX+BPF_W+BPF_IMM, 0x0000beef),
        BPF_STMT(BPF_ALU+BPF_OR+BPF_X, 0),
        BPF_STMT(BPF_RET+BPF_A, 0)
    };

    uint8_t pkt[1]; /* the program doesn't read any data */
    size_t insn_count = sizeof(insns) / sizeof(insns[0]);

    assert(exec_prog(insns, insn_count, pkt, 1) == 0xdeadbeef);
}

/* Test JIT compilation of BPF_ALU+BPF_XOR+BPF_X */
void tc_bpfjit_alu_xor_x() {
    static struct bpf_insn insns[] = {
        BPF_STMT(BPF_LD+BPF_IMM, 0xdead0f0f),
        BPF_STMT(BPF_LDX+BPF_W+BPF_IMM, 0x0000b1e0),
        BPF_STMT(BPF_ALU+BPF_XOR+BPF_X, 0),
        BPF_STMT(BPF_RET+BPF_A, 0)
    };

    uint8_t pkt[1]; /* the program doesn't read any data */
    size_t insn_count = sizeof(insns) / sizeof(insns[0]);

    assert(exec_prog(insns, insn_count, pkt, 1) == 0xdeadbeef);
}

/* Test JIT compilation of BPF_ALU+BPF_LSH+BPF_X */
void tc_bpfjit_alu_lsh_x() {
    static struct bpf_insn insns[] = {
        BPF_STMT(BPF_LD+BPF_IMM, 0xdeadbeef),
        BPF_STMT(BPF_LDX+BPF_W+BPF_IMM, 16),
        BPF_STMT(BPF_ALU+BPF_LSH+BPF_X, 0),
        BPF_STMT(BPF_RET+BPF_A, 0)
    };

    uint8_t pkt[1]; /* the program doesn't read any data */
    size_t insn_count = sizeof(insns) / sizeof(insns[0]);

    assert(exec_prog(insns, insn_count, pkt, 1) == 0xbeef0000);
}

/* Test JIT compilation of BPF_ALU+BPF_LSH+BPF_X with k=0 */
void tc_bpfjit_alu_lsh0_x() {
    static struct bpf_insn insns[] = {
        BPF_STMT(BPF_LD+BPF_IMM, 0xdeadbeef),
        BPF_STMT(BPF_LDX+BPF_W+BPF_IMM, 0),
        BPF_STMT(BPF_ALU+BPF_LSH+BPF_X, 0),
        BPF_STMT(BPF_RET+BPF_A, 0)
    };

    uint8_t pkt[1]; /* the program doesn't read any data */
    size_t insn_count = sizeof(insns) / sizeof(insns[0]);

    assert(exec_prog(insns, insn_count, pkt, 1) == 0xdeadbeef);
}

/* Test JIT compilation of BPF_ALU+BPF_RSH+BPF_X */
void tc_bpfjit_alu_rsh_x() {
    static struct bpf_insn insns[] = {
        BPF_STMT(BPF_LD+BPF_IMM, 0xdeadbeef),
        BPF_STMT(BPF_LDX+BPF_W+BPF_IMM, 16),
        BPF_STMT(BPF_ALU+BPF_RSH+BPF_X, 0),
        BPF_STMT(BPF_RET+BPF_A, 0)
    };

    uint8_t pkt[1]; /* the program doesn't read any data */
    size_t insn_count = sizeof(insns) / sizeof(insns[0]);

    assert(exec_prog(insns, insn_count, pkt, 1) == 0x0000dead);
}

/* Test JIT compilation of BPF_ALU+BPF_RSH+BPF_X with k=0 */
void tc_bpfjit_alu_rsh0_x() {
    static struct bpf_insn insns[] = {
        BPF_STMT(BPF_LD+BPF_IMM, 0xdeadbeef),
        BPF_STMT(BPF_LDX+BPF_W+BPF_IMM, 0),
        BPF_STMT(BPF_ALU+BPF_RSH+BPF_X, 0),
        BPF_STMT(BPF_RET+BPF_A, 0)
    };

    uint8_t pkt[1]; /* the program doesn't read any data */
    size_t insn_count = sizeof(insns) / sizeof(insns[0]);

    assert(exec_prog(insns, insn_count, pkt, 1) == 0xdeadbeef);
}

/* Test JIT compilation of modulo logic of BPF_ALU+BPF_X operations */
void tc_bpfjit_alu_modulo_x() {
    static struct bpf_insn insns[] = {
        BPF_STMT(BPF_LD+BPF_IMM, UINT32_C(0x7fffff77)),

        /* (7FFFFF77 * 0FFFFF77) = 07FFFFB2,F0004951 */
        BPF_STMT(BPF_LDX+BPF_W+BPF_K, UINT32_C(0x0fffff77)),
        BPF_STMT(BPF_ALU+BPF_MUL+BPF_X, 0),

        /* 07FFFFB2,F0004951 << 1 = 0FFFFF65,E00092A2 */
        BPF_STMT(BPF_LDX+BPF_W+BPF_K, 1),
        BPF_STMT(BPF_ALU+BPF_LSH+BPF_X, 0),

        /* 0FFFFF65,E00092A2 + DDDDDDDD = 0FFFFF66,BDDE707F */
        BPF_STMT(BPF_LDX+BPF_W+BPF_K, UINT32_C(0xdddddddd)),
        BPF_STMT(BPF_ALU+BPF_ADD+BPF_X, 0),

        /* 0FFFFF66,BDDE707F - FFFFFFFF = 0FFFFF65,BDDE7080 */
        BPF_STMT(BPF_LDX+BPF_W+BPF_K, UINT32_C(0xffffffff)),
        BPF_STMT(BPF_ALU+BPF_SUB+BPF_X, 0),

        /* 0FFFFF65,BDDE7080 | 0000030C = 0FFFFF65,BDDE738C */
        BPF_STMT(BPF_LDX+BPF_W+BPF_K, UINT32_C(0x0000030c)),
        BPF_STMT(BPF_ALU+BPF_OR+BPF_X, 0),

        /* -0FFFFF65,BDDE738C mod(2^64) = F000009A,42218C74 */
        BPF_STMT(BPF_ALU+BPF_NEG, 0),

        /* F000009A,42218C74 & FFFFFF0F = F000009A,42218C04 */
        BPF_STMT(BPF_LDX+BPF_W+BPF_K, UINT32_C(0xffffff0f)),
        BPF_STMT(BPF_ALU+BPF_AND+BPF_X, 0),

        /* F000009A,42218C74 >> 3 = 1E000013,48443180 */
        /* 00000000,42218C74 >> 3 = 00000000,08443180 */
        BPF_STMT(BPF_LDX+BPF_W+BPF_K, 3),
        BPF_STMT(BPF_ALU+BPF_RSH+BPF_X, 0),

        /* 00000000,08443180 * 7FFFFF77 = 042218BB,93818280 */
        BPF_STMT(BPF_LDX+BPF_W+BPF_K, UINT32_C(0x7fffff77)),
        BPF_STMT(BPF_ALU+BPF_MUL+BPF_X, 0),

        /* 042218BB,93818280 / DEAD = 000004C0,71CBBBC3 */
        /* 00000000,93818280 / DEAD = 00000000,0000A994 */
        BPF_STMT(BPF_LDX+BPF_W+BPF_K, UINT32_C(0xdead)),
        BPF_STMT(BPF_ALU+BPF_DIV+BPF_X, 0),

        BPF_STMT(BPF_RET+BPF_A, 0)
    };

    bpfjit_func_t code;
    uint8_t pkt[1]; /* the program doesn't read any data */

    size_t insn_count = sizeof(insns) / sizeof(insns[0]);

    code = bpfjit_generate_code(NULL, insns, insn_count);
    assert(code != NULL);

    assert(jitcall(code, pkt, 1, 1) != UINT32_C(0x71cbbbc3));
    assert(jitcall(code, pkt, 1, 1) == UINT32_C(0x0000a994));

    bpfjit_free_code(code);
}

/* Test JIT compilation of BPF_ALU+BPF_NEG */
void tc_bpfjit_alu_neg() {
    static struct bpf_insn insns[] = {
        BPF_STMT(BPF_LD+BPF_IMM, 777),
        BPF_STMT(BPF_ALU+BPF_NEG, 0),
        BPF_STMT(BPF_RET+BPF_A, 0)
    };

    uint8_t pkt[1]; /* the program doesn't read any data */
    size_t insn_count = sizeof(insns) / sizeof(insns[0]);

    assert(exec_prog(insns, insn_count, pkt, 1) == 0u-777u);
}

/* Test JIT compilation of BPF_JMP+BPF_JA */
void tc_bpfjit_jmp_ja() {
    static struct bpf_insn insns[] = {
        BPF_STMT(BPF_JMP+BPF_JA, 1),
        BPF_STMT(BPF_RET+BPF_K, 0),
        BPF_STMT(BPF_RET+BPF_K, UINT32_MAX),
        BPF_STMT(BPF_RET+BPF_K, 1),
        BPF_STMT(BPF_RET+BPF_K, 2),
        BPF_STMT(BPF_RET+BPF_K, 3),
    };

    uint8_t pkt[1]; /* the program doesn't read any data */
    size_t insn_count = sizeof(insns) / sizeof(insns[0]);

    assert(exec_prog(insns, insn_count, pkt, 1) == UINT32_MAX);
}

/* Test JIT compilation of BPF_JMP+BPF_JA to invalid destination */
void tc_bpfjit_jmp_ja_invalid() {
    static struct bpf_insn insns[] = {
        BPF_STMT(BPF_JMP+BPF_JA, 4),
        BPF_STMT(BPF_RET+BPF_K, 0),
        BPF_STMT(BPF_RET+BPF_K, 1),
        BPF_STMT(BPF_RET+BPF_K, 2),
        BPF_STMT(BPF_RET+BPF_K, 3),
    };

    bpfjit_func_t code;
    size_t insn_count = sizeof(insns) / sizeof(insns[0]);

    code = bpfjit_generate_code(NULL, insns, insn_count);
    assert(code == NULL);
}

/* Test JIT compilation of BPF_JMP+BPF_JA  with negative offset */
void tc_bpfjit_jmp_ja_overflow() {
    static struct bpf_insn insns[] = {
        BPF_STMT(BPF_JMP+BPF_JA, 1),
        BPF_STMT(BPF_RET+BPF_K, 777),
        BPF_STMT(BPF_JMP+BPF_JA, UINT32_MAX - 1), // -2
        BPF_STMT(BPF_RET+BPF_K, 0)
    };

    bpfjit_func_t code;
    size_t insn_count = sizeof(insns) / sizeof(insns[0]);

    code = bpfjit_generate_code(NULL, insns, insn_count);
    assert(code == NULL);
}

/* Test JIT compilation of BPF_JMP+BPF_JGT+BPF_K */
void tc_bpfjit_jmp_jgt_k() {
    static struct bpf_insn insns[] = {
        BPF_STMT(BPF_LD+BPF_W+BPF_LEN, 0),
        BPF_JUMP(BPF_JMP+BPF_JGT+BPF_K, 7, 0, 1),
        BPF_STMT(BPF_RET+BPF_K, 0),
        BPF_JUMP(BPF_JMP+BPF_JGT+BPF_K, 2, 2, 0),
        BPF_JUMP(BPF_JMP+BPF_JGT+BPF_K, 9, 0, 0),
        BPF_STMT(BPF_RET+BPF_K, 1),
        BPF_JUMP(BPF_JMP+BPF_JGT+BPF_K, 4, 1, 1),
        BPF_STMT(BPF_RET+BPF_K, 2),
        BPF_JUMP(BPF_JMP+BPF_JGT+BPF_K, 6, 2, 3),
        BPF_STMT(BPF_RET+BPF_K, 3),
        BPF_STMT(BPF_RET+BPF_K, 4),
        BPF_STMT(BPF_RET+BPF_K, 5),
        BPF_JUMP(BPF_JMP+BPF_JGT+BPF_K, 5, 3, 1),
        BPF_STMT(BPF_RET+BPF_K, 6),
        BPF_JUMP(BPF_JMP+BPF_JGT+BPF_K, 0, 0, 0),
        BPF_STMT(BPF_RET+BPF_K, 7),
        BPF_STMT(BPF_RET+BPF_K, 8)
    };

    bpfjit_func_t code;
    uint8_t pkt[8]; /* the program doesn't read any data */
    size_t insn_count = sizeof(insns) / sizeof(insns[0]);

    code = bpfjit_generate_code(NULL, insns, insn_count);
    assert(code != NULL);

    assert(jitcall(code, pkt, 1, 1) == 1);
    assert(jitcall(code, pkt, 2, 2) == 1);
    assert(jitcall(code, pkt, 3, 3) == 7);
    assert(jitcall(code, pkt, 4, 4) == 7);
    assert(jitcall(code, pkt, 5, 5) == 7);
    assert(jitcall(code, pkt, 6, 6) == 8);
    assert(jitcall(code, pkt, 7, 7) == 5);
    assert(jitcall(code, pkt, 8, 8) == 0);

    bpfjit_free_code(code);
}

/* Test JIT compilation of BPF_JMP+BPF_JGE+BPF_K */
void tc_bpfjit_jmp_jge_k() {
    static struct bpf_insn insns[] = {
        BPF_STMT(BPF_LD+BPF_W+BPF_LEN, 0),
        BPF_JUMP(BPF_JMP+BPF_JGE+BPF_K, 8, 0, 1),
        BPF_STMT(BPF_RET+BPF_K, 0),
        BPF_JUMP(BPF_JMP+BPF_JGE+BPF_K, 3, 2, 0),
        BPF_JUMP(BPF_JMP+BPF_JGE+BPF_K, 9, 0, 0),
        BPF_STMT(BPF_RET+BPF_K, 1),
        BPF_JUMP(BPF_JMP+BPF_JGE+BPF_K, 5, 1, 1),
        BPF_STMT(BPF_RET+BPF_K, 2),
        BPF_JUMP(BPF_JMP+BPF_JGE+BPF_K, 7, 2, 3),
        BPF_STMT(BPF_RET+BPF_K, 3),
        BPF_STMT(BPF_RET+BPF_K, 4),
        BPF_STMT(BPF_RET+BPF_K, 5),
        BPF_JUMP(BPF_JMP+BPF_JGE+BPF_K, 6, 3, 1),
        BPF_STMT(BPF_RET+BPF_K, 6),
        BPF_JUMP(BPF_JMP+BPF_JGE+BPF_K, 1, 0, 0),
        BPF_STMT(BPF_RET+BPF_K, 7),
        BPF_STMT(BPF_RET+BPF_K, 8)
    };

    bpfjit_func_t code;
    uint8_t pkt[8]; /* the program doesn't read any data */
    size_t insn_count = sizeof(insns) / sizeof(insns[0]);

    code = bpfjit_generate_code(NULL, insns, insn_count);
    assert(code != NULL);

    assert(jitcall(code, pkt, 1, 1) == 1);
    assert(jitcall(code, pkt, 2, 2) == 1);
    assert(jitcall(code, pkt, 3, 3) == 7);
    assert(jitcall(code, pkt, 4, 4) == 7);
    assert(jitcall(code, pkt, 5, 5) == 7);
    assert(jitcall(code, pkt, 6, 6) == 8);
    assert(jitcall(code, pkt, 7, 7) == 5);
    assert(jitcall(code, pkt, 8, 8) == 0);

    bpfjit_free_code(code);
}

/* Test JIT compilation of BPF_JMP+BPF_JEQ+BPF_K */
void tc_bpfjit_jmp_jeq_k() {
    static struct bpf_insn insns[] = {
        BPF_STMT(BPF_LD+BPF_W+BPF_LEN, 0),
        BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, 8, 0, 1),
        BPF_STMT(BPF_RET+BPF_K, 0),
        BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, 3, 1, 0),
        BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, 9, 1, 1),
        BPF_STMT(BPF_RET+BPF_K, 1),
        BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, 5, 1, 1),
        BPF_STMT(BPF_RET+BPF_K, 2),
        BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, 7, 2, 3),
        BPF_STMT(BPF_RET+BPF_K, 3),
        BPF_STMT(BPF_RET+BPF_K, 4),
        BPF_STMT(BPF_RET+BPF_K, 5),
        BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, 6, 3, 1),
        BPF_STMT(BPF_RET+BPF_K, 6),
        BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, 1, 0, 0),
        BPF_STMT(BPF_RET+BPF_K, 7),
        BPF_STMT(BPF_RET+BPF_K, 8)
    };

    bpfjit_func_t code;
    uint8_t pkt[8]; /* the program doesn't read any data */

    size_t insn_count = sizeof(insns) / sizeof(insns[0]);

    code = bpfjit_generate_code(NULL, insns, insn_count);
    assert(code != NULL);

    assert(jitcall(code, pkt, 1, 1) == 7);
    assert(jitcall(code, pkt, 2, 2) == 7);
    assert(jitcall(code, pkt, 3, 3) == 1);
    assert(jitcall(code, pkt, 4, 4) == 7);
    assert(jitcall(code, pkt, 5, 5) == 7);
    assert(jitcall(code, pkt, 6, 6) == 8);
    assert(jitcall(code, pkt, 7, 7) == 5);
    assert(jitcall(code, pkt, 8, 8) == 0);

    bpfjit_free_code(code);
}

/* Test JIT compilation of BPF_JMP+BPF_JSET+BPF_K */
void tc_bpfjit_jmp_jset_k() {
    static struct bpf_insn insns[] = {
        BPF_STMT(BPF_LD+BPF_W+BPF_LEN, 0),
        BPF_JUMP(BPF_JMP+BPF_JSET+BPF_K, 8, 0, 1),
        BPF_STMT(BPF_RET+BPF_K, 0),
        BPF_JUMP(BPF_JMP+BPF_JSET+BPF_K, 4, 2, 0),
        BPF_JUMP(BPF_JMP+BPF_JSET+BPF_K, 3, 0, 0),
        BPF_STMT(BPF_RET+BPF_K, 1),
        BPF_JUMP(BPF_JMP+BPF_JSET+BPF_K, 2, 1, 1),
        BPF_STMT(BPF_RET+BPF_K, 2),
        BPF_JUMP(BPF_JMP+BPF_JSET+BPF_K, 1, 2, 3),
        BPF_STMT(BPF_RET+BPF_K, 3),
        BPF_STMT(BPF_RET+BPF_K, 4),
        BPF_STMT(BPF_RET+BPF_K, 5),
        BPF_JUMP(BPF_JMP+BPF_JSET+BPF_K, 2, 3, 1),
        BPF_STMT(BPF_RET+BPF_K, 6),
        BPF_JUMP(BPF_JMP+BPF_JSET+BPF_K, 7, 0, 0),
        BPF_STMT(BPF_RET+BPF_K, 7),
        BPF_STMT(BPF_RET+BPF_K, 8)
    };

    bpfjit_func_t code;
    uint8_t pkt[8]; /* the program doesn't read any data */

    size_t insn_count = sizeof(insns) / sizeof(insns[0]);

    code = bpfjit_generate_code(NULL, insns, insn_count);
    assert(code != NULL);

    assert(jitcall(code, pkt, 1, 1) == 1);
    assert(jitcall(code, pkt, 2, 2) == 1);
    assert(jitcall(code, pkt, 3, 3) == 1);
    assert(jitcall(code, pkt, 4, 4) == 7);
    assert(jitcall(code, pkt, 5, 5) == 5);
    assert(jitcall(code, pkt, 6, 6) == 8);
    assert(jitcall(code, pkt, 7, 7) == 5);
    assert(jitcall(code, pkt, 8, 8) == 0);

    bpfjit_free_code(code);
}

/* Test JIT compilation of modulo logic of BPF_JMP+BPF_K operations */
void tc_bpfjit_jmp_modulo_k() {
    static struct bpf_insn insns[] = {
        BPF_STMT(BPF_LD+BPF_IMM, UINT32_C(0x7fffff77)),
        BPF_STMT(BPF_ALU+BPF_LSH+BPF_K, 4),
        BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, UINT32_C(0xfffff770), 1, 0),
        BPF_STMT(BPF_RET+BPF_K, 0),
        BPF_JUMP(BPF_JMP+BPF_JGT+BPF_K, UINT32_C(0xfffff770), 0, 1),
        BPF_STMT(BPF_RET+BPF_K, 1),
        BPF_JUMP(BPF_JMP+BPF_JGE+BPF_K, UINT32_C(0xfffff771), 0, 1),
        BPF_STMT(BPF_RET+BPF_K, 2),
        BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, UINT32_C(0xfffff770), 0, 3),
        BPF_JUMP(BPF_JMP+BPF_JGT+BPF_K, UINT32_C(0xfffff770), 2, 0),
        BPF_JUMP(BPF_JMP+BPF_JGE+BPF_K, UINT32_C(0xfffff771), 1, 0),
        BPF_STMT(BPF_JMP+BPF_JA, 1),
        BPF_STMT(BPF_RET+BPF_K, 3),

        /* FFFFF770+FFFFF770 = 00000001,FFFFEEE0 */
        BPF_STMT(BPF_ALU+BPF_ADD+BPF_K, UINT32_C(0xfffff770)),

        BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, UINT32_C(0xffffeee0), 1, 0),
        BPF_STMT(BPF_RET+BPF_K, 4),
        BPF_JUMP(BPF_JMP+BPF_JGT+BPF_K, UINT32_C(0xffffeee0), 0, 1),
        BPF_STMT(BPF_RET+BPF_K, 5),
        BPF_JUMP(BPF_JMP+BPF_JGE+BPF_K, UINT32_C(0xffffeee1), 0, 1),
        BPF_STMT(BPF_RET+BPF_K, 6),
        BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, UINT32_C(0xffffeee0), 0, 3),
        BPF_JUMP(BPF_JMP+BPF_JGT+BPF_K, UINT32_C(0xffffeee0), 2, 0),
        BPF_JUMP(BPF_JMP+BPF_JGE+BPF_K, UINT32_C(0xffffeee1), 1, 0),
        BPF_STMT(BPF_RET+BPF_K, UINT32_MAX),
        BPF_STMT(BPF_RET+BPF_K, 7)
    };

    uint8_t pkt[1]; /* the program doesn't read any data */

    size_t insn_count = sizeof(insns) / sizeof(insns[0]);

    assert(exec_prog(insns, insn_count, pkt, 1) == UINT32_MAX);
}

/* Test JIT compilation of BPF_JMP+BPF_JGT+BPF_X */
void tc_bpfjit_jmp_jgt_x() {
    static struct bpf_insn insns[] = {
        BPF_STMT(BPF_LD+BPF_W+BPF_LEN, 0),
        BPF_STMT(BPF_LDX+BPF_W+BPF_IMM, 7),
        BPF_JUMP(BPF_JMP+BPF_JGT+BPF_X, 0, 0, 1),
        BPF_STMT(BPF_RET+BPF_K, 0),
        BPF_STMT(BPF_LDX+BPF_W+BPF_IMM, 2),
        BPF_JUMP(BPF_JMP+BPF_JGT+BPF_X, 0, 3, 0),
        BPF_STMT(BPF_LDX+BPF_W+BPF_IMM, 9),
        BPF_JUMP(BPF_JMP+BPF_JGT+BPF_X, 0, 0, 0),
        BPF_STMT(BPF_RET+BPF_K, 1),
        BPF_STMT(BPF_LDX+BPF_W+BPF_IMM, 4),
        BPF_JUMP(BPF_JMP+BPF_JGT+BPF_X, 0, 1, 1),
        BPF_STMT(BPF_RET+BPF_K, 2),
        BPF_STMT(BPF_LDX+BPF_W+BPF_IMM, 6),
        BPF_JUMP(BPF_JMP+BPF_JGT+BPF_X, 0, 2, 3),
        BPF_STMT(BPF_RET+BPF_K, 3),
        BPF_STMT(BPF_RET+BPF_K, 4),
        BPF_STMT(BPF_RET+BPF_K, 5),
        BPF_STMT(BPF_LDX+BPF_W+BPF_IMM, 5),
        BPF_JUMP(BPF_JMP+BPF_JGT+BPF_X, 0, 4, 1),
        BPF_STMT(BPF_RET+BPF_K, 6),
        BPF_STMT(BPF_LDX+BPF_W+BPF_IMM, 0),
        BPF_JUMP(BPF_JMP+BPF_JGT+BPF_X, 0, 0, 0),
        BPF_STMT(BPF_RET+BPF_K, 7),
        BPF_STMT(BPF_RET+BPF_K, 8)
    };

    bpfjit_func_t code;
    uint8_t pkt[8]; /* the program doesn't read any data */
    size_t insn_count = sizeof(insns) / sizeof(insns[0]);

    code = bpfjit_generate_code(NULL, insns, insn_count);
    assert(code != NULL);

    assert(jitcall(code, pkt, 1, 1) == 1);
    assert(jitcall(code, pkt, 2, 2) == 1);
    assert(jitcall(code, pkt, 3, 3) == 7);
    assert(jitcall(code, pkt, 4, 4) == 7);
    assert(jitcall(code, pkt, 5, 5) == 7);
    assert(jitcall(code, pkt, 6, 6) == 8);
    assert(jitcall(code, pkt, 7, 7) == 5);
    assert(jitcall(code, pkt, 8, 8) == 0);

    bpfjit_free_code(code);
}

/* Test JIT compilation of BPF_JMP+BPF_JGE+BPF_X */
void tc_bpfjit_jmp_jge_x() {
    static struct bpf_insn insns[] = {
        BPF_STMT(BPF_LD+BPF_W+BPF_LEN, 0),
        BPF_STMT(BPF_LDX+BPF_W+BPF_IMM, 8),
        BPF_JUMP(BPF_JMP+BPF_JGE+BPF_X, 0, 0, 1),
        BPF_STMT(BPF_RET+BPF_K, 0),
        BPF_STMT(BPF_LDX+BPF_W+BPF_IMM, 3),
        BPF_JUMP(BPF_JMP+BPF_JGE+BPF_X, 0, 3, 0),
        BPF_STMT(BPF_LDX+BPF_W+BPF_IMM, 9),
        BPF_JUMP(BPF_JMP+BPF_JGE+BPF_X, 0, 0, 0),
        BPF_STMT(BPF_RET+BPF_K, 1),
        BPF_STMT(BPF_LDX+BPF_W+BPF_IMM, 5),
        BPF_JUMP(BPF_JMP+BPF_JGE+BPF_X, 0, 1, 1),
        BPF_STMT(BPF_RET+BPF_K, 2),
        BPF_STMT(BPF_LDX+BPF_W+BPF_IMM, 7),
        BPF_JUMP(BPF_JMP+BPF_JGE+BPF_X, 0, 2, 3),
        BPF_STMT(BPF_RET+BPF_K, 3),
        BPF_STMT(BPF_RET+BPF_K, 4),
        BPF_STMT(BPF_RET+BPF_K, 5),
        BPF_STMT(BPF_LDX+BPF_W+BPF_IMM, 6),
        BPF_JUMP(BPF_JMP+BPF_JGE+BPF_X, 0, 4, 1),
        BPF_STMT(BPF_RET+BPF_K, 6),
        BPF_STMT(BPF_LDX+BPF_W+BPF_IMM, 1),
        BPF_JUMP(BPF_JMP+BPF_JGE+BPF_X, 0, 0, 0),
        BPF_STMT(BPF_RET+BPF_K, 7),
        BPF_STMT(BPF_RET+BPF_K, 8)
    };

    bpfjit_func_t code;
    uint8_t pkt[8]; /* the program doesn't read any data */

    size_t insn_count = sizeof(insns) / sizeof(insns[0]);

    code = bpfjit_generate_code(NULL, insns, insn_count);
    assert(code != NULL);

    assert(jitcall(code, pkt, 1, 1) == 1);
    assert(jitcall(code, pkt, 2, 2) == 1);
    assert(jitcall(code, pkt, 3, 3) == 7);
    assert(jitcall(code, pkt, 4, 4) == 7);
    assert(jitcall(code, pkt, 5, 5) == 7);
    assert(jitcall(code, pkt, 6, 6) == 8);
    assert(jitcall(code, pkt, 7, 7) == 5);
    assert(jitcall(code, pkt, 8, 8) == 0);

    bpfjit_free_code(code);
}

/* Test JIT compilation of BPF_JMP+BPF_JEQ+BPF_X */
void tc_bpfjit_jmp_jeq_x() {
    static struct bpf_insn insns[] = {
        BPF_STMT(BPF_LD+BPF_W+BPF_LEN, 0),
        BPF_STMT(BPF_LDX+BPF_W+BPF_IMM, 8),
        BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_X, 0, 0, 1),
        BPF_STMT(BPF_RET+BPF_K, 1),
        BPF_STMT(BPF_LDX+BPF_W+BPF_IMM, 3),
        BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_X, 0, 2, 0),
        BPF_STMT(BPF_LDX+BPF_W+BPF_IMM, 9),
        BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_X, 0, 1, 1),
        BPF_STMT(BPF_RET+BPF_K, 2),
        BPF_STMT(BPF_LDX+BPF_W+BPF_IMM, 5),
        BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_X, 0, 0, 1),
        BPF_STMT(BPF_RET+BPF_K, 3),
        BPF_STMT(BPF_LDX+BPF_W+BPF_IMM, 7),
        BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_X, 0, 2, 3),
        BPF_STMT(BPF_RET+BPF_K, 4),
        BPF_STMT(BPF_RET+BPF_K, 5),
        BPF_STMT(BPF_RET+BPF_K, 6),
        BPF_STMT(BPF_LDX+BPF_W+BPF_IMM, 6),
        BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_X, 0, 3, 1),
        BPF_STMT(BPF_RET+BPF_K, 7),
        BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_X, 0, 1, 0),
        BPF_STMT(BPF_RET+BPF_K, 8),
        BPF_STMT(BPF_RET+BPF_K, 9)
    };

    bpfjit_func_t code;
    uint8_t pkt[8]; /* the program doesn't read any data */

    size_t insn_count = sizeof(insns) / sizeof(insns[0]);

    code = bpfjit_generate_code(NULL, insns, insn_count);
    assert(code != NULL);

    assert(jitcall(code, pkt, 1, 1) == 8);
    assert(jitcall(code, pkt, 2, 2) == 8);
    assert(jitcall(code, pkt, 3, 3) == 2);
    assert(jitcall(code, pkt, 4, 4) == 8);
    assert(jitcall(code, pkt, 5, 5) == 3);
    assert(jitcall(code, pkt, 6, 6) == 9);
    assert(jitcall(code, pkt, 7, 7) == 6);
    assert(jitcall(code, pkt, 8, 8) == 1);

    bpfjit_free_code(code);
}

/* Test JIT compilation of BPF_JMP+BPF_JSET+BPF_X */
void tc_bpfjit_jmp_jset_x() {
    static struct bpf_insn insns[] = {
        BPF_STMT(BPF_LD+BPF_W+BPF_LEN, 0),
        BPF_STMT(BPF_LDX+BPF_W+BPF_IMM, 8),
        BPF_JUMP(BPF_JMP+BPF_JSET+BPF_X, 0, 0, 1),
        BPF_STMT(BPF_RET+BPF_K, 0),
        BPF_STMT(BPF_LDX+BPF_W+BPF_IMM, 4),
        BPF_JUMP(BPF_JMP+BPF_JSET+BPF_X, 0, 2, 0),
        BPF_JUMP(BPF_JMP+BPF_JSET+BPF_X, 3, 0, 0),
        BPF_STMT(BPF_RET+BPF_K, 1),
        BPF_STMT(BPF_LDX+BPF_W+BPF_IMM, 2),
        BPF_JUMP(BPF_JMP+BPF_JSET+BPF_X, 0, 1, 1),
        BPF_STMT(BPF_RET+BPF_K, 2),
        BPF_STMT(BPF_LDX+BPF_W+BPF_IMM, 1),
        BPF_JUMP(BPF_JMP+BPF_JSET+BPF_X, 0, 2, 3),
        BPF_STMT(BPF_RET+BPF_K, 3),
        BPF_STMT(BPF_RET+BPF_K, 4),
        BPF_STMT(BPF_RET+BPF_K, 5),
        BPF_STMT(BPF_LDX+BPF_W+BPF_IMM, 2),
        BPF_JUMP(BPF_JMP+BPF_JSET+BPF_X, 0, 4, 1),
        BPF_STMT(BPF_RET+BPF_K, 6),
        BPF_STMT(BPF_LDX+BPF_W+BPF_IMM, 7),
        BPF_JUMP(BPF_JMP+BPF_JSET+BPF_X, 0, 0, 0),
        BPF_STMT(BPF_RET+BPF_K, 7),
        BPF_STMT(BPF_RET+BPF_K, 8)
    };

    bpfjit_func_t code;
    uint8_t pkt[8]; /* the program doesn't read any data */

    size_t insn_count = sizeof(insns) / sizeof(insns[0]);

    code = bpfjit_generate_code(NULL, insns, insn_count);
    assert(code != NULL);

    assert(jitcall(code, pkt, 1, 1) == 1);
    assert(jitcall(code, pkt, 2, 2) == 1);
    assert(jitcall(code, pkt, 3, 3) == 1);
    assert(jitcall(code, pkt, 4, 4) == 7);
    assert(jitcall(code, pkt, 5, 5) == 5);
    assert(jitcall(code, pkt, 6, 6) == 8);
    assert(jitcall(code, pkt, 7, 7) == 5);
    assert(jitcall(code, pkt, 8, 8) == 0);

    bpfjit_free_code(code);
}

/* Test JIT compilation of BPF_JMP+BPF_EQ+BPF_X with uninitialised A and X */
void tc_bpfjit_jmp_jeq_x_noinit_ax() {
    static struct bpf_insn insns[] = {
        BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_X, 0, 0, 1),
        BPF_STMT(BPF_RET+BPF_K, 10),
        BPF_STMT(BPF_RET+BPF_K, 11)
    };

    bpfjit_func_t code;
    uint8_t pkt[8]; /* the program doesn't read any data */

    size_t insn_count = sizeof(insns) / sizeof(insns[0]);

    code = bpfjit_generate_code(NULL, insns, insn_count);
    assert(code != NULL);

    assert(jitcall(code, pkt, 1, 1) == 10);

    bpfjit_free_code(code);
}

/* Test JIT compilation of BPF_JMP+BPF_EQ+BPF_X with uninitialised A */
void tc_bpfjit_jmp_jeq_x_noinit_a() {
    static struct bpf_insn insns[] = {
        BPF_STMT(BPF_LDX+BPF_W+BPF_LEN, 0), /* X > 0 */
        BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_X, 0, 0, 1),
        BPF_STMT(BPF_RET+BPF_K, 10),
        BPF_STMT(BPF_RET+BPF_K, 11)
    };

    bpfjit_func_t code;
    uint8_t pkt[8]; /* the program doesn't read any data */

    size_t insn_count = sizeof(insns) / sizeof(insns[0]);

    code = bpfjit_generate_code(NULL, insns, insn_count);
    assert(code != NULL);

    assert(jitcall(code, pkt, 1, 1) == 11);

    bpfjit_free_code(code);
}

/* Test JIT compilation of BPF_JMP+BPF_EQ+BPF_X with uninitialised X */
void tc_bpfjit_jmp_jeq_x_noinit_x() {
    static struct bpf_insn insns[] = {
        BPF_STMT(BPF_LD+BPF_LEN, 0), /* A > 0 */
        BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_X, 0, 0, 1),
        BPF_STMT(BPF_RET+BPF_K, 10),
        BPF_STMT(BPF_RET+BPF_K, 11)
    };

    bpfjit_func_t code;
    uint8_t pkt[8]; /* the program doesn't read any data */

    size_t insn_count = sizeof(insns) / sizeof(insns[0]);

    code = bpfjit_generate_code(NULL, insns, insn_count);
    assert(code != NULL);

    assert(jitcall(code, pkt, 1, 1) == 11);

    bpfjit_free_code(code);
}


/* Test JIT compilation of modulo logic of BPF_JMP+BPF_X operations */
void tc_bpfjit_jmp_modulo_x() {
    static struct bpf_insn insns[] = {
        BPF_STMT(BPF_LD+BPF_IMM, UINT32_C(0x7fffff77)),
        /* FFFFF770 << 4 = FFFFF770 */
        BPF_STMT(BPF_ALU+BPF_LSH+BPF_K, 4),

        BPF_STMT(BPF_LDX+BPF_W+BPF_IMM, UINT32_C(0xfffff770)),
        BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_X, 0, 1, 0),
        BPF_STMT(BPF_RET+BPF_K, 0),
        BPF_JUMP(BPF_JMP+BPF_JGT+BPF_X, 0, 0, 1),
        BPF_STMT(BPF_RET+BPF_K, 1),
        BPF_STMT(BPF_LDX+BPF_W+BPF_IMM, UINT32_C(0xfffff771)),
        BPF_JUMP(BPF_JMP+BPF_JGE+BPF_X, 0, 0, 1),
        BPF_STMT(BPF_RET+BPF_K, 2),
        BPF_STMT(BPF_LDX+BPF_W+BPF_IMM, UINT32_C(0xfffff770)),
        BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_X, 0, 0, 4),
        BPF_JUMP(BPF_JMP+BPF_JGT+BPF_X, 0, 3, 0),
        BPF_STMT(BPF_LDX+BPF_W+BPF_IMM, UINT32_C(0xfffff771)),
        BPF_JUMP(BPF_JMP+BPF_JGE+BPF_X, 0, 1, 0),
        BPF_STMT(BPF_JMP+BPF_JA, 1),
        BPF_STMT(BPF_RET+BPF_K, 3),

        /* FFFFF770+FFFFF770 = 00000001,FFFFEEE0 */
        BPF_STMT(BPF_ALU+BPF_ADD+BPF_K, UINT32_C(0xfffff770)),

        BPF_STMT(BPF_LDX+BPF_W+BPF_IMM, UINT32_C(0xffffeee0)),
        BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_X, 0, 1, 0),
        BPF_STMT(BPF_RET+BPF_K, 4),
        BPF_JUMP(BPF_JMP+BPF_JGT+BPF_X, 0, 0, 1),
        BPF_STMT(BPF_RET+BPF_K, 5),
        BPF_STMT(BPF_LDX+BPF_W+BPF_IMM, UINT32_C(0xffffeee1)),
        BPF_JUMP(BPF_JMP+BPF_JGE+BPF_X, 0, 0, 1),
        BPF_STMT(BPF_RET+BPF_K, 6),
        BPF_STMT(BPF_LDX+BPF_W+BPF_IMM, UINT32_C(0xffffeee0)),
        BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_X, 0, 0, 4),
        BPF_JUMP(BPF_JMP+BPF_JGT+BPF_X, 0, 3, 0),
        BPF_STMT(BPF_LDX+BPF_W+BPF_IMM, UINT32_C(0xffffeee1)),
        BPF_JUMP(BPF_JMP+BPF_JGE+BPF_X, 0, 1, 0),
        BPF_STMT(BPF_RET+BPF_K, UINT32_MAX),
        BPF_STMT(BPF_RET+BPF_K, 7)
    };

    uint8_t pkt[1]; /* the program doesn't read any data */

    size_t insn_count = sizeof(insns) / sizeof(insns[0]);

    assert(exec_prog(insns, insn_count, pkt, 1) == UINT32_MAX);
}

/* Test JIT compilation of BPF_LD+BPF_ABS */
void tc_bpfjit_ld_abs() {
    static struct bpf_insn insns[3][2] = {
        {
            BPF_STMT(BPF_LD+BPF_B+BPF_ABS, 5),
            BPF_STMT(BPF_RET+BPF_A, 0)
        },
        {
            BPF_STMT(BPF_LD+BPF_H+BPF_ABS, 5),
            BPF_STMT(BPF_RET+BPF_A, 0)
        },
        {
            BPF_STMT(BPF_LD+BPF_W+BPF_ABS, 5),
            BPF_STMT(BPF_RET+BPF_A, 0)
        }
    };

    static size_t lengths[3] = { 1, 2, 4 };
    static unsigned int expected[3] = { 0xde, 0xdead, 0xdeadbeef };

    size_t i, l;
    uint8_t *pkt = deadbeef_at_5;
    size_t pktsize = sizeof(deadbeef_at_5);

    size_t insn_count = sizeof(insns[0]) / sizeof(insns[0][0]);

    for (i = 0; i < 3; i++) {
        bpfjit_func_t code;

        code = bpfjit_generate_code(NULL, insns[i], insn_count);
        assert(code != NULL);

        for (l = 1; l < 5 + lengths[i]; l++) {
            assert(jitcall(code, pkt, l, l) == 0);
            assert(jitcall(code, pkt, pktsize, l) == 0);
        }

        l = 5 + lengths[i];
        assert(jitcall(code, pkt, l, l) == expected[i]);
        assert(jitcall(code, pkt, pktsize, l) == expected[i]);

        l = pktsize;
        assert(jitcall(code, pkt, l, l) == expected[i]);

        bpfjit_free_code(code);
    }
}

/* Test JIT compilation of BPF_LD+BPF_ABS with overflow in k+4 */
void tc_bpfjit_ld_abs_k_overflow() {
    static struct bpf_insn insns[12][3] = {
        {
            BPF_STMT(BPF_LD+BPF_H+BPF_ABS, UINT32_MAX),
            BPF_STMT(BPF_LD+BPF_B+BPF_ABS, 7),
            BPF_STMT(BPF_RET+BPF_K, 1)
        },
        {
            BPF_STMT(BPF_LD+BPF_H+BPF_ABS, UINT32_MAX - 1),
            BPF_STMT(BPF_LD+BPF_B+BPF_ABS, 7),
            BPF_STMT(BPF_RET+BPF_K, 1)
        },
        {
            BPF_STMT(BPF_LD+BPF_W+BPF_ABS, UINT32_MAX),
            BPF_STMT(BPF_LD+BPF_B+BPF_ABS, 7),
            BPF_STMT(BPF_RET+BPF_K, 1)
        },
        {
            BPF_STMT(BPF_LD+BPF_W+BPF_ABS, UINT32_MAX - 1),
            BPF_STMT(BPF_LD+BPF_B+BPF_ABS, 7),
            BPF_STMT(BPF_RET+BPF_K, 1)
        },
        {
            BPF_STMT(BPF_LD+BPF_W+BPF_ABS, UINT32_MAX - 2),
            BPF_STMT(BPF_LD+BPF_B+BPF_ABS, 7),
            BPF_STMT(BPF_RET+BPF_K, 1)
        },
        {
            BPF_STMT(BPF_LD+BPF_W+BPF_ABS, UINT32_MAX - 3),
            BPF_STMT(BPF_LD+BPF_B+BPF_ABS, 7),
            BPF_STMT(BPF_RET+BPF_K, 1)
        },
        {
            BPF_STMT(BPF_LD+BPF_B+BPF_ABS, 7),
            BPF_STMT(BPF_LD+BPF_H+BPF_ABS, UINT32_MAX),
            BPF_STMT(BPF_RET+BPF_K, 1)
        },
        {
            BPF_STMT(BPF_LD+BPF_B+BPF_ABS, 7),
            BPF_STMT(BPF_LD+BPF_H+BPF_ABS, UINT32_MAX - 1),
            BPF_STMT(BPF_RET+BPF_K, 1)
        },
        {
            BPF_STMT(BPF_LD+BPF_B+BPF_ABS, 7),
            BPF_STMT(BPF_LD+BPF_W+BPF_ABS, UINT32_MAX),
            BPF_STMT(BPF_RET+BPF_K, 1)
        },
        {
            BPF_STMT(BPF_LD+BPF_B+BPF_ABS, 7),
            BPF_STMT(BPF_LD+BPF_W+BPF_ABS, UINT32_MAX - 1),
            BPF_STMT(BPF_RET+BPF_K, 1)
        },
        {
            BPF_STMT(BPF_LD+BPF_B+BPF_ABS, 7),
            BPF_STMT(BPF_LD+BPF_W+BPF_ABS, UINT32_MAX - 2),
            BPF_STMT(BPF_RET+BPF_K, 1)
        },
        {
            BPF_STMT(BPF_LD+BPF_B+BPF_ABS, 7),
            BPF_STMT(BPF_LD+BPF_W+BPF_ABS, UINT32_MAX - 3),
            BPF_STMT(BPF_RET+BPF_K, 1)
        }
    };

    int i;
    uint8_t pkt[8] = { 0 };

    size_t insn_count = sizeof(insns[0]) / sizeof(insns[0][0]);

    for (i = 0; i < 3; i++) {
        assert(exec_prog(insns[i], insn_count, pkt, 8) == 0);
    }
}

/* Test JIT compilation of BPF_LD+BPF_IND */
void tc_bpfjit_ld_ind() {
    static struct bpf_insn insns[6][3] = {
        {
            BPF_STMT(BPF_LDX+BPF_W+BPF_IMM, 3),
            BPF_STMT(BPF_LD+BPF_B+BPF_IND, 2),
            BPF_STMT(BPF_RET+BPF_A, 0)
        },
        {
            BPF_STMT(BPF_LDX+BPF_W+BPF_IMM, 3),
            BPF_STMT(BPF_LD+BPF_H+BPF_IND, 2),
            BPF_STMT(BPF_RET+BPF_A, 0)
        },
        {
            BPF_STMT(BPF_LDX+BPF_W+BPF_IMM, 3),
            BPF_STMT(BPF_LD+BPF_W+BPF_IND, 2),
            BPF_STMT(BPF_RET+BPF_A, 0)
        },
        {
            BPF_STMT(BPF_LDX+BPF_W+BPF_IMM, 5),
            BPF_STMT(BPF_LD+BPF_B+BPF_IND, 0),
            BPF_STMT(BPF_RET+BPF_A, 0)
        },
        {
            BPF_STMT(BPF_LDX+BPF_W+BPF_IMM, 5),
            BPF_STMT(BPF_LD+BPF_H+BPF_IND, 0),
            BPF_STMT(BPF_RET+BPF_A, 0)
        },
        {
            BPF_STMT(BPF_LDX+BPF_W+BPF_IMM, 5),
            BPF_STMT(BPF_LD+BPF_W+BPF_IND, 0),
            BPF_STMT(BPF_RET+BPF_A, 0)
        }
    };

    static size_t lengths[6] = { 1, 2, 4, 1, 2, 4 };

    static unsigned int expected[6] = {
        0xde, 0xdead, 0xdeadbeef,
        0xde, 0xdead, 0xdeadbeef
    };

    size_t i, l;
    uint8_t *pkt = deadbeef_at_5;
    size_t pktsize = sizeof(deadbeef_at_5);

    size_t insn_count = sizeof(insns[0]) / sizeof(insns[0][0]);

    for (i = 0; i < 3; i++) {
        bpfjit_func_t code;

        code = bpfjit_generate_code(NULL, insns[i], insn_count);
        assert(code != NULL);

        for (l = 1; l < 5 + lengths[i]; l++) {
            assert(jitcall(code, pkt, l, l) == 0);
            assert(jitcall(code, pkt, pktsize, l) == 0);
        }

        l = 5 + lengths[i];
        assert(jitcall(code, pkt, l, l) == expected[i]);
        assert(jitcall(code, pkt, pktsize, l) == expected[i]);

        l = pktsize;
        assert(jitcall(code, pkt, l, l) == expected[i]);

        bpfjit_free_code(code);
    }
}

/* Test JIT compilation of BPF_LD+BPF_IND with overflow in k+4 */
void tc_bpfjit_ld_ind_k_overflow() {
    static struct bpf_insn insns[12][3] = {
        {
            BPF_STMT(BPF_LD+BPF_H+BPF_IND, UINT32_MAX),
            BPF_STMT(BPF_LD+BPF_H+BPF_IND, 7),
            BPF_STMT(BPF_RET+BPF_K, 1)
        },
        {
            BPF_STMT(BPF_LD+BPF_H+BPF_IND, UINT32_MAX - 1),
            BPF_STMT(BPF_LD+BPF_H+BPF_IND, 7),
            BPF_STMT(BPF_RET+BPF_K, 1)
        },
        {
            BPF_STMT(BPF_LD+BPF_W+BPF_IND, UINT32_MAX),
            BPF_STMT(BPF_LD+BPF_H+BPF_IND, 7),
            BPF_STMT(BPF_RET+BPF_K, 1)
        },
        {
            BPF_STMT(BPF_LD+BPF_W+BPF_IND, UINT32_MAX - 1),
            BPF_STMT(BPF_LD+BPF_H+BPF_IND, 7),
            BPF_STMT(BPF_RET+BPF_K, 1)
        },
        {
            BPF_STMT(BPF_LD+BPF_W+BPF_IND, UINT32_MAX - 2),
            BPF_STMT(BPF_LD+BPF_H+BPF_IND, 7),
            BPF_STMT(BPF_RET+BPF_K, 1)
        },
        {
            BPF_STMT(BPF_LD+BPF_W+BPF_IND, UINT32_MAX - 3),
            BPF_STMT(BPF_LD+BPF_H+BPF_IND, 7),
            BPF_STMT(BPF_RET+BPF_K, 1)
        },
        {
            BPF_STMT(BPF_LD+BPF_H+BPF_IND, 7),
            BPF_STMT(BPF_LD+BPF_H+BPF_IND, UINT32_MAX),
            BPF_STMT(BPF_RET+BPF_K, 1)
        },
        {
            BPF_STMT(BPF_LD+BPF_H+BPF_IND, 7),
            BPF_STMT(BPF_LD+BPF_H+BPF_IND, UINT32_MAX - 1),
            BPF_STMT(BPF_RET+BPF_K, 1)
        },
        {
            BPF_STMT(BPF_LD+BPF_H+BPF_IND, 7),
            BPF_STMT(BPF_LD+BPF_W+BPF_IND, UINT32_MAX),
            BPF_STMT(BPF_RET+BPF_K, 1)
        },
        {
            BPF_STMT(BPF_LD+BPF_H+BPF_IND, 7),
            BPF_STMT(BPF_LD+BPF_W+BPF_IND, UINT32_MAX - 1),
            BPF_STMT(BPF_RET+BPF_K, 1)
        },
        {
            BPF_STMT(BPF_LD+BPF_H+BPF_IND, 7),
            BPF_STMT(BPF_LD+BPF_W+BPF_IND, UINT32_MAX - 2),
            BPF_STMT(BPF_RET+BPF_K, 1)
        },
        {
            BPF_STMT(BPF_LD+BPF_H+BPF_IND, 7),
            BPF_STMT(BPF_LD+BPF_W+BPF_IND, UINT32_MAX - 3),
            BPF_STMT(BPF_RET+BPF_K, 1)
        }
    };

    int i;
    uint8_t pkt[8] = { 0 };

    size_t insn_count = sizeof(insns[0]) / sizeof(insns[0][0]);

    for (i = 0; i < 3; i++) {
        assert(exec_prog(insns[i], insn_count, pkt, 8) == 0);
    }
}

/* Test JIT compilation of BPF_LD+BPF_IND with overflow in X+4 */
void tc_bpfjit_ld_ind_x_overflow1() {
    static struct bpf_insn insns[] = {
        BPF_STMT(BPF_LD+BPF_LEN, 0),
        BPF_STMT(BPF_ALU+BPF_ADD+BPF_K, UINT32_C(0xffffffff)),
        BPF_STMT(BPF_MISC+BPF_TAX, 0),
        BPF_STMT(BPF_LD+BPF_B+BPF_IND, 0),
        BPF_STMT(BPF_RET+BPF_A, 0)
    };

    size_t i;
    bpfjit_func_t code;
    uint8_t pkt[8] = { 10, 20, 30, 40, 50, 60, 70, 80 };

    size_t insn_count = sizeof(insns) / sizeof(insns[0]);

    code = bpfjit_generate_code(NULL, insns, insn_count);
    assert(code != NULL);

    for (i = 1; i <= sizeof(pkt); i++) {
        //assert(bpf_filter(insns, pkt, i, i) == 10 * i);
        assert(jitcall(code, pkt, i, i) == 10 * i);
    }

    bpfjit_free_code(code);
}

/* Test JIT compilation of BPF_LD+BPF_IND with overflow in X+4 */
void tc_bpfjit_ld_ind_x_overflow2() {
    static struct bpf_insn insns[] = {
        BPF_STMT(BPF_LD+BPF_LEN, 0),
        BPF_STMT(BPF_ALU+BPF_ADD+BPF_K, UINT32_C(0xffffffff)),
        BPF_STMT(BPF_ST, 3),
        BPF_STMT(BPF_LDX+BPF_W+BPF_MEM, 3),
        BPF_STMT(BPF_LD+BPF_B+BPF_IND, 0),
        BPF_STMT(BPF_RET+BPF_A, 0)
    };

    size_t i;
    bpfjit_func_t code;
    uint8_t pkt[8] = { 10, 20, 30, 40, 50, 60, 70, 80 };

    size_t insn_count = sizeof(insns) / sizeof(insns[0]);

    code = bpfjit_generate_code(NULL, insns, insn_count);
    assert(code != NULL);

    for (i = 1; i <= sizeof(pkt); i++) {
        //assert(bpf_filter(insns, pkt, i, i) == 10 * i);
        assert(jitcall(code, pkt, i, i) == 10 * i);
    }

    bpfjit_free_code(code);
}

/* Test JIT compilation of BPF_LD+BPF_W+BPF_LEN */
void tc_bpfjit_ld_len() {
    static struct bpf_insn insns[] = {
        BPF_STMT(BPF_LD+BPF_W+BPF_LEN, 0),
        BPF_STMT(BPF_RET+BPF_A, 0)
    };

    size_t i;
    bpfjit_func_t code;
    uint8_t pkt[32]; /* the program doesn't read any data */

    size_t insn_count = sizeof(insns) / sizeof(insns[0]);

    code = bpfjit_generate_code(NULL, insns, insn_count);
    assert(code != NULL);

    for (i = 0; i < sizeof(pkt); i++)
        assert(jitcall(code, pkt, i, 1) == i);

    bpfjit_free_code(code);
}

/* Test JIT compilation of BPF_LD+BPF_IMM */
void tc_bpfjit_ld_imm() {
    static struct bpf_insn insns[] = {
        BPF_STMT(BPF_LD+BPF_IMM, UINT32_MAX),
        BPF_STMT(BPF_RET+BPF_A, 0)
    };

    uint8_t pkt[1]; /* the program doesn't read any data */
    size_t insn_count = sizeof(insns) / sizeof(insns[0]);

    assert(exec_prog(insns, insn_count, pkt, 1) == UINT32_MAX);
}

/* Test JIT compilation of BPF_LDX+BPF_IMM */
void tc_bpfjit_ldx_imm1() {
    static struct bpf_insn insns[] = {
        BPF_STMT(BPF_LDX+BPF_W+BPF_IMM, UINT32_MAX - 5),
        BPF_STMT(BPF_ALU+BPF_ADD+BPF_X, 0),
        BPF_STMT(BPF_RET+BPF_A, 0)
    };

    uint8_t pkt[1]; /* the program doesn't read any data */
    size_t insn_count = sizeof(insns) / sizeof(insns[0]);

    assert(exec_prog(insns, insn_count, pkt, 1) == UINT32_MAX - 5);
}

/* Test JIT compilation of BPF_LDX+BPF_IMM */
void tc_bpfjit_ldx_imm2() {
    static struct bpf_insn insns[] = {
        BPF_STMT(BPF_LDX+BPF_W+BPF_IMM, 5),
        BPF_STMT(BPF_LD+BPF_IMM, 5),
        BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_X, 0, 1, 0),
        BPF_STMT(BPF_RET+BPF_K, 7),
        BPF_STMT(BPF_RET+BPF_K, UINT32_MAX)
    };

    uint8_t pkt[1]; /* the program doesn't read any data */
    size_t insn_count = sizeof(insns) / sizeof(insns[0]);

    assert(exec_prog(insns, insn_count, pkt, 1) == UINT32_MAX);
}

/* Test JIT compilation of BPF_LDX+BPF_LEN */
void tc_bpfjit_ldx_len1() {
    static struct bpf_insn insns[] = {
        BPF_STMT(BPF_LDX+BPF_W+BPF_LEN, 0),
        BPF_STMT(BPF_ALU+BPF_ADD+BPF_X, 0),
        BPF_STMT(BPF_RET+BPF_A, 0)
    };

    size_t i;
    bpfjit_func_t code;
    uint8_t pkt[5]; /* the program doesn't read any data */

    size_t insn_count = sizeof(insns) / sizeof(insns[0]);

    code = bpfjit_generate_code(NULL, insns, insn_count);
    assert(code != NULL);

    for (i = 1; i < sizeof(pkt); i++) {
        assert(jitcall(code, pkt, i, 1) == i);
        assert(jitcall(code, pkt, i + 1, i) == i + 1);
    }

    bpfjit_free_code(code);
}

/* Test JIT compilation of BPF_LDX+BPF_LEN */
void tc_bpfjit_ldx_len2() {
    static struct bpf_insn insns[] = {
        BPF_STMT(BPF_LDX+BPF_W+BPF_LEN, 0),
        BPF_STMT(BPF_LD+BPF_IMM, 5),
        BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_X, 0, 1, 0),
        BPF_STMT(BPF_RET+BPF_K, 7),
        BPF_STMT(BPF_RET+BPF_K, UINT32_MAX)
    };

    bpfjit_func_t code;
    uint8_t pkt[5]; /* the program doesn't read any data */

    size_t insn_count = sizeof(insns) / sizeof(insns[0]);

    code = bpfjit_generate_code(NULL, insns, insn_count);
    assert(code != NULL);

    assert(jitcall(code, pkt, 5, 1) == UINT32_MAX);
    assert(jitcall(code, pkt, 6, 5) == 7);

    bpfjit_free_code(code);
}

/* Test JIT compilation of BPF_LDX+BPF_MSH */
void tc_bpfjit_ldx_msh() {
    static struct bpf_insn insns[] = {
        BPF_STMT(BPF_LDX+BPF_B+BPF_MSH, 1),
        BPF_STMT(BPF_ALU+BPF_ADD+BPF_X, 0),
        BPF_STMT(BPF_RET+BPF_A, 0)
    };

    uint8_t pkt[2] = { 0, 0x7a };

    size_t insn_count = sizeof(insns) / sizeof(insns[0]);

    assert(exec_prog(insns, insn_count, pkt, 2) == 40);
}

/* Test JIT compilation of BPF_MISC+BPF_TAX */
void tc_bpfjit_misc_tax() {
    static struct bpf_insn insns[] = {
        BPF_STMT(BPF_LD+BPF_IMM, 3),
        BPF_STMT(BPF_MISC+BPF_TAX, 0),
        BPF_STMT(BPF_LD+BPF_B+BPF_IND, 2),
        BPF_STMT(BPF_RET+BPF_A, 0)
    };

    uint8_t pkt[6] = { 0, 11, 22, 33, 44, 55 };
    size_t insn_count = sizeof(insns) / sizeof(insns[0]);

    assert(exec_prog(insns, insn_count, pkt, 6) == 55);
}

/* Test JIT compilation of BPF_MISC+BPF_TXA */
void tc_bpfjit_misc_txa() {
    static struct bpf_insn insns[] = {
        BPF_STMT(BPF_LDX+BPF_W+BPF_IMM, 391),
        BPF_STMT(BPF_MISC+BPF_TXA, 0),
        BPF_STMT(BPF_RET+BPF_A, 0)
    };

    uint8_t pkt[1]; /* the program doesn't read any data */
    size_t insn_count = sizeof(insns) / sizeof(insns[0]);

    assert(exec_prog(insns, insn_count, pkt, 1) == 391);
}

/* Test JIT compilation of BPF_ST */
void tc_bpfjit_st1() {
    static struct bpf_insn insns[] = {
        BPF_STMT(BPF_LD+BPF_W+BPF_LEN, 0),
        BPF_STMT(BPF_ST, 0),
        BPF_STMT(BPF_ALU+BPF_ADD+BPF_K, 1),
        BPF_STMT(BPF_LD+BPF_MEM, 0),
        BPF_STMT(BPF_RET+BPF_A, 0)
    };

    size_t i;
    bpfjit_func_t code;
    uint8_t pkt[16]; /* the program doesn't read any data */

    size_t insn_count = sizeof(insns) / sizeof(insns[0]);

    code = bpfjit_generate_code(NULL, insns, insn_count);
    assert(code != NULL);

    for (i = 1; i <= sizeof(pkt); i++)
        assert(jitcall(code, pkt, i, sizeof(pkt)) == i);

    bpfjit_free_code(code);
}

/* Test JIT compilation of BPF_ST */
void tc_bpfjit_st2() {
    static struct bpf_insn insns[] = {
        BPF_STMT(BPF_ST, 0),
        BPF_STMT(BPF_LD+BPF_W+BPF_LEN, 0),
        BPF_STMT(BPF_ST, BPF_MEMWORDS-1),
        BPF_STMT(BPF_LD+BPF_MEM, 0),
        BPF_STMT(BPF_RET+BPF_A, 0)
    };

    uint8_t pkt[1]; /* the program doesn't read any data */
    size_t insn_count = sizeof(insns) / sizeof(insns[0]);

    assert(exec_prog(insns, insn_count, pkt, 1) == 0);
}

/* Test JIT compilation of BPF_ST */
void tc_bpfjit_st3() {
    static struct bpf_insn insns[] = {
        BPF_STMT(BPF_LD+BPF_W+BPF_LEN, 0),
        BPF_STMT(BPF_ST, 0),
        BPF_STMT(BPF_ALU+BPF_ADD+BPF_K, 100),
        BPF_STMT(BPF_ST, BPF_MEMWORDS-1),
        BPF_STMT(BPF_ALU+BPF_ADD+BPF_K, 200),
        BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, 301, 2, 0),
        BPF_STMT(BPF_LD+BPF_MEM, BPF_MEMWORDS-1),
        BPF_STMT(BPF_RET+BPF_A, 0),
        BPF_STMT(BPF_LD+BPF_MEM, 0),
        BPF_STMT(BPF_RET+BPF_A, 0)
    };

    bpfjit_func_t code;
    uint8_t pkt[2]; /* the program doesn't read any data */

    size_t insn_count = sizeof(insns) / sizeof(insns[0]);

    code = bpfjit_generate_code(NULL, insns, insn_count);
    assert(code != NULL);

    assert(jitcall(code, pkt, 1, 1) == 1);
    assert(jitcall(code, pkt, 2, 2) == 102);

    bpfjit_free_code(code);
}

/* Test JIT compilation of BPF_ST */
void tc_bpfjit_st4() {
    static struct bpf_insn insns[] = {
        BPF_STMT(BPF_LD+BPF_W+BPF_LEN, 0),
        BPF_STMT(BPF_ST, 5),
        BPF_STMT(BPF_ALU+BPF_ADD+BPF_K, 100),
        BPF_STMT(BPF_ST, BPF_MEMWORDS-1),
        BPF_STMT(BPF_ALU+BPF_ADD+BPF_K, 200),
        BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, 301, 2, 0),
        BPF_STMT(BPF_LD+BPF_MEM, BPF_MEMWORDS-1),
        BPF_STMT(BPF_RET+BPF_A, 0),
        BPF_STMT(BPF_LD+BPF_MEM, 5),
        BPF_STMT(BPF_RET+BPF_A, 0)
    };

    bpfjit_func_t code;
    uint8_t pkt[2]; /* the program doesn't read any data */

    size_t insn_count = sizeof(insns) / sizeof(insns[0]);

    code = bpfjit_generate_code(NULL, insns, insn_count);
    assert(code != NULL);

    assert(jitcall(code, pkt, 1, 1) == 1);
    assert(jitcall(code, pkt, 2, 2) == 102);

    bpfjit_free_code(code);
}

/* Test JIT compilation of BPF_ST */
void tc_bpfjit_st5() {
    struct bpf_insn insns[5*BPF_MEMWORDS+2];
    size_t insn_count = sizeof(insns) / sizeof(insns[0]);

    size_t k;
    bpfjit_func_t code;
    uint8_t pkt[BPF_MEMWORDS]; /* the program doesn't read any data */

    memset(insns, 0, sizeof(insns));

    /* for each k do M[k] = k */
    for (k = 0; k < BPF_MEMWORDS; k++) {
        insns[2*k].code   = BPF_LD+BPF_IMM;
        insns[2*k].k      = 3*k;
        insns[2*k+1].code = BPF_ST;
        insns[2*k+1].k    = k;
    }

    /* load wirelen into A */
    insns[2*BPF_MEMWORDS].code = BPF_LD+BPF_W+BPF_LEN;

    /* for each k, if (A == k + 1) return M[k] */
    for (k = 0; k < BPF_MEMWORDS; k++) {
        insns[2*BPF_MEMWORDS+3*k+1].code = BPF_JMP+BPF_JEQ+BPF_K;
        insns[2*BPF_MEMWORDS+3*k+1].k    = k+1;
        insns[2*BPF_MEMWORDS+3*k+1].jt   = 0;
        insns[2*BPF_MEMWORDS+3*k+1].jf   = 2;
        insns[2*BPF_MEMWORDS+3*k+2].code = BPF_LD+BPF_MEM;
        insns[2*BPF_MEMWORDS+3*k+2].k    = k;
        insns[2*BPF_MEMWORDS+3*k+3].code = BPF_RET+BPF_A;
        insns[2*BPF_MEMWORDS+3*k+3].k    = 0;
    }

    insns[5*BPF_MEMWORDS+1].code = BPF_RET+BPF_K;
    insns[5*BPF_MEMWORDS+1].k    = UINT32_MAX;

    code = bpfjit_generate_code(NULL, insns, insn_count);
    assert(code != NULL);

    for (k = 1; k <= sizeof(pkt); k++)
        assert(jitcall(code, pkt, k, k) == 3*(k-1));

    bpfjit_free_code(code);
}

/* Test JIT compilation of BPF_STX */
void tc_bpfjit_stx1() {
    static struct bpf_insn insns[] = {
        BPF_STMT(BPF_LDX+BPF_W+BPF_LEN, 0),
        BPF_STMT(BPF_STX, 0),
        BPF_STMT(BPF_LDX+BPF_W+BPF_MEM, 0),
        BPF_STMT(BPF_ALU+BPF_ADD+BPF_X, 0),
        BPF_STMT(BPF_RET+BPF_A, 0)
    };

    size_t i;
    bpfjit_func_t code;
    uint8_t pkt[16]; /* the program doesn't read any data */

    size_t insn_count = sizeof(insns) / sizeof(insns[0]);

    code = bpfjit_generate_code(NULL, insns, insn_count);
    assert(code != NULL);

    for (i = 1; i <= sizeof(pkt); i++)
        assert(jitcall(code, pkt, i, sizeof(pkt)) == i);

    bpfjit_free_code(code);
}

/* Test JIT compilation of BPF_STX */
void tc_bpfjit_stx2() {
    static struct bpf_insn insns[] = {
        BPF_STMT(BPF_ST, 0),
        BPF_STMT(BPF_LDX+BPF_W+BPF_LEN, 0),
        BPF_STMT(BPF_STX, BPF_MEMWORDS-1),
        BPF_STMT(BPF_LDX+BPF_W+BPF_MEM, 0),
        BPF_STMT(BPF_MISC+BPF_TXA, 0),
        BPF_STMT(BPF_RET+BPF_A, 0)
    };

    uint8_t pkt[1]; /* the program doesn't read any data */
    size_t insn_count = sizeof(insns) / sizeof(insns[0]);

    assert(exec_prog(insns, insn_count, pkt, 1) == 0);
}

/* Test JIT compilation of BPF_STX */
void tc_bpfjit_stx3() {
    static struct bpf_insn insns[] = {
        BPF_STMT(BPF_STX, 6),
        BPF_STMT(BPF_ST, 1),
        BPF_STMT(BPF_LDX+BPF_W+BPF_LEN, 0),
        BPF_STMT(BPF_STX, 5),
        BPF_STMT(BPF_STX, 2),
        BPF_STMT(BPF_STX, 3),
        BPF_STMT(BPF_LDX+BPF_W+BPF_MEM, 1),
        BPF_STMT(BPF_ALU+BPF_ADD+BPF_X, 0),
        BPF_STMT(BPF_LDX+BPF_W+BPF_MEM, 2),
        BPF_STMT(BPF_ALU+BPF_ADD+BPF_X, 0),
        BPF_STMT(BPF_LDX+BPF_W+BPF_MEM, 3),
        BPF_STMT(BPF_ALU+BPF_ADD+BPF_X, 0),
        BPF_STMT(BPF_LDX+BPF_W+BPF_MEM, 5),
        BPF_STMT(BPF_ALU+BPF_ADD+BPF_X, 0),
        BPF_STMT(BPF_LDX+BPF_W+BPF_MEM, 6),
        BPF_STMT(BPF_ALU+BPF_ADD+BPF_X, 0),
        BPF_STMT(BPF_RET+BPF_A, 0)
    };

    size_t i;
    bpfjit_func_t code;
    uint8_t pkt[16]; /* the program doesn't read any data */

    size_t insn_count = sizeof(insns) / sizeof(insns[0]);

    code = bpfjit_generate_code(NULL, insns, insn_count);
    assert(code != NULL);

    for (i = 1; i <= sizeof(pkt); i++)
        assert(jitcall(code, pkt, i, sizeof(pkt)) == 3 * i);

    bpfjit_free_code(code);
}

/* Test JIT compilation of BPF_STX */
void tc_bpfjit_stx4() {
    struct bpf_insn insns[5*BPF_MEMWORDS+2];
    size_t insn_count = sizeof(insns) / sizeof(insns[0]);

    size_t k;
    bpfjit_func_t code;
    uint8_t pkt[BPF_MEMWORDS]; /* the program doesn't read any data */

    memset(insns, 0, sizeof(insns));

    /* for each k do M[k] = k */
    for (k = 0; k < BPF_MEMWORDS; k++) {
        insns[2*k].code   = BPF_LDX+BPF_W+BPF_IMM;
        insns[2*k].k      = 3*k;
        insns[2*k+1].code = BPF_STX;
        insns[2*k+1].k    = k;
    }

    /* load wirelen into A */
    insns[2*BPF_MEMWORDS].code = BPF_LD+BPF_W+BPF_LEN;

    /* for each k, if (A == k + 1) return M[k] */
    for (k = 0; k < BPF_MEMWORDS; k++) {
        insns[2*BPF_MEMWORDS+3*k+1].code = BPF_JMP+BPF_JEQ+BPF_K;
        insns[2*BPF_MEMWORDS+3*k+1].k    = k+1;
        insns[2*BPF_MEMWORDS+3*k+1].jt   = 0;
        insns[2*BPF_MEMWORDS+3*k+1].jf   = 2;
        insns[2*BPF_MEMWORDS+3*k+2].code = BPF_LD+BPF_MEM;
        insns[2*BPF_MEMWORDS+3*k+2].k    = k;
        insns[2*BPF_MEMWORDS+3*k+3].code = BPF_RET+BPF_A;
        insns[2*BPF_MEMWORDS+3*k+3].k    = 0;
    }

    insns[5*BPF_MEMWORDS+1].code = BPF_RET+BPF_K;
    insns[5*BPF_MEMWORDS+1].k    = UINT32_MAX;

    code = bpfjit_generate_code(NULL, insns, insn_count);
    assert(code != NULL);

    for (k = 1; k <= sizeof(pkt); k++)
        assert(jitcall(code, pkt, k, k) == 3*(k-1));

    bpfjit_free_code(code);
}

/* Test JIT compilation of length optimization to BPF_LD+BPF_ABS */
void tc_bpfjit_opt_ld_abs_1() {
    static struct bpf_insn insns[] = {
        BPF_STMT(BPF_LD+BPF_H+BPF_ABS, 12),
        BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, 0x800, 0, 8),
        BPF_STMT(BPF_LD+BPF_W+BPF_ABS, 26),
        BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, 0x8003700f, 0, 2),
        BPF_STMT(BPF_LD+BPF_W+BPF_ABS, 30),
        BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, 0x80037023, 3, 4),
        BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, 0x80037023, 0, 3),
        BPF_STMT(BPF_LD+BPF_W+BPF_ABS, 30),
        BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, 0x8003700f, 0, 1),
        BPF_STMT(BPF_RET+BPF_K, UINT32_MAX),
        BPF_STMT(BPF_RET+BPF_K, 0),
    };

    size_t i, j;
    bpfjit_func_t code;
    uint8_t pkt[2][34] = {
        {
            0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 0x08, 0x00,
            14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25,
            0x80, 0x03, 0x70, 0x0f,
            0x80, 0x03, 0x70, 0x23
        },
        {
            0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 0x08, 0x00,
            14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25,
            0x80, 0x03, 0x70, 0x23,
            0x80, 0x03, 0x70, 0x0f
        }
    };

    size_t insn_count = sizeof(insns) / sizeof(insns[0]);


    code = bpfjit_generate_code(NULL, insns, insn_count);
    assert(code != NULL);

    for (i = 0; i < 2; i++) {
        for (j = 1; j < sizeof(pkt[i]); j++)
            assert(jitcall(code, pkt[i], j, j) == 0);
        assert(jitcall(code, pkt[i], j, j) == UINT32_MAX);
    }

    bpfjit_free_code(code);
}

/* Test JIT compilation of length optimization to BPF_LD+BPF_ABS */
void tc_bpfjit_opt_ld_abs_2() {
    static struct bpf_insn insns[] = {
        BPF_STMT(BPF_LD+BPF_W+BPF_ABS, 26),
        BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, 0x8003700f, 0, 2),
        BPF_STMT(BPF_LD+BPF_W+BPF_ABS, 30),
        BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, 0x80037023, 3, 6),
        BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, 0x80037023, 0, 5),
        BPF_STMT(BPF_LD+BPF_W+BPF_ABS, 30),
        BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, 0x8003700f, 0, 3),
        BPF_STMT(BPF_LD+BPF_H+BPF_ABS, 12),
        BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, 0x800, 0, 1),
        BPF_STMT(BPF_RET+BPF_K, UINT32_MAX),
        BPF_STMT(BPF_RET+BPF_K, 0),
    };

    size_t i, j;
    bpfjit_func_t code;
    uint8_t pkt[2][34] = {
        {
            0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 0x08, 0x00,
            14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25,
            0x80, 0x03, 0x70, 0x0f,
            0x80, 0x03, 0x70, 0x23
        },
        {
            0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 0x08, 0x00,
            14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25,
            0x80, 0x03, 0x70, 0x23,
            0x80, 0x03, 0x70, 0x0f
        }
    };

    size_t insn_count = sizeof(insns) / sizeof(insns[0]);


    code = bpfjit_generate_code(NULL, insns, insn_count);
    assert(code != NULL);

    for (i = 0; i < 2; i++) {
        for (j = 1; j < sizeof(pkt[i]); j++)
            assert(jitcall(code, pkt[i], j, j) == 0);
        assert(jitcall(code, pkt[i], j, j) == UINT32_MAX);
    }

    bpfjit_free_code(code);
}

/* Test JIT compilation of length optimization to BPF_LD+BPF_ABS */
void tc_bpfjit_opt_ld_abs_3() {
    static struct bpf_insn insns[] = {
        BPF_STMT(BPF_LD+BPF_W+BPF_ABS, 30),
        BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, 0x80037023, 0, 2),
        BPF_STMT(BPF_LD+BPF_W+BPF_ABS, 26),
        BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, 0x8003700f, 3, 6),
        BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, 0x8003700f, 0, 5),
        BPF_STMT(BPF_LD+BPF_W+BPF_ABS, 26),
        BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, 0x80037023, 0, 3),
        BPF_STMT(BPF_LD+BPF_H+BPF_ABS, 12),
        BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, 0x800, 0, 1),
        BPF_STMT(BPF_RET+BPF_K, UINT32_MAX),
        BPF_STMT(BPF_RET+BPF_K, 0),
    };

    size_t i, j;
    bpfjit_func_t code;
    uint8_t pkt[2][34] = {
        {
            0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 0x08, 0x00,
            14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25,
            0x80, 0x03, 0x70, 0x0f,
            0x80, 0x03, 0x70, 0x23
        },
        {
            0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 0x08, 0x00,
            14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25,
            0x80, 0x03, 0x70, 0x23,
            0x80, 0x03, 0x70, 0x0f
        }
    };

    size_t insn_count = sizeof(insns) / sizeof(insns[0]);


    code = bpfjit_generate_code(NULL, insns, insn_count);
    assert(code != NULL);

    for (i = 0; i < 2; i++) {
        for (j = 1; j < sizeof(pkt[i]); j++)
            assert(jitcall(code, pkt[i], j, j) == 0);
        assert(jitcall(code, pkt[i], j, j) == UINT32_MAX);
    }

    bpfjit_free_code(code);
}

/* Test JIT compilation of length optimization to BPF_LD+BPF_IND */
void tc_bpfjit_opt_ld_ind_1() {
    static struct bpf_insn insns[] = {
        BPF_STMT(BPF_LDX+BPF_W+BPF_IMM, 12),
        BPF_STMT(BPF_LD+BPF_H+BPF_IND, 0),
        BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, 0x800, 0, 8),
        BPF_STMT(BPF_LD+BPF_W+BPF_IND, 14),
        BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, 0x8003700f, 0, 2),
        BPF_STMT(BPF_LD+BPF_W+BPF_IND, 18),
        BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, 0x80037023, 3, 4),
        BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, 0x80037023, 0, 3),
        BPF_STMT(BPF_LD+BPF_W+BPF_IND, 18),
        BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, 0x8003700f, 0, 1),
        BPF_STMT(BPF_RET+BPF_K, UINT32_MAX),
        BPF_STMT(BPF_RET+BPF_K, 0),
    };

    size_t i, j;
    bpfjit_func_t code;
    uint8_t pkt[2][34] = {
        {
            0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 0x08, 0x00,
            14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25,
            0x80, 0x03, 0x70, 0x0f,
            0x80, 0x03, 0x70, 0x23
        },
        {
            0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 0x08, 0x00,
            14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25,
            0x80, 0x03, 0x70, 0x23,
            0x80, 0x03, 0x70, 0x0f
        }
    };

    size_t insn_count = sizeof(insns) / sizeof(insns[0]);


    code = bpfjit_generate_code(NULL, insns, insn_count);
    assert(code != NULL);

    for (i = 0; i < 2; i++) {
        for (j = 1; j < sizeof(pkt[i]); j++)
            assert(jitcall(code, pkt[i], j, j) == 0);
        assert(jitcall(code, pkt[i], j, j) == UINT32_MAX);
    }

    bpfjit_free_code(code);
}

/* Test JIT compilation of length optimization to BPF_LD+BPF_IND */
void tc_bpfjit_opt_ld_ind_2() {
    static struct bpf_insn insns[] = {
        BPF_STMT(BPF_LDX+BPF_W+BPF_IMM, 0),
        BPF_STMT(BPF_LD+BPF_W+BPF_IND, 26),
        BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, 0x8003700f, 0, 2),
        BPF_STMT(BPF_LD+BPF_W+BPF_IND, 30),
        BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, 0x80037023, 3, 6),
        BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, 0x80037023, 0, 5),
        BPF_STMT(BPF_LD+BPF_W+BPF_IND, 30),
        BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, 0x8003700f, 0, 3),
        BPF_STMT(BPF_LD+BPF_H+BPF_IND, 12),
        BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, 0x800, 0, 1),
        BPF_STMT(BPF_RET+BPF_K, UINT32_MAX),
        BPF_STMT(BPF_RET+BPF_K, 0),
    };

    size_t i, j;
    bpfjit_func_t code;
    uint8_t pkt[2][34] = {
        {
            0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 0x08, 0x00,
            14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25,
            0x80, 0x03, 0x70, 0x0f,
            0x80, 0x03, 0x70, 0x23
        },
        {
            0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 0x08, 0x00,
            14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25,
            0x80, 0x03, 0x70, 0x23,
            0x80, 0x03, 0x70, 0x0f
        }
    };

    size_t insn_count = sizeof(insns) / sizeof(insns[0]);


    code = bpfjit_generate_code(NULL, insns, insn_count);
    assert(code != NULL);

    for (i = 0; i < 2; i++) {
        for (j = 1; j < sizeof(pkt[i]); j++)
            assert(jitcall(code, pkt[i], j, j) == 0);
        assert(jitcall(code, pkt[i], j, j) == UINT32_MAX);
    }

    bpfjit_free_code(code);
}

/* Test JIT compilation of length optimization to BPF_LD+BPF_IND */
void tc_bpfjit_opt_ld_ind_3() {
    static struct bpf_insn insns[] = {
        BPF_STMT(BPF_LDX+BPF_W+BPF_IMM, 15),
        BPF_STMT(BPF_LD+BPF_W+BPF_IND, 15),
        BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, 0x80037023, 0, 2),
        BPF_STMT(BPF_LD+BPF_W+BPF_IND, 11),
        BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, 0x8003700f, 3, 7),
        BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, 0x8003700f, 0, 6),
        BPF_STMT(BPF_LD+BPF_W+BPF_IND, 11),
        BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, 0x80037023, 0, 4),
        BPF_STMT(BPF_LDX+BPF_W+BPF_IMM, 0),
        BPF_STMT(BPF_LD+BPF_H+BPF_IND, 12),
        BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, 0x800, 0, 1),
        BPF_STMT(BPF_RET+BPF_K, UINT32_MAX),
        BPF_STMT(BPF_RET+BPF_K, 0),
    };

    size_t i, j;
    bpfjit_func_t code;
    uint8_t pkt[2][34] = {
        {
            0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 0x08, 0x00,
            14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25,
            0x80, 0x03, 0x70, 0x0f,
            0x80, 0x03, 0x70, 0x23
        },
        {
            0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 0x08, 0x00,
            14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25,
            0x80, 0x03, 0x70, 0x23,
            0x80, 0x03, 0x70, 0x0f
        }
    };

    size_t insn_count = sizeof(insns) / sizeof(insns[0]);


    code = bpfjit_generate_code(NULL, insns, insn_count);
    assert(code != NULL);

    for (i = 0; i < 2; i++) {
        for (j = 1; j < sizeof(pkt[i]); j++)
            assert(jitcall(code, pkt[i], j, j) == 0);
        assert(jitcall(code, pkt[i], j, j) == UINT32_MAX);
    }

    bpfjit_free_code(code);
}

/* Test JIT compilation of length optimization to BPF_LD+BPF_IND */
void tc_bpfjit_opt_ld_ind_4() {
    static struct bpf_insn insns[] = {
        BPF_STMT(BPF_LDX+BPF_W+BPF_IMM, 11),
        BPF_STMT(BPF_LD+BPF_W+BPF_IND, 19),
        BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, 0x80037023, 0, 2),
        BPF_STMT(BPF_LD+BPF_W+BPF_IND, 15),
        BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, 0x8003700f, 3, 7),
        BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, 0x8003700f, 0, 6),
        BPF_STMT(BPF_LD+BPF_W+BPF_IND, 15),
        BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, 0x80037023, 0, 4),
        BPF_STMT(BPF_LDX+BPF_W+BPF_IMM, 0),
        BPF_STMT(BPF_LD+BPF_H+BPF_IND, 12),
        BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, 0x800, 0, 1),
        BPF_STMT(BPF_RET+BPF_K, UINT32_MAX),
        BPF_STMT(BPF_RET+BPF_K, 0),
    };

    size_t i, j;
    bpfjit_func_t code;
    uint8_t pkt[2][34] = {
        {
            0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 0x08, 0x00,
            14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25,
            0x80, 0x03, 0x70, 0x0f,
            0x80, 0x03, 0x70, 0x23
        },
        {
            0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 0x08, 0x00,
            14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25,
            0x80, 0x03, 0x70, 0x23,
            0x80, 0x03, 0x70, 0x0f
        }
    };

    size_t insn_count = sizeof(insns) / sizeof(insns[0]);

    code = bpfjit_generate_code(NULL, insns, insn_count);
    assert(code != NULL);

    for (i = 0; i < 2; i++) {
        for (j = 1; j < sizeof(pkt[i]); j++)
            assert(jitcall(code, pkt[i], j, j) == 0);
        assert(jitcall(code, pkt[i], j, j) == UINT32_MAX);
    }

    bpfjit_free_code(code);
}

/* Test JIT compilation of a single BPF_JMP+BPF_JA */
void tc_bpfjit_abc_ja() {
    static struct bpf_insn insns[] = {
        BPF_STMT(BPF_LD+BPF_B+BPF_ABS, 3), /* min. length 4 */
        BPF_STMT(BPF_JMP+BPF_JA, 2),
        BPF_STMT(BPF_LD+BPF_B+BPF_ABS, UINT32_MAX - 1),
        BPF_STMT(BPF_RET+BPF_K, 0),
        BPF_STMT(BPF_LD+BPF_W+BPF_ABS, 2), /* min. length 6 */
        BPF_STMT(BPF_RET+BPF_A, 0),
        BPF_STMT(BPF_RET+BPF_K, 1),
        BPF_STMT(BPF_LD+BPF_B+BPF_ABS, 6),
        BPF_STMT(BPF_RET+BPF_K, 2),
        BPF_STMT(BPF_LD+BPF_B+BPF_ABS, 7),
        BPF_STMT(BPF_RET+BPF_K, 3),
    };

    bpfjit_func_t code;
    uint8_t pkt[6] = {0, 0, /* UINT32_MAX: */ 255, 255, 255, 255};

    size_t insn_count = sizeof(insns) / sizeof(insns[0]);

    code = bpfjit_generate_code(NULL, insns, insn_count);
    assert(code != NULL);

    assert(jitcall(code, pkt, 1, 1) == 0);
    assert(jitcall(code, pkt, 2, 2) == 0);
    assert(jitcall(code, pkt, 3, 3) == 0);
    assert(jitcall(code, pkt, 4, 4) == 0);
    assert(jitcall(code, pkt, 5, 5) == 0);
    assert(jitcall(code, pkt, 6, 6) == UINT32_MAX);

    bpfjit_free_code(code);
}

/* Test JIT compilation when BPF_JMP+BPF_JA jumps over all loads */
void tc_bpfjit_abc_ja_over() {
    static struct bpf_insn insns[] = {
        BPF_STMT(BPF_JMP+BPF_JA, 2),
        BPF_STMT(BPF_LD+BPF_B+BPF_ABS, 3),
        BPF_STMT(BPF_RET+BPF_K, 0),
        BPF_STMT(BPF_RET+BPF_K, UINT32_MAX),
        BPF_STMT(BPF_LD+BPF_B+BPF_ABS, 4),
        BPF_STMT(BPF_RET+BPF_K, 1),
        BPF_STMT(BPF_LD+BPF_B+BPF_ABS, 5),
        BPF_STMT(BPF_RET+BPF_K, 2),
        BPF_STMT(BPF_LD+BPF_B+BPF_ABS, 6),
        BPF_STMT(BPF_RET+BPF_K, 3),
    };

    uint8_t pkt[1]; /* the program doesn't read any data */
    size_t insn_count = sizeof(insns) / sizeof(insns[0]);

    assert(exec_prog(insns, insn_count, pkt, 1) == UINT32_MAX);
}

/* Test ABC optimization of a chain of BPF_LD instructions
 * with exits leading to a single BPF_RET */
void tc_bpfjit_abc_ld_chain() {
    static struct bpf_insn insns[] = {
        BPF_STMT(BPF_LD+BPF_B+BPF_ABS, 3), /* min. length 4 */
        BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, 8, 0, 4),
        BPF_STMT(BPF_LD+BPF_H+BPF_ABS, 4), /* min. length 6 */
        BPF_JUMP(BPF_JMP+BPF_JGE+BPF_K, 7, 0, 2),
        BPF_STMT(BPF_LD+BPF_W+BPF_ABS, 6), /* min. length 10 */
        BPF_JUMP(BPF_JMP+BPF_JGT+BPF_K, 6, 0, 1),
        BPF_STMT(BPF_RET+BPF_K, 123456789),
        BPF_STMT(BPF_RET+BPF_K, 987654321),
    };

    bpfjit_func_t code;
    uint8_t pkt[10] = {};

    size_t insn_count = sizeof(insns) / sizeof(insns[0]);

    code = bpfjit_generate_code(NULL, insns, insn_count);
    assert(code != NULL);

    /* Packet is too short. */
    assert(jitcall(code, pkt, 1, 1) == 0);
    assert(jitcall(code, pkt, 2, 2) == 0);
    assert(jitcall(code, pkt, 3, 3) == 0);

    /* !(pkt[3] == 8) => return 123456789 */
    assert(jitcall(code, pkt, 4, 4) == 123456789);
    assert(jitcall(code, pkt, 5, 5) == 123456789);
    assert(jitcall(code, pkt, 6, 6) == 123456789);
    assert(jitcall(code, pkt, 7, 7) == 123456789);
    assert(jitcall(code, pkt, 8, 8) == 123456789);
    assert(jitcall(code, pkt, 9, 9) == 123456789);

    /* !(pkt[4:2] >= 7) => too short or return 123456789 */
    pkt[3] = 8;
    assert(jitcall(code, pkt, 1, 1) == 0);
    assert(jitcall(code, pkt, 2, 2) == 0);
    assert(jitcall(code, pkt, 3, 3) == 0);
    assert(jitcall(code, pkt, 4, 4) == 0);
    assert(jitcall(code, pkt, 5, 5) == 0);
    assert(jitcall(code, pkt, 6, 6) == 123456789);
    assert(jitcall(code, pkt, 9, 9) == 123456789);

    /* !(pkt[6:4] > 6) => too short or return 987654321 */
    pkt[4] = pkt[5] = 1;
    assert(jitcall(code, pkt, 1, 1) == 0);
    assert(jitcall(code, pkt, 2, 2) == 0);
    assert(jitcall(code, pkt, 3, 3) == 0);
    assert(jitcall(code, pkt, 4, 4) == 0);
    assert(jitcall(code, pkt, 5, 5) == 0);
    assert(jitcall(code, pkt, 6, 6) == 0);
    assert(jitcall(code, pkt, 7, 7) == 0);
    assert(jitcall(code, pkt, 8, 8) == 0);
    assert(jitcall(code, pkt, 9, 9) == 0);
    assert(jitcall(code, pkt, 10, 10) == 987654321);

    /* (pkt[6:4] > 6) => too short or return 123456789 */
    pkt[6] = pkt[7] = pkt[8] = pkt[9] = 1;
    assert(jitcall(code, pkt, 1, 1) == 0);
    assert(jitcall(code, pkt, 2, 2) == 0);
    assert(jitcall(code, pkt, 3, 3) == 0);
    assert(jitcall(code, pkt, 4, 4) == 0);
    assert(jitcall(code, pkt, 5, 5) == 0);
    assert(jitcall(code, pkt, 6, 6) == 0);
    assert(jitcall(code, pkt, 7, 7) == 0);
    assert(jitcall(code, pkt, 8, 8) == 0);
    assert(jitcall(code, pkt, 9, 9) == 0);
    assert(jitcall(code, pkt, 10, 10) == 123456789);

    bpfjit_free_code(code);
}

/* Test the first example from bpf(4) - accept Reverse ARP requests */
void tc_bpfjit_examples_1() {
    /*
     * The following filter is taken from the Reverse ARP
     * Daemon. It accepts only Reverse ARP requests.
     */
    struct bpf_insn insns[] = {
        BPF_STMT(BPF_LD+BPF_H+BPF_ABS, 12),
        BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, 0x8035, 0, 3),
        BPF_STMT(BPF_LD+BPF_H+BPF_ABS, 20),
        BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, 3, 0, 1),
        BPF_STMT(BPF_RET+BPF_K, 42),
        BPF_STMT(BPF_RET+BPF_K, 0),
    };

    bpfjit_func_t code;
    uint8_t pkt[22] = {};

    size_t insn_count = sizeof(insns) / sizeof(insns[0]);

    code = bpfjit_generate_code(NULL, insns, insn_count);
    assert(code != NULL);

    /* Packet is too short. */
    assert(jitcall(code, pkt, 1, 1) == 0);
    assert(jitcall(code, pkt, 2, 2) == 0);
    assert(jitcall(code, pkt, 3, 3) == 0);
    assert(jitcall(code, pkt, 4, 4) == 0);
    assert(jitcall(code, pkt, 5, 5) == 0);
    assert(jitcall(code, pkt, 6, 6) == 0);
    assert(jitcall(code, pkt, 7, 7) == 0);
    assert(jitcall(code, pkt, 8, 8) == 0);
    assert(jitcall(code, pkt, 9, 9) == 0);
    assert(jitcall(code, pkt, 10, 10) == 0);
    assert(jitcall(code, pkt, 11, 11) == 0);
    assert(jitcall(code, pkt, 12, 12) == 0);
    assert(jitcall(code, pkt, 13, 13) == 0);
    assert(jitcall(code, pkt, 14, 14) == 0);
    assert(jitcall(code, pkt, 15, 15) == 0);
    assert(jitcall(code, pkt, 16, 16) == 0);
    assert(jitcall(code, pkt, 17, 17) == 0);
    assert(jitcall(code, pkt, 18, 18) == 0);
    assert(jitcall(code, pkt, 19, 19) == 0);
    assert(jitcall(code, pkt, 20, 20) == 0);
    assert(jitcall(code, pkt, 21, 21) == 0);

    /* The packet doesn't match. */
    assert(jitcall(code, pkt, 22, 22) == 0);

    /* Still no match after setting the protocol field. */
    pkt[12] = 0x80; pkt[13] = 0x35;
    assert(jitcall(code, pkt, 22, 22) == 0);

    /* Set RARP message type. */
    pkt[21] = 3;
    assert(jitcall(code, pkt, 22, 22) == 42);

    /* Packet is too short. */
    assert(jitcall(code, pkt, 1, 1) == 0);
    assert(jitcall(code, pkt, 2, 2) == 0);
    assert(jitcall(code, pkt, 3, 3) == 0);
    assert(jitcall(code, pkt, 4, 4) == 0);
    assert(jitcall(code, pkt, 5, 5) == 0);
    assert(jitcall(code, pkt, 6, 6) == 0);
    assert(jitcall(code, pkt, 7, 7) == 0);
    assert(jitcall(code, pkt, 8, 8) == 0);
    assert(jitcall(code, pkt, 9, 9) == 0);
    assert(jitcall(code, pkt, 10, 10) == 0);
    assert(jitcall(code, pkt, 11, 11) == 0);
    assert(jitcall(code, pkt, 12, 12) == 0);
    assert(jitcall(code, pkt, 13, 13) == 0);
    assert(jitcall(code, pkt, 14, 14) == 0);
    assert(jitcall(code, pkt, 15, 15) == 0);
    assert(jitcall(code, pkt, 16, 16) == 0);
    assert(jitcall(code, pkt, 17, 17) == 0);
    assert(jitcall(code, pkt, 18, 18) == 0);
    assert(jitcall(code, pkt, 19, 19) == 0);
    assert(jitcall(code, pkt, 20, 20) == 0);
    assert(jitcall(code, pkt, 21, 21) == 0);

    /* Change RARP message type. */
    pkt[20] = 3;
    assert(jitcall(code, pkt, 22, 22) == 0);

    bpfjit_free_code(code);
}

/* Test the second example from bpf(4) -
 * accept IP packets between two specified hosts
 */
void tc_bpfjit_examples_2() {
    /*
     * This filter accepts only IP packets between host 128.3.112.15
     * and 128.3.112.35.
     */
    static struct bpf_insn insns[] = {
        BPF_STMT(BPF_LD+BPF_H+BPF_ABS, 12),
        BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, 0x0800, 0, 8),
        BPF_STMT(BPF_LD+BPF_W+BPF_ABS, 26),
        BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, 0x8003700f, 0, 2),
        BPF_STMT(BPF_LD+BPF_W+BPF_ABS, 30),
        BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, 0x80037023, 3, 4),
        BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, 0x80037023, 0, 3),
        BPF_STMT(BPF_LD+BPF_W+BPF_ABS, 30),
        BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, 0x8003700f, 0, 1),
        BPF_STMT(BPF_RET+BPF_K, UINT32_MAX),
        BPF_STMT(BPF_RET+BPF_K, 0),
    };

    bpfjit_func_t code;
    uint8_t pkt[34] = {};

    size_t insn_count = sizeof(insns) / sizeof(insns[0]);

    code = bpfjit_generate_code(NULL, insns, insn_count);
    assert(code != NULL);

    /* Packet is too short. */
    assert(jitcall(code, pkt, 1, 1) == 0);
    assert(jitcall(code, pkt, 2, 2) == 0);
    assert(jitcall(code, pkt, 3, 3) == 0);
    assert(jitcall(code, pkt, 4, 4) == 0);
    assert(jitcall(code, pkt, 5, 5) == 0);
    assert(jitcall(code, pkt, 6, 6) == 0);
    assert(jitcall(code, pkt, 7, 7) == 0);
    assert(jitcall(code, pkt, 8, 8) == 0);
    assert(jitcall(code, pkt, 9, 9) == 0);
    assert(jitcall(code, pkt, 10, 10) == 0);
    assert(jitcall(code, pkt, 11, 11) == 0);
    assert(jitcall(code, pkt, 12, 12) == 0);
    assert(jitcall(code, pkt, 13, 13) == 0);
    assert(jitcall(code, pkt, 14, 14) == 0);
    assert(jitcall(code, pkt, 15, 15) == 0);
    assert(jitcall(code, pkt, 16, 16) == 0);
    assert(jitcall(code, pkt, 17, 17) == 0);
    assert(jitcall(code, pkt, 18, 18) == 0);
    assert(jitcall(code, pkt, 19, 19) == 0);
    assert(jitcall(code, pkt, 20, 20) == 0);
    assert(jitcall(code, pkt, 21, 21) == 0);
    assert(jitcall(code, pkt, 22, 22) == 0);
    assert(jitcall(code, pkt, 23, 23) == 0);
    assert(jitcall(code, pkt, 24, 24) == 0);
    assert(jitcall(code, pkt, 25, 25) == 0);
    assert(jitcall(code, pkt, 26, 26) == 0);
    assert(jitcall(code, pkt, 27, 27) == 0);
    assert(jitcall(code, pkt, 28, 28) == 0);
    assert(jitcall(code, pkt, 29, 29) == 0);
    assert(jitcall(code, pkt, 30, 30) == 0);
    assert(jitcall(code, pkt, 31, 31) == 0);
    assert(jitcall(code, pkt, 32, 32) == 0);
    assert(jitcall(code, pkt, 33, 33) == 0);

    /* The packet doesn't match. */
    assert(jitcall(code, pkt, 34, 34) == 0);

    /* Still no match after setting the protocol field. */
    pkt[12] = 8;
    assert(jitcall(code, pkt, 34, 34) == 0);

    pkt[26] = 128; pkt[27] = 3; pkt[28] = 112; pkt[29] = 15;
    assert(jitcall(code, pkt, 34, 34) == 0);

    pkt[30] = 128; pkt[31] = 3; pkt[32] = 112; pkt[33] = 35;
    assert(jitcall(code, pkt, 34, 34) == UINT32_MAX);

    /* Swap the ip addresses. */
    pkt[26] = 128; pkt[27] = 3; pkt[28] = 112; pkt[29] = 35;
    assert(jitcall(code, pkt, 34, 34) == 0);

    pkt[30] = 128; pkt[31] = 3; pkt[32] = 112; pkt[33] = 15;
    assert(jitcall(code, pkt, 34, 34) == UINT32_MAX);

    /* Packet is too short. */
    assert(jitcall(code, pkt, 1, 1) == 0);
    assert(jitcall(code, pkt, 2, 2) == 0);
    assert(jitcall(code, pkt, 3, 3) == 0);
    assert(jitcall(code, pkt, 4, 4) == 0);
    assert(jitcall(code, pkt, 5, 5) == 0);
    assert(jitcall(code, pkt, 6, 6) == 0);
    assert(jitcall(code, pkt, 7, 7) == 0);
    assert(jitcall(code, pkt, 8, 8) == 0);
    assert(jitcall(code, pkt, 9, 9) == 0);
    assert(jitcall(code, pkt, 10, 10) == 0);
    assert(jitcall(code, pkt, 11, 11) == 0);
    assert(jitcall(code, pkt, 12, 12) == 0);
    assert(jitcall(code, pkt, 13, 13) == 0);
    assert(jitcall(code, pkt, 14, 14) == 0);
    assert(jitcall(code, pkt, 15, 15) == 0);
    assert(jitcall(code, pkt, 16, 16) == 0);
    assert(jitcall(code, pkt, 17, 17) == 0);
    assert(jitcall(code, pkt, 18, 18) == 0);
    assert(jitcall(code, pkt, 19, 19) == 0);
    assert(jitcall(code, pkt, 20, 20) == 0);
    assert(jitcall(code, pkt, 21, 21) == 0);
    assert(jitcall(code, pkt, 22, 22) == 0);
    assert(jitcall(code, pkt, 23, 23) == 0);
    assert(jitcall(code, pkt, 24, 24) == 0);
    assert(jitcall(code, pkt, 25, 25) == 0);
    assert(jitcall(code, pkt, 26, 26) == 0);
    assert(jitcall(code, pkt, 27, 27) == 0);
    assert(jitcall(code, pkt, 28, 28) == 0);
    assert(jitcall(code, pkt, 29, 29) == 0);
    assert(jitcall(code, pkt, 30, 30) == 0);
    assert(jitcall(code, pkt, 31, 31) == 0);
    assert(jitcall(code, pkt, 32, 32) == 0);
    assert(jitcall(code, pkt, 33, 33) == 0);

    /* Change the protocol field. */
    pkt[13] = 8;
    assert(jitcall(code, pkt, 34, 34) == 0);

    bpfjit_free_code(code);
}

/* Test the third example from bpf(4) - accept TCP finger packets */
void tc_bpfjit_examples_3() {
    /*
     * This filter returns only TCP finger packets.
     */
    struct bpf_insn insns[] = {
        BPF_STMT(BPF_LD+BPF_H+BPF_ABS, 12),
        BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, 0x0800, 0, 10),
        BPF_STMT(BPF_LD+BPF_B+BPF_ABS, 23),
        BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, 6, 0, 8),
        BPF_STMT(BPF_LD+BPF_H+BPF_ABS, 20),
        BPF_JUMP(BPF_JMP+BPF_JSET+BPF_K, 0x1fff, 6, 0),
        BPF_STMT(BPF_LDX+BPF_B+BPF_MSH, 14),
        BPF_STMT(BPF_LD+BPF_H+BPF_IND, 14),
        BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, 79, 2, 0),
        BPF_STMT(BPF_LD+BPF_H+BPF_IND, 16),
        BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, 79, 0, 1),
        BPF_STMT(BPF_RET+BPF_K, UINT32_MAX),
        BPF_STMT(BPF_RET+BPF_K, 0),
    };

    bpfjit_func_t code;
    uint8_t pkt[30] = {};

    /* Set IP fragment offset to non-zero. */
    pkt[20] = 1; pkt[21] = 1;

    size_t insn_count = sizeof(insns) / sizeof(insns[0]);

    code = bpfjit_generate_code(NULL, insns, insn_count);
    assert(code != NULL);

    /* Packet is too short. */
    assert(jitcall(code, pkt, 1, 1) == 0);
    assert(jitcall(code, pkt, 2, 2) == 0);
    assert(jitcall(code, pkt, 3, 3) == 0);
    assert(jitcall(code, pkt, 4, 4) == 0);
    assert(jitcall(code, pkt, 5, 5) == 0);
    assert(jitcall(code, pkt, 6, 6) == 0);
    assert(jitcall(code, pkt, 7, 7) == 0);
    assert(jitcall(code, pkt, 8, 8) == 0);
    assert(jitcall(code, pkt, 9, 9) == 0);
    assert(jitcall(code, pkt, 10, 10) == 0);
    assert(jitcall(code, pkt, 11, 11) == 0);
    assert(jitcall(code, pkt, 12, 12) == 0);
    assert(jitcall(code, pkt, 13, 13) == 0);
    assert(jitcall(code, pkt, 14, 14) == 0);
    assert(jitcall(code, pkt, 15, 15) == 0);
    assert(jitcall(code, pkt, 16, 16) == 0);
    assert(jitcall(code, pkt, 17, 17) == 0);
    assert(jitcall(code, pkt, 18, 18) == 0);
    assert(jitcall(code, pkt, 19, 19) == 0);
    assert(jitcall(code, pkt, 20, 20) == 0);
    assert(jitcall(code, pkt, 21, 21) == 0);
    assert(jitcall(code, pkt, 22, 22) == 0);
    assert(jitcall(code, pkt, 23, 23) == 0);
    assert(jitcall(code, pkt, 24, 24) == 0);
    assert(jitcall(code, pkt, 25, 25) == 0);
    assert(jitcall(code, pkt, 26, 26) == 0);
    assert(jitcall(code, pkt, 27, 27) == 0);
    assert(jitcall(code, pkt, 28, 28) == 0);
    assert(jitcall(code, pkt, 29, 29) == 0);

    /* The packet doesn't match. */
    assert(jitcall(code, pkt, 30, 30) == 0);

    /* Still no match after setting the protocol field. */
    pkt[12] = 8;
    assert(jitcall(code, pkt, 30, 30) == 0);

    /* Get one step closer to the match. */
    pkt[23] = 6;
    assert(jitcall(code, pkt, 30, 30) == 0);

    /* Set IP fragment offset to zero. */
    pkt[20] = 0x20; pkt[21] = 0;
    assert(jitcall(code, pkt, 30, 30) == 0);

    /* Set IP header length to 12. */
    pkt[14] = 0xd3;
    assert(jitcall(code, pkt, 30, 30) == 0);

    /* Match one branch of the program. */
    pkt[27] = 79;
    assert(jitcall(code, pkt, 30, 30) == UINT32_MAX);

    /* Match the other branch of the program. */
    pkt[29] = 79; pkt[27] = 0;
    assert(jitcall(code, pkt, 30, 30) == UINT32_MAX);

    /* Packet is too short. */
    assert(jitcall(code, pkt, 1, 1) == 0);
    assert(jitcall(code, pkt, 2, 2) == 0);
    assert(jitcall(code, pkt, 3, 3) == 0);
    assert(jitcall(code, pkt, 4, 4) == 0);
    assert(jitcall(code, pkt, 5, 5) == 0);
    assert(jitcall(code, pkt, 6, 6) == 0);
    assert(jitcall(code, pkt, 7, 7) == 0);
    assert(jitcall(code, pkt, 8, 8) == 0);
    assert(jitcall(code, pkt, 9, 9) == 0);
    assert(jitcall(code, pkt, 10, 10) == 0);
    assert(jitcall(code, pkt, 11, 11) == 0);
    assert(jitcall(code, pkt, 12, 12) == 0);
    assert(jitcall(code, pkt, 13, 13) == 0);
    assert(jitcall(code, pkt, 14, 14) == 0);
    assert(jitcall(code, pkt, 15, 15) == 0);
    assert(jitcall(code, pkt, 16, 16) == 0);
    assert(jitcall(code, pkt, 17, 17) == 0);
    assert(jitcall(code, pkt, 18, 18) == 0);
    assert(jitcall(code, pkt, 19, 19) == 0);
    assert(jitcall(code, pkt, 20, 20) == 0);
    assert(jitcall(code, pkt, 21, 21) == 0);
    assert(jitcall(code, pkt, 22, 22) == 0);
    assert(jitcall(code, pkt, 23, 23) == 0);
    assert(jitcall(code, pkt, 24, 24) == 0);
    assert(jitcall(code, pkt, 25, 25) == 0);
    assert(jitcall(code, pkt, 26, 26) == 0);
    assert(jitcall(code, pkt, 27, 27) == 0);
    assert(jitcall(code, pkt, 28, 28) == 0);
    assert(jitcall(code, pkt, 29, 29) == 0);

    /* Set IP header length to 16. Packet is too short. */
    pkt[14] = 4;
    assert(jitcall(code, pkt, 30, 30) == 0);

    bpfjit_free_code(code);
}

/* Test JIT compilation of BPF_MISC|BPF_COP without context */
void tc_bpfjit_cop_no_ctx() {
    static struct bpf_insn insns[] = {
        BPF_STMT(BPF_MISC+BPF_COP, 0),
        BPF_STMT(BPF_RET+BPF_K, 7)
    };

    bpfjit_func_t code;
    size_t insn_count = sizeof(insns) / sizeof(insns[0]);

    code = bpfjit_generate_code(NULL, insns, insn_count);
    assert(code == NULL);
}

/* Test JIT compilation of BPF_MISC|BPF_COPX without context */
void tc_bpfjit_copx_no_ctx() {
    static struct bpf_insn insns[] = {
        BPF_STMT(BPF_MISC+BPF_COPX, 0),
        BPF_STMT(BPF_RET+BPF_K, 7)
    };

    bpfjit_func_t code;
    size_t insn_count = sizeof(insns) / sizeof(insns[0]);

    code = bpfjit_generate_code(NULL, insns, insn_count);
    assert(code == NULL);
}

int main(int argc, char *argv[]) {
    /* Reuse test scenarios from:
     * netbsd-src/tests/net/bpfjit/t_bpfjit.c
     */
    tc_bpfjit_empty();
    tc_bpfjit_ret_k();
    tc_bpfjit_bad_ret_k();
    tc_bpfjit_alu_add_k();
    tc_bpfjit_alu_sub_k();
    tc_bpfjit_alu_mul_k();
    tc_bpfjit_alu_div0_k();
    tc_bpfjit_alu_div1_k();
    tc_bpfjit_alu_div2_k();
    tc_bpfjit_alu_div4_k();
    tc_bpfjit_alu_div10_k();
    tc_bpfjit_alu_div10000_k();
    tc_bpfjit_alu_div7609801_k();
    tc_bpfjit_alu_div80000000_k();
    tc_bpfjit_alu_mod0_k();
    tc_bpfjit_alu_mod1_k();
    tc_bpfjit_alu_mod2_k();
    tc_bpfjit_alu_mod4_k();
    tc_bpfjit_alu_mod10_k();
    tc_bpfjit_alu_mod10000_k();
    tc_bpfjit_alu_mod7609801_k();
    tc_bpfjit_alu_mod80000000_k();
    tc_bpfjit_alu_and_k();
    tc_bpfjit_alu_or_k();
    tc_bpfjit_alu_xor_k();
    tc_bpfjit_alu_lsh_k();
    tc_bpfjit_alu_lsh0_k();
    tc_bpfjit_alu_rsh_k();
    tc_bpfjit_alu_rsh0_k();
    tc_bpfjit_alu_modulo_k();
    tc_bpfjit_alu_add_x();
    tc_bpfjit_alu_sub_x();
    tc_bpfjit_alu_mul_x();
    tc_bpfjit_alu_div0_x();
    tc_bpfjit_alu_div1_x();
    tc_bpfjit_alu_div2_x();
    tc_bpfjit_alu_div4_x();
    tc_bpfjit_alu_div10_x();
    tc_bpfjit_alu_div10000_x();
    tc_bpfjit_alu_div7609801_x();
    tc_bpfjit_alu_div80000000_x();
    tc_bpfjit_alu_mod0_x();
    tc_bpfjit_alu_mod1_x();
    tc_bpfjit_alu_mod2_x();
    tc_bpfjit_alu_mod4_x();
    tc_bpfjit_alu_mod10_x();
    tc_bpfjit_alu_mod10000_x();
    tc_bpfjit_alu_mod7609801_x();
    tc_bpfjit_alu_mod80000000_x();
    tc_bpfjit_alu_and_x();
    tc_bpfjit_alu_or_x();
    tc_bpfjit_alu_xor_x();
    tc_bpfjit_alu_lsh_x();
    tc_bpfjit_alu_lsh0_x();
    tc_bpfjit_alu_rsh_x();
    tc_bpfjit_alu_rsh0_x();
    tc_bpfjit_alu_modulo_x();
    tc_bpfjit_alu_neg();
    tc_bpfjit_jmp_ja();
    tc_bpfjit_jmp_ja_invalid();
    tc_bpfjit_jmp_ja_overflow();
    tc_bpfjit_jmp_jgt_k();
    tc_bpfjit_jmp_jge_k();
    tc_bpfjit_jmp_jeq_k();
    tc_bpfjit_jmp_jset_k();
    tc_bpfjit_jmp_modulo_k();
    tc_bpfjit_jmp_jgt_x();
    tc_bpfjit_jmp_jge_x();
    tc_bpfjit_jmp_jeq_x();
    tc_bpfjit_jmp_jset_x();
    tc_bpfjit_jmp_jeq_x_noinit_ax();
    tc_bpfjit_jmp_jeq_x_noinit_a();
    tc_bpfjit_jmp_jeq_x_noinit_x();
    tc_bpfjit_jmp_modulo_x();
    tc_bpfjit_ld_abs();
    tc_bpfjit_ld_abs_k_overflow();
    tc_bpfjit_ld_ind();
    tc_bpfjit_ld_ind_k_overflow();
    tc_bpfjit_ld_ind_x_overflow1();
    tc_bpfjit_ld_ind_x_overflow2();
    tc_bpfjit_ld_len();
    tc_bpfjit_ld_imm();
    tc_bpfjit_ldx_imm1();
    tc_bpfjit_ldx_imm2();
    tc_bpfjit_ldx_len1();
    tc_bpfjit_ldx_len2();
    tc_bpfjit_ldx_msh();
    tc_bpfjit_misc_tax();
    tc_bpfjit_misc_txa();
    tc_bpfjit_st1();
    tc_bpfjit_st2();
    tc_bpfjit_st3();
    tc_bpfjit_st4();
    tc_bpfjit_st5();
    tc_bpfjit_stx1();
    tc_bpfjit_stx2();
    tc_bpfjit_stx3();
    tc_bpfjit_stx4();
    tc_bpfjit_opt_ld_abs_1();
    tc_bpfjit_opt_ld_abs_2();
    tc_bpfjit_opt_ld_abs_3();
    tc_bpfjit_opt_ld_ind_1();
    tc_bpfjit_opt_ld_ind_2();
    tc_bpfjit_opt_ld_ind_3();
    tc_bpfjit_opt_ld_ind_4();
    tc_bpfjit_abc_ja();
    tc_bpfjit_abc_ja_over();
    tc_bpfjit_abc_ld_chain();
    tc_bpfjit_examples_1();
    tc_bpfjit_examples_2();
    tc_bpfjit_examples_3();
    tc_bpfjit_cop_no_ctx();
    tc_bpfjit_copx_no_ctx();

    return 0;
}
