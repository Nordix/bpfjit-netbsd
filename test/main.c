#include <assert.h>
#include <stdint.h>
#include <sys/types.h>
#include <net/bpf.h>
#include <net/bpfjit.h>

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
    struct bpf_insn dummy;
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

int main(int argc, char *argv[]) {
    /* Reuse test scenarios from:
     * netbsd-src/tests/net/bpfjit/t_bpfjit.c
     */
    tc_bpfjit_empty();
    tc_bpfjit_ret_k();
    tc_bpfjit_alu_add_k();
    tc_bpfjit_jmp_jgt_k();
}
