/* Source-only fixture. CASE and NO_UNWIND select binary evidence, not hints
 * passed to DDisasm. No debug information or source information is emitted. */
#ifndef CASE
#define CASE 0
#endif
#ifndef NO_UNWIND
#define NO_UNWIND 0
#endif

    .option norelax
    .text
#if CASE == 6 || CASE == 15
    .balign 8,0
#else
    .balign 4,0
#endif
    .globl main,after_gap
    .type main,@function
main:
#if !NO_UNWIND
    .cfi_startproc
#endif
    .option rvc
    c.nop
    .option norvc
#if CASE == 1
    beq a0,zero,.Lgap
#elif CASE == 8
    jalr ra,t1,0
#elif CASE == 11
    la t0,.Lgap
    jalr zero,t0,0
#elif CASE == 6 || CASE == 15
    addi a0,a0,0
#endif
#if CASE == 2
    addi a0,a0,1
#else
    jal zero,main
#endif
#if !NO_UNWIND && CASE != 13
    .cfi_endproc
#endif
#if CASE == 4
    .size main,.-main+2
#else
    .size main,.-main
#endif

.Lgap:
#if CASE == 3
    .globl gap_marker
gap_marker:
#endif
#if CASE == 6
    .2byte 0,1,0
#elif CASE == 7
    .2byte 0,0
#elif CASE == 15
    .2byte 0,0,0
#else
    .2byte 0
#endif
#if CASE == 12
    .globl zero_value
    .equ zero_value,0
    .reloc .Lgap,R_RISCV_32,zero_value
#endif
#if !NO_UNWIND && CASE == 13
    .cfi_endproc
#endif

after_gap:
#if CASE != 5
    .globl _start
    .type _start,@function
_start:
#if !NO_UNWIND
    .cfi_startproc
#endif
#endif
#if CASE == 12
    /* The four-byte zero relocation spans the two-byte gap and this real
       entry trap; the linker preserves all four zero bytes. */
    .2byte 0
#endif
#if CASE == 16
    /* The loaded displacement reaches the real trap before this function,
       but the provisional CFG cannot resolve this computed transfer. */
1:  auipc t0,%pcrel_hi(_start)
    addi t0,t0,%pcrel_lo(1b)
2:  auipc t1,%pcrel_hi(displacement)
    lw t1,%pcrel_lo(2b)(t1)
    add t0,t0,t1
    jalr zero,t0,0
#else
    addi a0,zero,0
    addi a7,zero,93
    ecall
#endif
#if CASE != 5
#if !NO_UNWIND
    .cfi_endproc
#endif
    .size _start,.-_start
#endif

#if CASE == 5
    /* after_gap has no independent function evidence. The ELF entry is in
       another executable section; a NOTYPE label is not a function start. */
    .section .entry,"ax",@progbits
    .balign 4,0
    .globl _start
    .type _start,@function
_start:
    addi a0,zero,0
    addi a7,zero,93
    ecall
    .size _start,.-_start
#endif

#if CASE == 9
    /* Without a target exclusion proof, this function's unresolved branch
       can enter the gap after main and must veto its removal. */
    .section .other,"ax",@progbits
    .balign 4,0
    .globl unrelated
    .type unrelated,@function
unrelated:
    .cfi_startproc
    jalr zero,t1,0
    .cfi_endproc
    .size unrelated,.-unrelated
#endif

#if CASE == 16
    .data
    .balign 4,0
displacement:
    .word -2
#endif

#if CASE == 10
    /* A genuine input pointer and its inferred symbolic expression name the
       gap even when the original symbol table is removed. */
    .data
    .balign 8,0
#if __riscv_xlen == 64
    .dword .Lgap
#else
    .word .Lgap
#endif
#endif

    .section .note.GNU-stack,"",@progbits
