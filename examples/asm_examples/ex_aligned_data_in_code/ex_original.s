# This example is to demonostrate that data-in-code is properly aligned
# when it is referenced by instructions that require explicitly aligned memory.
# If not properly aligned, it may cause a segmentation fault due to alignment
# requirement violation.
# See Table 15-6 in https://cdrdv2.intel.com/v1/dl/getContent/671200.

    .section .text

.globl main
.type main, @function
main:
    call print_message1

    # Load data into XMM register using movdqa: `data128.1` needs to be aligned.
    movdqa data128.1(%rip), %xmm0

    # A pair of instructions forms an access to `data128.2`, which needs to
    # be aligned.
    lea data128.2(%rip), %rax
    movdqa 0(%rax), %xmm1

    # The aligned target is reached from an earlier PC-relative base plus a
    # fixed displacement.  This access itself only requires 16-byte alignment,
    # while a separate YMM access below requires the effective target to be
    # 32-byte aligned.  The stronger target constraint must propagate back to
    # the base or padding inserted between them changes what the load reads.
    lea data256.base(%rip), %rax
    movdqa 32(%rax), %xmm1
    vmovdqa data256.composite(%rip), %ymm2

    # The table is an OBJECT in .text whose address is passed to a helper.
    # There is deliberately no direct aligned-load reference to the table for
    # the disassembler to follow interprocedurally.
    lea data256.indirect(%rip), %rdi
    call load_data256_indirect

    # Load data into XMM and YMM using vmovapd: `data256` needs to be 32-bit
    # aligned (YMM) instead of being 16-bit aligned (XMM).
    vmovapd data256(%rip), %xmm0
    vmovapd data256(%rip), %ymm0

    # Load data into YMM register using vmovups: `data256u` does not need to be aligned.
    vmovups data256u(%rip), %ymm1

    # Integer arithmetic/logical instructions that require alignment
    paddq data128.3(%rip), %xmm0
    pand data128.4(%rip), %xmm0
    psllq data128.5(%rip), %xmm0

    # Floating-point instructions that require alignment
    addps data128.6(%rip), %xmm0
    andpd data128.7(%rip), %xmm0

    call print_message2

    xorq %rax, %rax

    ret

.type print_message1, @function
print_message1:
    lea message1(%rip), %rdi
    call printf
    ret

.align 16
.type print_message2, @function
print_message2:
    lea message2(%rip), %rdi
    call printf
    ret
    .zero 3

.type load_data256_indirect, @function
load_data256_indirect:
    vmovdqa (%rdi), %ymm3
    ret

.align 16
data128.1:
    .byte 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16
.align 16
data128.2:
    .byte 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16
.align 16
data128.3:
    .byte 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16
.align 16
data128.4:
    .byte 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16
.align 16
data128.5:
    .byte 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16
.align 16
data128.6:
    .byte 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16
.align 16
data128.7:
    .byte 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16
.align 32
data256:
    .byte 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16
    .byte 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16

.align 32
data256.base:
    .byte 31, 30, 29, 28, 27, 26, 25, 24
    .byte 23, 22, 21, 20, 19, 18, 17, 16
    .byte 15, 14, 13, 12, 11, 10, 9, 8
    .byte 7, 6, 5, 4, 3, 2, 1, 0
data256.composite:
    .byte 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16
    .byte 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16

.align 32
.type data256.indirect, @object
data256.indirect:
    .byte 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16
    .byte 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16
.size data256.indirect, . - data256.indirect

    .zero 3
data256u:
    .byte 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16
    .byte 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16

    .section .data

message1:
    .ascii "Performing SIMD operations...\n"
    .byte 0
message2:
    .ascii "SIMD operations completed.\n"
    .byte 0
