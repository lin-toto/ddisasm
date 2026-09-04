.section .text

.globl main
.type main, @function
main:
    xorl %edi, %edi
    call indexed_lookup
    xorl %eax, %eax
    ret
.size main, .-main

.p2align 4
.globl indexed_lookup
.type indexed_lookup, @function
indexed_lookup:
    leaq .Lpost_function_table(%rip), %rdx

    # Keep the table base live across basic blocks.  This is the important
    # control: early straight-line def-use alone cannot connect the LEA to the
    # indexed loads below.
    testl %edi, %edi
    je .Llookup
    xorl %edi, %edi
.Llookup:
    andl $1, %edi
    movq (%rdx,%rdi,8), %rax
    testl %edi, %edi
    je .Lsecond_load
    xorl %edi, %edi
.Lsecond_load:
    movq 64(%rdx,%rdi,8), %rcx
    xorq %rcx, %rax
    ret
.size indexed_lookup, .-indexed_lookup

.p2align 5
.Lpost_function_table:
    .quad 0x1122334455667788
    .quad 0x8877665544332211
    .asciz "POSTFUNC-INDEXED"

    # Instruction-shaped scalar bytes, followed by padding, exercise the
    # competing-code candidates that the complete table extent must defeat.
    .byte 0xc2, 0x3e, 0xbe
    .fill 29, 1, 0xa5
    .quad 0x22937f3be5ec937c
    .fill 80, 1, 0x5a

.p2align 4
.globl post_table_function
.type post_table_function, @function
post_table_function:
    ret
.size post_table_function, .-post_table_function

.section .note.GNU-stack,"",@progbits
