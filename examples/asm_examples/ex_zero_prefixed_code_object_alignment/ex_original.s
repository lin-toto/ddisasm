.text

.globl main
.type main, @function
.align 32
main:
    leaq masked_table(%rip), %r10
    xorl %ecx, %ecx
.Lcount:
    addq $8, %r10
    incl %ecx
    testb $0xff, %r10b
    jne .Lcount

    xorl %eax, %eax
    cmpl $24, %ecx
    sete %al
    xorl $1, %eax
    ret
.size main, . - main

# This is the shape emitted by hand-written implementations that use pointer
# low bits as a loop sentinel: the alignment applies to the zero prefix, while
# the object deliberately begins 64 bytes into the 256-byte region.
.align 256
.zero 64
.type masked_table, @object
masked_table:
    .rept 24
    .quad 0x0102030405060708
    .endr
.size masked_table, . - masked_table

# A weaker alignment directive can happen to start at a more strongly aligned
# address.  The zero prefix plus object still identifies the intended
# 128-byte region, so reconstruction must not promote this anchor to 256.
.align 128
.zero 96
.type weaker_aligned_table, @object
weaker_aligned_table:
    .rept 4
    .quad 0x1112131415161718
    .endr
.size weaker_aligned_table, . - weaker_aligned_table

.section .note.GNU-stack,"",@progbits
