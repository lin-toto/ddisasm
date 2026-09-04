# Distinguish a completed page-aligned address spilled to the stack from an
# ADRP page base that is deliberately spilled before its LO12 tail.

.arch armv8-a
.file "src.s"
.text
.global main
.type main, %function
main:
    stp fp,lr,[sp,#-48]!

    # This ADD completes the address.  The later load and increment are normal
    # pointer operations and must not receive LO12 symbolic expressions.
    adrp x4, completed_pointer
    add x4, x4, #:lo12:completed_pointer
    str x4, [sp, #16]
    ldr x0, [sp, #16]
    ldrb w1, [x0]
    add x0, x0, #1

    # Positive control: an ADRP page base may be spilled and restored before
    # the instruction that genuinely completes the split load.
    adrp x5, stack_split_target
    str x5, [sp, #24]
    ldr x2, [sp, #24]
    add x2, x2, #:lo12:stack_split_target
    ldrb w3, [x2]

    mov w0, #0
    ldp fp,lr,[sp],#48
    ret
.size main, .-main

.section .rodata
.balign 4096
.global completed_pointer
.type completed_pointer, %object
completed_pointer:
    .asciz "A"
.size completed_pointer, .-completed_pointer

.balign 4096
.zero 32
.global stack_split_target
.type stack_split_target, %object
stack_split_target:
    .asciz "B"
.size stack_split_target, .-stack_split_target
