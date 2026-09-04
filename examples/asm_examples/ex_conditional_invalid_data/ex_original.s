    .text
    .globl main
    .type main, @function
main:
    xorl %eax, %eax
    ret
    .size main, .-main

    # A no-fallthrough instruction followed by alignment padding makes the
    # first non-NOP byte below a speculative code-discovery target.  The bytes
    # model an embedded table: they happen to decode as CDQ/JNS, but the JNS
    # fallthrough reaches POP followed by an opcode invalid in 64-bit mode.
    .p2align 5
    .byte 0x99
    jns real_target
    .byte 0x5a, 0x06, 0x0f, 0x0b
    .byte 0xde, 0xad, 0xbe, 0xef, 0x43, 0x46, 0x47, 0x21

    .p2align 4
    .globl real_target
    .type real_target, @function
real_target:
    ret
    .size real_target, .-real_target

    .section .note.GNU-stack,"",@progbits
