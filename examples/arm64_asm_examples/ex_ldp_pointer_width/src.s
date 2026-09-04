.arch armv8-a

.text
.global main
.type main, %function
main:
    adrp x0, .Lrecord
    add x0, x0, :lo12:.Lrecord
    ldp x1, x2, [x0, #16]
    adrp x3, pointer_target
    add x3, x3, :lo12:pointer_target
    cmp x1, x3
    b.ne .Lfail
    mov w0, #0
    ret
.Lfail:
    mov w0, #1
    ret
.size main, .-main

// Keep the pointer field anonymous and away from the section's mapping symbol.
// Its low bytes also look like a short printable string.  Correct LDP
// element-width evidence must preserve the pointer during relayout.
.section .rodata.record,"a",@progbits
.balign 8
.Lrecord:
    .quad 0
    .quad 0
    .quad pointer_target
    .quad 5
    .zero 24

.section .pointer_target,"aw",@progbits
.balign 8
.global pointer_target
.type pointer_target, %object
pointer_target:
    .skip 256
.size pointer_target, .-pointer_target

.section .note.GNU-stack,"",@progbits
