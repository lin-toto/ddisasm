# Ensure that an adr...add pattern does *not* generate a split load for
# unaligned addresses.

.arch armv8-a
.file "src.s"
.text
.global main
.type main, %function
main:
    stp fp,lr,[sp,#-64]!

    # load the addr of the structure.
    adr x8,my_struct

    # get a reference to the embedded string.
    # this can't be a split load, because my_struct is not page-aligned, and
    # thus :lo12:my_struct+8 won't produce the literal value #8.
    add x0,x8,#8
    bl printf

    # ADR encodes an exact address even when that address happens to be page
    # aligned.  The later field offset must not be folded back into the ADR,
    # or reconstruction applies the offset twice.
    adr x8,page_struct
    add x0,x8,#64
    bl printf

.exit:
    ldp fp,lr,[sp],#64
    mov x0, #0
    ret

.section .rodata
# ensure things are not page-aligned.
.zero 84

# a global structure has an embedded string at offset +8.
my_struct:
    .quad 1234
    .asciz "hello\n"

.balign 4096
.global page_struct
.type page_struct, %object
page_struct:
    .zero 64
page_message:
    .asciz "page-aligned\n"
    .zero 50
double_offset_message:
    .asciz "double-offset\n"
.size page_struct, .-page_struct
