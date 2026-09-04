.arch armv8-a

.text
.global main
.type main, %function
main:
    mov w0, #0
    ret
.size main, .-main

// Model two OpenSSL DES lookup shapes: an ADRP/ADD materializes one large
// uint32_t OBJECT, then a register-indexed LDR reads four-byte elements.
// The first index is bounded explicitly by a low-pass mask.
.global dense_u32_load
.type dense_u32_load, %function
dense_u32_load:
    adrp x1, dense_u32_table
    add x1, x1, :lo12:dense_u32_table
    // Preserve the compiler shape seen in an unrolled lookup: mask the index,
    // widen it, add a constant subarray index, then scale it in the load.  The
    // extra value-flow steps must not hide the four-byte element width.
    and w2, w0, #0x3f
    mov w2, w2
    add x2, x2, #0xc0
    ldr w0, [x1, x2, lsl #2]
    ret
.size dense_u32_load, .-dense_u32_load

// The final DES lookup omits the redundant mask: a 32-bit logical shift by 26
// already bounds the index to 0..63.  Range analysis must retain that fact
// through the move and constant subarray offset.
.global dense_u32_shift_load
.type dense_u32_shift_load, %function
dense_u32_shift_load:
    adrp x1, dense_u32_table
    add x1, x1, :lo12:dense_u32_table
    lsr w2, w0, #26
    mov w2, w2
    add x2, x2, #0x1c0
    ldr w0, [x1, x2, lsl #2]
    ret
.size dense_u32_shift_load, .-dense_u32_shift_load

// Positive control: a native-width load from a genuine pointer table must
// retain its symbolic expression even though the target is unlabeled.
.global dense_pointer_load
.type dense_pointer_load, %function
dense_pointer_load:
    adrp x1, dense_pointer_table
    add x1, x1, :lo12:dense_pointer_table
    ldr x0, [x1, x0, lsl #3]
    ret
.size dense_pointer_load, .-dense_pointer_load

.section .collision_target,"a",@progbits
.balign 8
.global collision_target_object
.type collision_target_object, %object
collision_target_object:
    .zero 0x40
.size collision_target_object, .-collision_target_object
    // Leave the string outside every original OBJECT, as in a compiler string
    // pool.  This removes the unrelated unlabeled-interior-object penalty and
    // makes the destination an independently inferred string start.
    .zero 0x40
    .asciz "inferred interior string target"
    .zero 0x200 - (.-collision_target_object)

.section .collision_table,"a",@progbits
.balign 16
.global dense_u32_table
.type dense_u32_table, %object
dense_u32_table:
    .long 1
    .long 2
    .zero 0x378 - (.-dense_u32_table)
    // Exercise the explicit-mask bounded range independently.
    .long 0x00820080
    .long 0
    .zero 0x7e8 - (.-dense_u32_table)
    // Exercise the logical-shift bounded range.  The adjacent uint32_t values
    // form the aligned native-width integer 0x0000000000820080.  It is numeric
    // table data, not a stored pointer.
    .long 0x00820080
    .long 0
    .zero 0x800 - (.-dense_u32_table)
.size dense_u32_table, .-dense_u32_table

// Model the unrelated pointer records that immediately follow DES_SPtrans in
// the OpenSSL image.  Their first fields are 0x80 bytes apart.  Without an
// object-boundary check, the scalar collision at dense_u32_table+0x7e8 can be
// mistaken for the first member of this later pointer sequence.
.zero 0x68
.quad collision_target_object
.zero 0x78
.quad collision_target_object + 8
.zero 0x78
.quad collision_target_object + 16

.balign 8
.global dense_pointer_table
.type dense_pointer_table, %object
dense_pointer_table:
    .quad 0x0000000000820080
    .quad 0x0000000000820088
    .quad 0x0000000000820090
    .quad 0x0000000000820098
.size dense_pointer_table, .-dense_pointer_table
