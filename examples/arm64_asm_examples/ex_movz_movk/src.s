// Test: MOVZ+MOVK address construction in non-PIE ARM64 binaries.
//
// This exercises the movz_movk_chain Datalog rules.  In a non-PIE executable
// the linker fills absolute addresses into the MOVZ/MOVK immediates, so
// ddisasm must recognize the pair as constructing an address and emit
// symbolic operand candidates with G0/G1 attributes.
//
// Expected behavior:
//   - ddisasm produces SymAddrConst for both the MOVZ and the MOVK
//   - gtirb-pprinter emits:
//       movz  x0, #:abs_g1:msg
//       movk  x0, #:abs_g0_nc:msg
//   - reassembled binary runs identically.

.arch armv8-a
.file "src.s"

.text
.global main
.type main, %function

main:
    stp     fp, lr, [sp, #-16]!

    // Construct the address of msg using MOVZ + MOVK.
    // The linker/assembler resolves the relocations at link time.
    movz    x0, #:abs_g1:msg
    movk    x0, #:abs_g0_nc:msg

    bl      printf

    mov     x0, #0
    ldp     fp, lr, [sp], #16
    ret
.size main, .-main

    // Numeric control: 0x700142 happens to lie strictly inside the data
    // object below, but this value is shifted and masked as an integer before
    // becoming an array index.  The eventual memory use must not turn the
    // original scalar into collision_data_object+0x142.
.global movz_movk_numeric_collision
.type movz_movk_numeric_collision, %function
movz_movk_numeric_collision:
    mov     w0, #1
    lsl     w0, w0, #2
    movz    w1, #0x0142
    movk    w1, #0x70, lsl #16
    asr     w0, w1, w0
    and     w0, w0, #0xf
    adrp    x3, collision_index_bytes
    add     x3, x3, :lo12:collision_index_bytes
    ldrb    w0, [x3, w0, uxtw]
    ret
.size movz_movk_numeric_collision, .-movz_movk_numeric_collision

    // Positive control: the same kind of unlabeled interior value really is
    // an address here, because the completed value is used as a memory base.
    // Keep it in an uncalled symbol-delimited helper so older qemu-user builds
    // need not map the deliberately distant test section at runtime.
.global movz_movk_interior_address
.type movz_movk_interior_address, %function
movz_movk_interior_address:
    movz    x2, #0x0101
    movk    x2, #0x70, lsl #16
    mov     x3, x2
    add     x3, x3, #1
    ldrb    w2, [x3]
    ret
.size movz_movk_interior_address, .-movz_movk_interior_address

    // Numeric control: 0x710010 is an unlabeled instruction inside the
    // distant code region below.  Here it is only a register bit mask, so its
    // MOVZ/MOVK slices must remain numeric when that region later moves.
.global movz_movk_code_mask_collision
.type movz_movk_code_mask_collision, %function
movz_movk_code_mask_collision:
    movz    x1, #0x0010
    movk    x1, #0x71, lsl #16
    and     x0, x0, x1
    ret
.size movz_movk_code_mask_collision, .-movz_movk_code_mask_collision

    // Positive control: the same unlabeled interior value is a genuine code
    // address when it is used directly as an indirect branch destination.
.global movz_movk_code_address_control
.type movz_movk_code_address_control, %function
movz_movk_code_address_control:
    movz    x2, #0x0010
    movk    x2, #0x71, lsl #16
    br      x2
.size movz_movk_code_address_control, .-movz_movk_code_address_control

.section .rodata
msg:
    .asciz "Hello from MOVZ+MOVK!\n"

.section .collision_data,"a",@progbits
.balign 8
.global collision_data_object
.type collision_data_object, %object
collision_data_object:
    .zero 0x200
.size collision_data_object, .-collision_data_object

.section .rodata
.balign 16
collision_index_bytes:
    .byte 0, 1, 2, 3, 4, 5, 6, 7
    .byte 8, 9, 10, 11, 12, 13, 14, 15

// Keep 0x710010 strictly inside a symbol-delimited code block, with no source
// symbol at the colliding address itself.
.section .collision_code,"ax",@progbits
.balign 4
.global collision_code_region
.type collision_code_region, %function
collision_code_region:
    nop
    nop
    nop
    nop
    nop
    ret
.size collision_code_region, .-collision_code_region
