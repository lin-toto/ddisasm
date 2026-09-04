# Test: a numeric RV64 stack adjustment collides with an exact code symbol.
#
# The LUI/ADDI pair in rv_stack_adjustment_collision constructs the literal
# 0x70040.  A function deliberately exists at that address, but the completed
# value is used to update SP and must not become a symbolic reference to it.
# The second helper constructs the same value and uses it as a memory base,
# providing the positive address-materialization control.

.option norelax
.option norvc

.text
.globl main
.type main, @function
main:
    li      a0, 0
    ret
.size main, .-main

.globl rv_stack_adjustment_collision
.type rv_stack_adjustment_collision, @function
rv_stack_adjustment_collision:
    lui     t0, 0x70
    addi    t0, t0, 0x40
    add     sp, sp, t0
    sub     sp, sp, t0
    ret
.size rv_stack_adjustment_collision, .-rv_stack_adjustment_collision

.globl rv_address_positive_control
.type rv_address_positive_control, @function
rv_address_positive_control:
    lui     t1, 0x70
    addi    t1, t1, 0x40
    lbu     a0, 0(t1)
    ret
.size rv_address_positive_control, .-rv_address_positive_control

# The same exact-symbol value is a scalar multiplier here.  Exact destination
# identity alone is not enough to make an unrelocated LUI/ADDI pair an address:
# the completed value's direct arithmetic use is independent scalar evidence.
.globl rv_exact_symbol_multiplier_collision
.type rv_exact_symbol_multiplier_collision, @function
rv_exact_symbol_multiplier_collision:
    lui     t2, 0x70
    addi    t2, t2, 0x40
    mul     a0, a0, t2
    ret
.size rv_exact_symbol_multiplier_collision, .-rv_exact_symbol_multiplier_collision

# The value 0x70044 is deliberately an unlabeled instruction interior.  It is
# scalar data here and must remain literal even though it falls in executable
# code and reaches a multiplication.
.globl rv_unlabeled_scalar_collision
.type rv_unlabeled_scalar_collision, @function
rv_unlabeled_scalar_collision:
    lui     t2, 0x70
    addi    t2, t2, 0x44
    mul     a0, a0, t2
    ret
.size rv_unlabeled_scalar_collision, .-rv_unlabeled_scalar_collision

# The same unlabeled interior value is a genuine address here.  Its direct use
# as a memory base supplies independent positive evidence.
.globl rv_unlabeled_address_positive_control
.type rv_unlabeled_address_positive_control, @function
rv_unlabeled_address_positive_control:
    lui     t3, 0x70
    addi    t3, t3, 0x44
    lbu     a0, 0(t3)
    ret
.size rv_unlabeled_address_positive_control, .-rv_unlabeled_address_positive_control

# A data address returned to a caller has no local memory-base use.  Neutral
# LUI/ADDI materializations into non-code sections must nevertheless relocate;
# otherwise every such address becomes stale when data is laid out again.
.globl rv_unlabeled_data_address_return
.type rv_unlabeled_data_address_return, @function
rv_unlabeled_data_address_return:
    lui     a0, 0x71
    addi    a0, a0, 0x4
    ret
.size rv_unlabeled_data_address_return, .-rv_unlabeled_data_address_return

# A compiler may schedule an instruction for an unrelated register between
# the LUI and the memory operation that consumes its page value.  Reaching-def
# analysis must still recognize this as one absolute address materialization;
# otherwise relayout leaves the original numeric address in the store.
.globl rv_interleaved_store_positive_control
.type rv_interleaved_store_positive_control, @function
rv_interleaved_store_positive_control:
    lui     t0, %hi(rv_interleaved_store_target)
    li      t1, 1
    sw      t1, %lo(rv_interleaved_store_target)(t0)
    ret
.size rv_interleaved_store_positive_control, .-rv_interleaved_store_positive_control

# Referencing a short fixed-width name from code is not enough to make the
# name's little-endian bytes a pointer.  This control addresses the first short
# slot following a longer string whose tail occupies the preceding slot.
.globl rv_referenced_short_string
.type rv_referenced_short_string, @function
rv_referenced_short_string:
    lui     a0, %hi(rv_referenced_short_md5)
    addi    a0, a0, %lo(rv_referenced_short_md5)
    ret
.size rv_referenced_short_string, .-rv_referenced_short_string

# RV64 medlow uses 32-bit absolute entries for some switch tables.  The table
# is placed on a 4 KiB boundary so its LUI/ADDI materialization has a zero low
# half; Capstone renders that ADDI as `mv`, which must still seed table recovery.
.globl rv_absolute_jump_table_zero_lo
.type rv_absolute_jump_table_zero_lo, @function
rv_absolute_jump_table_zero_lo:
    li      t0, 2
    bgtu    a0, t0, rv_absolute_jump_table_default
    slli    t1, a0, 2
    lui     t0, 0x72
    addi    t0, t0, 0
    add     t1, t1, t0
    lw      t1, 0(t1)
    jr      t1
.globl rv_absolute_jump_table_case0
rv_absolute_jump_table_case0:
    li      a0, 10
    ret
.globl rv_absolute_jump_table_case1
rv_absolute_jump_table_case1:
    li      a0, 11
    ret
.globl rv_absolute_jump_table_case2
rv_absolute_jump_table_case2:
    li      a0, 12
    ret
.globl rv_absolute_jump_table_default
rv_absolute_jump_table_default:
    li      a0, -1
    ret
.size rv_absolute_jump_table_zero_lo, .-rv_absolute_jump_table_zero_lo

.section .collision_text,"ax",@progbits
.globl rv_exact_collision_target
.type rv_exact_collision_target, @function
rv_exact_collision_target:
    nop
    ret
.size rv_exact_collision_target, .-rv_exact_collision_target

.section .collision_data,"a",@progbits
.zero 4
.Lrv_unlabeled_data_target:
.byte 0x41
.zero 3
.globl rv_interleaved_store_target
.type rv_interleaved_store_target, @object
rv_interleaved_store_target:
    .word 0
.size rv_interleaved_store_target, .-rv_interleaved_store_target
.zero 8

.section .collision_jump_table,"a",@progbits
.globl rv_absolute_jump_table_zero_lo_table
.type rv_absolute_jump_table_zero_lo_table, @object
rv_absolute_jump_table_zero_lo_table:
    .word rv_absolute_jump_table_case0
    .word rv_absolute_jump_table_case1
    .word rv_absolute_jump_table_case2
.size rv_absolute_jump_table_zero_lo_table, .-rv_absolute_jump_table_zero_lo_table

# Each eight-byte slot below contains a short NUL-terminated name followed by
# zero padding.  On little-endian RV64, the bytes for "MD5" also form the
# mapped integer 0x35444d.  The middle slot is text, not a pointer, and must
# remain literal even though that accidental value falls inside a loadable
# section.  Its two fixed-width string neighbors provide structural evidence
# that this is a string pool rather than an address array.
.section .collision_string_pool,"a",@progbits
.balign 8
.globl rv_dense_short_string_pool
.type rv_dense_short_string_pool, @object
rv_dense_short_string_pool:
    .asciz "md2"
    .zero 4
    .asciz "MD5"
    .zero 4
    .asciz "md5"
    .zero 4
.size rv_dense_short_string_pool, .-rv_dense_short_string_pool

# The long first name crosses a pointer-width boundary.  Consequently the
# slot immediately before rv_referenced_short_md5 contains only the tail of a
# string and cannot serve as a full short-string neighbor.  The direct code
# reference plus the following padded name still establishes the intended
# string-pool layout.
.balign 8
.globl rv_referenced_short_string_pool
.type rv_referenced_short_string_pool, @object
rv_referenced_short_string_pool:
    .asciz "MD5-SHA1"
    .zero 7
.globl rv_referenced_short_md5
rv_referenced_short_md5:
    .asciz "MD5"
    .zero 4
    .asciz "HMAC"
    .zero 3
.size rv_referenced_short_string_pool, .-rv_referenced_short_string_pool

.section .collision_string_target,"a",@progbits
.zero 0x500
