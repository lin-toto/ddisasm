    .text
    .globl main
    .type main, @function
main:
    # Scalar load followed by an indirect call.
    movq collision_literal+24(%rip), %rdx
    call *%rdx

    # A direct memory-indirect call has no intermediate register definition.
    call *collision_literal+32(%rip)

    # The indexed access is propagated across the four-entry pointer table.
    andl $3, %edi
    leaq collision_literal+40(%rip), %r8
    movq (%r8,%rdi,8), %rdx
    call *%rdx

    # This pointer targets an unlabeled location inside a nonzero OBJECT.  Its
    # pointer-sized load and subsequent dereference are independent evidence
    # that distinguishes it from the packed scalar control below.
    movq collision_literal+144(%rip), %r10
    movzbl (%r10), %r11d

    # This local target has no source symbol in the linked binary, but the
    # direct call supplies independent function-entry provenance.
    call .Lcollision_called_entry

    # Preserve the accidental-collision value as the observable result.
    # Independently materialize the short text field's address, mirroring a
    # format string passed to a callee.  This distinguishes it from unrelated
    # pointer fields whose low address bytes merely happen to be printable.
    leaq collision_short_string_literal(%rip), %r11
    leaq collision_zero_prefixed_referenced_string_literal(%rip), %r11
    leaq collision_zero_prefixed_single_char_literal(%rip), %r11
    leaq collision_leading_repeated_string_records(%rip), %r11
    leaq collision_four_repeated_string_scalars(%rip), %r11
    movq collision_literal(%rip), %rax
    cmpq $0x6c6176, %rax
    setne %al
    movzbl %al, %eax
    ret
    .size main, .-main

    # These symbol-delimited helpers are discovered as code but are not called
    # at runtime.  They exercise both register and direct-memory jump uses.
    .globl collision_register_jump_use
    .type collision_register_jump_use, @function
collision_register_jump_use:
    movq collision_literal+96(%rip), %rdx
    jmp *%rdx
    .size collision_register_jump_use, .-collision_register_jump_use

    .globl collision_direct_jump_use
    .type collision_direct_jump_use, @function
collision_direct_jump_use:
    jmp *collision_literal+104(%rip)
    .size collision_direct_jump_use, .-collision_direct_jump_use

    # Negative control: this address-shaped integer participates in a real
    # memory address as an index, but never becomes a control-flow target.
    .globl collision_integer_index_use
    .type collision_integer_index_use, @function
collision_integer_index_use:
    movq collision_literal+72(%rip), %r9
    leaq collision_literal(%rip), %r10
    movzbl (%r10,%r9), %r11d
    ret
    .size collision_integer_index_use, .-collision_integer_index_use

    # Stronger negative: the collision value indexes a pointer table whose
    # loaded result is called.  Address-use propagation can label the index as
    # call-related, but the index itself is not the transferred value.
    .globl collision_call_index_use
    .type collision_call_index_use, @function
collision_call_index_use:
    movq collision_literal+112(%rip), %r9
    leaq collision_literal+40(%rip), %r8
    movq (%r8,%r9,8), %rdx
    call *%rdx
    ret
    .size collision_call_index_use, .-collision_call_index_use

    # The indexed branch addresses a contiguous nine-entry code-pointer
    # array, but the inferred access stride is 32 bytes.  This mirrors a
    # bounded switch expression where data-access propagation observes only
    # every fourth pointer-sized cell.  Control-flow evidence from those cells
    # must retain all members of the same contiguous code-pointer array.
    .globl collision_sparse_code_pointer_array_use
    .type collision_sparse_code_pointer_array_use, @function
collision_sparse_code_pointer_array_use:
    cmpl $8, %edi
    ja .Lcollision_table_target0
    leaq collision_sparse_code_pointer_array(%rip), %r8
    movq (%r8,%rdi,8), %rdx
    jmp *%rdx
    .size collision_sparse_code_pointer_array_use, .-collision_sparse_code_pointer_array_use

    # A direct indexed memory-indirect jump has no intermediate load register
    # and no preferred_data_access row for an individual table cell.  The
    # jump-table access itself is the control-flow evidence for the array.
    .globl collision_direct_indexed_code_pointer_array_use
    .type collision_direct_indexed_code_pointer_array_use, @function
collision_direct_indexed_code_pointer_array_use:
    andl $3, %edi
    leaq collision_direct_indexed_code_pointer_array(%rip), %r8
    jmp *(%r8,%rdi,8)
    .size collision_direct_indexed_code_pointer_array_use, .-collision_direct_indexed_code_pointer_array_use

    # Brotli-shaped negative control: a densely indexed uint64 table contains
    # regularly spaced scalar bit patterns that happen to be data addresses.
    # The loaded value is used as a scaled index, never as a pointer base.
    .globl collision_dense_scalar_use
    .type collision_dense_scalar_use, @function
collision_dense_scalar_use:
    leaq collision_dense_scalar_lattice(%rip), %r8
    movq (%r8,%rdi,8), %rax
    leaq collision_literal(%rip), %rdx
    movzbl (%rdx,%rax), %ecx
    ret
    .size collision_dense_scalar_use, .-collision_dense_scalar_use

    # The same negative at a four-qword apparent-address spacing reproduces
    # Brotli's second scalar-table pattern while the true access stays dense.
    .globl collision_dense_scalar32_use
    .type collision_dense_scalar32_use, @function
collision_dense_scalar32_use:
    leaq collision_dense_scalar32_lattice(%rip), %r8
    movq (%r8,%rdi,8), %rax
    leaq collision_literal(%rip), %rdx
    movzbl (%rdx,%rax), %ecx
    ret
    .size collision_dense_scalar32_use, .-collision_dense_scalar32_use

    # A dense uint32_t table can also form an aligned pointer-width collision
    # from two adjacent scalar entries.  The loaded field is four bytes, not a
    # pointer; reconstruction must therefore leave the eight-byte window raw.
    .globl collision_dense_u32_scalar_use
    .type collision_dense_u32_scalar_use, @function
collision_dense_u32_scalar_use:
    leaq collision_dense_u32_scalar_table(%rip), %r8
    movl (%r8,%rdi,4), %eax
    ret
    .size collision_dense_u32_scalar_use, .-collision_dense_u32_scalar_use

    # Matching positive control: the same dense indexed-load shape genuinely
    # produces a pointer that is directly dereferenced as a memory base.
    .globl collision_dense_pointer_use
    .type collision_dense_pointer_use, @function
collision_dense_pointer_use:
    leaq collision_dense_pointer_lattice(%rip), %r8
    movq (%r8,%rdi,8), %rax
    movzbl (%rax), %ecx
    ret
    .size collision_dense_pointer_use, .-collision_dense_pointer_use

    # Aligned target addresses are not characteristic of Brotli's packed bit
    # patterns.  This OpenSSL-shaped positive returns the loaded pointer rather
    # than immediately dereferencing it, so target alignment itself must keep
    # the entries out of the dense-scalar penalty.
    .globl collision_dense_aligned_pointer_return
    .type collision_dense_aligned_pointer_return, @function
collision_dense_aligned_pointer_return:
    leaq collision_dense_aligned_pointer_lattice(%rip), %r8
    movq (%r8,%rdi,8), %rax
    ret
    .size collision_dense_aligned_pointer_return, .-collision_dense_aligned_pointer_return

    # A dense table may point to adjacent, unlabeled string literals.  The
    # loaded pointer is returned (or, in real programs, passed to a callee),
    # so there is no local dereference from which to recover it.  Exact starts
    # of several independently inferred strings are the pointer evidence.
    .globl collision_dense_string_pointer_return
    .type collision_dense_string_pointer_return, @function
collision_dense_string_pointer_return:
    leaq collision_dense_string_pointer_lattice(%rip), %r8
    movq (%r8,%rdi,8), %rax
    ret
    .size collision_dense_string_pointer_return, .-collision_dense_string_pointer_return

    # Two dense subarrays share one enclosing OBJECT.  Only the second load
    # produces a pointer that is dereferenced.  Its evidence must not restore
    # the scalar candidates in the first subarray.
    .globl collision_dense_mixed_use
    .type collision_dense_mixed_use, @function
collision_dense_mixed_use:
    leaq collision_dense_mixed_object(%rip), %r8
    movq (%r8,%rdi,8), %rax
    leaq collision_literal(%rip), %rdx
    movzbl (%rdx,%rax), %ecx
    leaq collision_dense_mixed_object+320(%rip), %r8
    movq (%r8,%rdi,8), %rax
    movzbl (%rax), %ecx
    ret
    .size collision_dense_mixed_use, .-collision_dense_mixed_use

    # A broad outer OBJECT encloses two smaller siblings.  Only the scalar
    # sibling has a dense indexed load; the unused pointer sibling must not be
    # classified through the outer symbol.
    .globl collision_dense_nested_scalar_use
    .type collision_dense_nested_scalar_use, @function
collision_dense_nested_scalar_use:
    leaq collision_dense_nested_scalar(%rip), %r8
    movq (%r8,%rdi,8), %rax
    leaq collision_literal(%rip), %rdx
    movzbl (%rdx,%rax), %ecx
    ret
    .size collision_dense_nested_scalar_use, .-collision_dense_nested_scalar_use

    # Brotli-shaped code-immediate collision: 0x70003b is a packed integer,
    # not a pointer, even though it lands strictly inside the fixed data
    # OBJECT below.  Its direct shift and mask are scalar evidence.
    .globl collision_shifted_immediate_scalar
    .type collision_shifted_immediate_scalar, @function
collision_shifted_immediate_scalar:
    movl $0x70003b, %edx
    movl %edi, %ecx
    sarl %cl, %edx
    andl $0xf, %edx
    movl %edx, %eax
    ret
    .size collision_shifted_immediate_scalar, .-collision_shifted_immediate_scalar

    # Positive companion: an equally unlabeled interior value is genuinely
    # used as a memory base and must remain symbolic.
    .globl collision_immediate_address_use
    .type collision_immediate_address_use, @function
collision_immediate_address_use:
    movabsq $0x700101, %rax
    movzbl (%rax), %eax
    ret
    .size collision_immediate_address_use, .-collision_immediate_address_use

    # A bounded 32-bit relative switch table can contain an overlapping
    # eight-byte window whose raw value happens to equal an unrelated exact
    # function address.  The table below is fixed so entries 0..2 are 0x40,
    # 0x50, and 0x10000; bytes 2..9 therefore decode as 0x500000.  Those bytes
    # are still two-and-a-half scalar table entries, not a packed pointer.
    .globl collision_relative_jump_table_use
    .type collision_relative_jump_table_use, @function
collision_relative_jump_table_use:
    cmpl $2, %edi
    ja collision_relative_jump_target0
    leaq collision_relative_jump_table(%rip), %rax
    movslq (%rax,%rdi,4), %rdx
    addq %rax, %rdx
    jmp *%rdx
    .size collision_relative_jump_table_use, .-collision_relative_jump_table_use

    # Positive companion for the short-string data collision below.  The raw
    # pointer bytes also spell "ABC\0", but the loaded value is directly
    # dereferenced and therefore has independent pointer evidence.
    .globl collision_short_string_pointer_use
    .type collision_short_string_pointer_use, @function
collision_short_string_pointer_use:
    movq collision_short_string_pointer_control(%rip), %rax
    movzbl (%rax), %eax
    ret
    .size collision_short_string_pointer_use, .-collision_short_string_pointer_use

    # Positive control for an unaligned pointer whose bytes, together with a
    # printable prefix, also form "ffdhe3072".  The exact load at +6 is
    # independent source evidence and must retain the symbolic pointer.
    .globl collision_referenced_long_string_pointer_use
    .type collision_referenced_long_string_pointer_use, @function
collision_referenced_long_string_pointer_use:
    movq collision_referenced_long_string_pointer_control+6(%rip), %rax
    movzbl (%rax), %eax
    ret
    .size collision_referenced_long_string_pointer_use, .-collision_referenced_long_string_pointer_use

    # Positive control for an aligned pointer embedded after an eight-byte
    # printable prefix.  The exact qword load and dereference are independent
    # source evidence, so broadening the string-tail guard must not suppress it.
    .globl collision_referenced_aligned_tail_pointer_use
    .type collision_referenced_aligned_tail_pointer_use, @function
collision_referenced_aligned_tail_pointer_use:
    movq collision_referenced_aligned_tail_pointer_control+8(%rip), %rax
    movzbl (%rax), %eax
    ret
    .size collision_referenced_aligned_tail_pointer_use, .-collision_referenced_aligned_tail_pointer_use

    # Positive control for the zero-prefixed string overlap below.  The
    # candidate begins one byte before the referenced "DH" suffix, but an
    # exact pointer-width load and dereference independently prove that this
    # matching byte sequence is a real pointer.
    .globl collision_zero_prefixed_pointer_use
    .type collision_zero_prefixed_pointer_use, @function
collision_zero_prefixed_pointer_use:
    movq collision_zero_prefixed_pointer_string-1(%rip), %rax
    movzbl (%rax), %eax
    ret
    .size collision_zero_prefixed_pointer_use, .-collision_zero_prefixed_pointer_use

    # Positive control for the one-character suffix below.  Loading and
    # dereferencing the complete unaligned field independently proves that it
    # is a pointer even though code also references its interior "w" bytes.
    .globl collision_zero_prefixed_single_char_pointer_use
    .type collision_zero_prefixed_single_char_pointer_use, @function
collision_zero_prefixed_single_char_pointer_use:
    movq collision_zero_prefixed_single_char_pointer-2(%rip), %rax
    movzbl (%rax), %eax
    ret
    .size collision_zero_prefixed_single_char_pointer_use, .-collision_zero_prefixed_single_char_pointer_use

    # Positive control for a real packed pointer whose final six bytes also
    # belong to a named object beginning two bytes into the field.  The exact
    # pointer-width load and dereference are independent source evidence, so a
    # source-boundary collision guard must retain this expression.
    .globl collision_cross_object_boundary_pointer_use
    .type collision_cross_object_boundary_pointer_use, @function
collision_cross_object_boundary_pointer_use:
    movq collision_cross_object_boundary_pointer_object-2(%rip), %rax
    movzbl (%rax), %eax
    ret
    .size collision_cross_object_boundary_pointer_use, .-collision_cross_object_boundary_pointer_use

    # The exact target address is chosen so its little-endian bytes spell the
    # suffix "072" followed by NUL bytes.
    .section .collision_string_exact_target,"a",@progbits
    .globl collision_string_exact_target
    .type collision_string_exact_target, @object
collision_string_exact_target:
    .byte 0x42
    .size collision_string_exact_target, .-collision_string_exact_target

    # This exact object address spells "pem" followed by NUL in little-endian
    # form, matching a realistic property-string suffix collision.
    .section .collision_pem_exact_target,"a",@progbits
    .globl collision_pem_exact_target
    .type collision_pem_exact_target, @object
collision_pem_exact_target:
    .byte 0x43
    .size collision_pem_exact_target, .-collision_pem_exact_target

    # Its little-endian address begins with two zero bytes followed by
    # "w\0", matching the short literal-overlap case below.
    .section .collision_single_char_exact_target,"a",@progbits
    .globl collision_single_char_exact_target
    .type collision_single_char_exact_target, @object
collision_single_char_exact_target:
    .byte 0x44
    .size collision_single_char_exact_target, .-collision_single_char_exact_target

    # Anonymous string target whose fixed address has printable low bytes.
    # Descriptor records below repeatedly point here, while a four-record raw
    # scalar control contains the same numeric value without enough evidence.
    .section .collision_repeated_string_target,"a",@progbits
    .zero 16
.Lcollision_repeated_string_target:
    .ascii "tls-group-name"
    .byte 0

    # The section begins at 0x434240, making the local target one byte later.
    # There is deliberately no source symbol at 0x434241.
    .section .collision_format_target,"a",@progbits
    .byte 0
.Lcollision_short_string_target:
    .byte 0x41
    .zero 15

    # This section starts at 0x6c6100.  The direct branch makes 0x6c6176 a
    # code-block boundary inside collision_function, not a function entry.
    .section .collision,"ax",@progbits
    .globl collision_function
    .type collision_function, @function
collision_function:
    .byte 0xe9
    .long .Lcollision_interior - . - 4
    .fill 0x71, 1, 0x90
.Lcollision_interior:
    nop
    .globl collision_labeled_interior
collision_labeled_interior:
    jne .Lcollision_pointer_target
    jne .Lcollision_direct_target
    jne .Lcollision_table_target0
    jne .Lcollision_table_target1
    jne .Lcollision_table_target2
    jne .Lcollision_table_target3
    jne .Lcollision_relocated_target
    jne .Lcollision_register_jump_target
    jne .Lcollision_direct_jump_target
    ret
.Lcollision_pointer_target:
    xorl %eax, %eax
    ret
.Lcollision_direct_target:
    xorl %eax, %eax
    ret
.Lcollision_table_target0:
    xorl %eax, %eax
    ret
.Lcollision_table_target1:
    xorl %eax, %eax
    ret
.Lcollision_table_target2:
    xorl %eax, %eax
    ret
.Lcollision_table_target3:
    xorl %eax, %eax
    ret
.Lcollision_relocated_target:
    xorl %eax, %eax
    ret
.Lcollision_called_entry:
    xorl %eax, %eax
    ret
.Lcollision_register_jump_target:
    xorl %eax, %eax
    ret
.Lcollision_direct_jump_target:
    xorl %eax, %eax
    ret
.Lcollision_init_target:
    ret
    .size collision_function, .-collision_function

    .section .rodata
    .balign 8
    .globl collision_literal
    .type collision_literal, @object
collision_literal:
    # Numeric value that happens to match the interior code-block address.
    .quad 0x6c6176
    # Positive control: a genuine function-entry pointer remains symbolic.
    .quad collision_function
    # Positive control: an original symbol for an interior instruction is
    # independent pointer evidence and also remains symbolic.
    .quad collision_labeled_interior
    # Positive control: this stripped interior pointer has no source symbol or
    # final relocation, but its loaded value is used for an indirect call.
    .quad .Lcollision_pointer_target
    # Positive control: direct memory-indirect control flow.
    .quad .Lcollision_direct_target
    # Positive controls: an indexed pointer table.  Only its first entry is
    # selected at runtime; data-access propagation supplies evidence for all.
    .quad .Lcollision_table_target0
    .quad .Lcollision_table_target1
    .quad .Lcollision_table_target2
    .quad .Lcollision_table_target3
    # Negative control: the same accidental numeric value is used only as a
    # scaled integer index in address arithmetic.
    .quad 0x6c6176
    # Positive control: no source symbol, but a direct call independently
    # establishes this address as a function entry.
    .quad .Lcollision_called_entry
    # Positive control for the PIE companion: a dynamic relocation targets an
    # otherwise-unused unlabeled instruction inside collision_function.
    .quad .Lcollision_relocated_target
    # Positive controls for loaded-register and direct-memory jumps.
    .quad .Lcollision_register_jump_target
    .quad .Lcollision_direct_jump_target
    # Negative control used only as the index of a pointer load whose result
    # is subsequently called.
    .quad 0x6c6176

    # Negative data-address control.  These are two 16-bit scalar values plus
    # padding, not a pointer; packed as a qword they happen to equal 0x70003b,
    # an unlabeled address strictly inside collision_data_object.
    .short 59
    .short 112
    .zero 4
    # Delimit the scalar from the genuine pointer sequence so adjacency cannot
    # accidentally supply pointer-array evidence.
    .quad 0
    # Positive control: an exact target symbol is independent evidence.
    .quad collision_labeled_data_interior
    # Positive control: pointer-sized load followed by a dereference.
    .quad .Lcollision_data_dereference_target
    .quad 0
    # Positive controls: three consecutive pointers into the same data object
    # supply pointer-array evidence without requiring a runtime access.
    .quad .Lcollision_data_array_target0
    .quad .Lcollision_data_array_target1
    .quad .Lcollision_data_array_target2
    .quad 0
    # Positive control for the PIE companion: a retained relocation is the
    # only independent evidence for this otherwise-unused interior pointer.
    .quad .Lcollision_data_relocated_target
    .size collision_literal, .-collision_literal

    # "ABC\0" followed by four padding bytes is numerically 0x434241 in
    # little-endian order.  That happens to be the unlabeled interior address
    # above, but this object is text and must remain literal after relayout.
    # The adjacent longer string supplies conservative string-pool evidence;
    # printable low bytes in an otherwise unrelated pointer record do not.
    .balign 8
    .globl collision_short_string_literal
    .type collision_short_string_literal, @object
collision_short_string_literal:
    .ascii "ABC"
    .byte 0
    .zero 4
    .size collision_short_string_literal, .-collision_short_string_literal
    .ascii "neighbor-format:%s"
    .byte 0

    # Data tables also point to short option/name strings.  Here "pss\0"
    # followed by padding numerically equals 0x737370, an unlabeled mapped
    # address, while the next pointer-sized slot begins another real string.
    # The incoming table pointer and adjacent string anchor the source as text.
    .balign 8
    .globl collision_data_referenced_short_string_literal
    .type collision_data_referenced_short_string_literal, @object
collision_data_referenced_short_string_literal:
    .ascii "pss"
    .byte 0
    .zero 4
    .size collision_data_referenced_short_string_literal, .-collision_data_referenced_short_string_literal
    .ascii "PEM format string"
    .byte 0
    .balign 8
    .globl collision_short_string_reference_table
    .type collision_short_string_reference_table, @object
collision_short_string_reference_table:
    .quad collision_data_referenced_short_string_literal
    .quad 0
    .size collision_short_string_reference_table, .-collision_short_string_reference_table

    # An isolated compiler literal can have the same collision without an
    # immediately adjacent string.  "ABC\0" plus slot padding still decodes
    # as the mapped address 0x434241, but the incoming table entry identifies
    # this slot as referenced text.  The zero-filled gap ensures that no
    # neighboring-string heuristic can classify it.
    .balign 8
    .globl collision_isolated_referenced_short_string_literal
    .type collision_isolated_referenced_short_string_literal, @object
collision_isolated_referenced_short_string_literal:
    .ascii "ABC"
    .byte 0
    .zero 4
    .size collision_isolated_referenced_short_string_literal, .-collision_isolated_referenced_short_string_literal
    .zero 24
    .balign 8
    .globl collision_isolated_short_string_reference_table
    .type collision_isolated_short_string_reference_table, @object
collision_isolated_short_string_reference_table:
    .quad collision_isolated_referenced_short_string_literal
    .quad 0
    .size collision_isolated_short_string_reference_table, .-collision_isolated_short_string_reference_table

    # A referenced long string can contain an unaligned pointer-width window:
    # bytes 6..13 of "ffdhe3072\0" decode as the exact address 0x323730.
    # This label intentionally remains NOTYPE, matching compiler-generated
    # string literals that are not enclosed by an OBJECT symbol.
    .balign 8
    .globl collision_referenced_long_string_literal
collision_referenced_long_string_literal:
    .ascii "ffdhe3072"
    .byte 0
    .zero 6
    .balign 8
    .globl collision_long_string_reference_table
    .type collision_long_string_reference_table, @object
collision_long_string_reference_table:
    .quad collision_referenced_long_string_literal
    .quad 0
    .size collision_long_string_reference_table, .-collision_long_string_reference_table

    # The suffix starts at the naturally aligned +8 slot.  Its bytes are
    # "pem\0" plus padding, numerically the exact address 0x6d6570, but they
    # remain part of the independently referenced string rather than a field.
    .balign 8
    .globl collision_referenced_aligned_tail_string_literal
collision_referenced_aligned_tail_string_literal:
    .ascii "providerpem"
    .byte 0
    .zero 4
    .balign 8
    .globl collision_aligned_tail_string_reference_table
    .type collision_aligned_tail_string_reference_table, @object
collision_aligned_tail_string_reference_table:
    .quad collision_referenced_aligned_tail_string_literal
    .quad collision_referenced_aligned_tail_pointer_control
    .quad 0
    .size collision_aligned_tail_string_reference_table, .-collision_aligned_tail_string_reference_table

    # Identical linked suffix bytes are a genuine pointer in this control.
    # The helper above loads and dereferences the aligned qword at +8.
    .balign 8
    .globl collision_referenced_aligned_tail_pointer_control
    .type collision_referenced_aligned_tail_pointer_control, @object
collision_referenced_aligned_tail_pointer_control:
    .ascii "provider"
    .quad collision_pem_exact_target
    .size collision_referenced_aligned_tail_pointer_control, .-collision_referenced_aligned_tail_pointer_control

    # Identical printable bytes, but here the eight bytes at +6 are an actual
    # packed pointer consumed by collision_referenced_long_string_pointer_use.
    .balign 8
    .globl collision_referenced_long_string_pointer_control
    .type collision_referenced_long_string_pointer_control, @object
collision_referenced_long_string_pointer_control:
    .ascii "ffdhe3"
    .quad collision_string_exact_target
    .zero 2
    .size collision_referenced_long_string_pointer_control, .-collision_referenced_long_string_pointer_control

    # A zero padding byte followed by the referenced string "DH\0" decodes as
    # 0x484400 when read from one byte before the string.  The source window is
    # literal string-pool storage, not a pointer to the unrelated exact code
    # symbol at that address.
    .balign 8
    .byte 0
    .globl collision_zero_prefixed_referenced_string_literal
collision_zero_prefixed_referenced_string_literal:
    .ascii "DH"
    .byte 0
    .zero 4
    .balign 8
    .globl collision_zero_prefixed_string_reference_table
    .type collision_zero_prefixed_string_reference_table, @object
collision_zero_prefixed_string_reference_table:
    .quad collision_zero_prefixed_referenced_string_literal
    .quad 0
    .size collision_zero_prefixed_string_reference_table, .-collision_zero_prefixed_string_reference_table

    # Two zero padding bytes followed by the independently referenced literal
    # "w\0" form the eight-byte value 0x770000.  There is no pointer field at
    # the source: changing the coincidental value when the unrelated target
    # moves would change the literal to a different character.
    .balign 8
    .zero 6
    .zero 2
    .globl collision_zero_prefixed_single_char_literal
collision_zero_prefixed_single_char_literal:
    .ascii "w"
    .byte 0
    .zero 4

    # Identical bytes are a genuine unaligned pointer in this companion.  The
    # helper above consumes the complete field, which must retain priority over
    # the interior-byte reference.
    .balign 8
    .zero 6
.Lcollision_zero_prefixed_single_char_pointer_start:
    .quad collision_single_char_exact_target
    .globl collision_zero_prefixed_single_char_pointer
    .set collision_zero_prefixed_single_char_pointer, .Lcollision_zero_prefixed_single_char_pointer_start+2

    # Identical bytes are a real pointer in this companion.  A code load from
    # the byte before the named suffix supplies independent source evidence.
    .balign 8
.Lcollision_zero_prefixed_pointer_start:
    .quad collision_zero_prefix_target
    .globl collision_zero_prefixed_pointer_string
    .set collision_zero_prefixed_pointer_string, .Lcollision_zero_prefixed_pointer_start+1
    .balign 8
    .globl collision_zero_prefixed_pointer_string_reference
    .type collision_zero_prefixed_pointer_string_reference, @object
collision_zero_prefixed_pointer_string_reference:
    .quad collision_zero_prefixed_pointer_string
    .quad 0
    .size collision_zero_prefixed_pointer_string_reference, .-collision_zero_prefixed_pointer_string_reference

    # Identical linked bytes, but the code helper loads and dereferences this
    # value.  That independent use must preserve it as a symbolic pointer.
    .balign 8
    .globl collision_short_string_pointer_control
    .type collision_short_string_pointer_control, @object
collision_short_string_pointer_control:
    .quad .Lcollision_short_string_target
    .size collision_short_string_pointer_control, .-collision_short_string_pointer_control

    # The aligned qword is a genuine pointer to unlabeled data.  Its final two
    # zero bytes overlap the following scalar so that the eight-byte window at
    # +6 accidentally decodes as 0x700000, the exact address of
    # collision_data_object.  Source alignment must resolve that ambiguity in
    # favor of the qword at +0; otherwise reconstruction grows an expression
    # from the middle of the real pointer and corrupts both fields.
    .balign 8
    .globl collision_overlapping_aligned_pointer
    .type collision_overlapping_aligned_pointer, @object
collision_overlapping_aligned_pointer:
    .quad .Lcollision_unobject_target
    .quad 0x70
    .size collision_overlapping_aligned_pointer, .-collision_overlapping_aligned_pointer

    # An otherwise ordinary aligned scalar follows two zero-filled slots.  The
    # pointer-width window beginning two bytes before that scalar decodes as
    # 0x500000, exactly matching collision_exact_code_target.  It has no
    # source label, relocation, data access, or array/control-flow evidence,
    # so the unaligned window is a byte coincidence rather than a pointer.
    .balign 8
    .globl collision_unaligned_exact_symbol_scalar
    .type collision_unaligned_exact_symbol_scalar, @object
collision_unaligned_exact_symbol_scalar:
    .zero 16
    .quad 0x50
    .quad 0
    .size collision_unaligned_exact_symbol_scalar, .-collision_unaligned_exact_symbol_scalar

    # The same false-positive shape can begin in the final bytes of an OBJECT
    # and continue into anonymous padding.  The eight-byte window at +4 is
    # 0x500000, but the declared seven-byte object cannot contain a pointer
    # field starting there.  This reproduces a compiler-emitted constant
    # structure whose trailing scalar bytes coincided with a function address.
    .balign 8
    .globl collision_unaligned_object_tail_scalar
    .type collision_unaligned_object_tail_scalar, @object
collision_unaligned_object_tail_scalar:
    .zero 6
    .byte 0x50
    .size collision_unaligned_object_tail_scalar, .-collision_unaligned_object_tail_scalar
    .zero 5

    # Reverse boundary shape: two anonymous zero-padding bytes immediately
    # precede a named scalar object whose first byte is 0x50.  Reading eight
    # bytes from object-2 yields 0x500000, the exact address of an unrelated
    # code symbol.  Since no relocation, label, pointer-width access, or array
    # anchors that unaligned source, it must remain literal; relocating it
    # would overwrite the first six bytes of the named scalar object.
    .balign 8
    .zero 8
    .globl collision_unaligned_object_head_scalar
    .type collision_unaligned_object_head_scalar, @object
collision_unaligned_object_head_scalar:
    .quad 0x50
    .size collision_unaligned_object_head_scalar, .-collision_unaligned_object_head_scalar

    # Identical cross-boundary bytes form a genuine packed pointer here.  The
    # code helper above consumes the complete unaligned field, which is the
    # source provenance that distinguishes it from the scalar case.
    .balign 8
    .zero 6
.Lcollision_cross_object_boundary_pointer_start:
    .quad collision_exact_code_target
    .globl collision_cross_object_boundary_pointer_object
    .type collision_cross_object_boundary_pointer_object, @object
    .set collision_cross_object_boundary_pointer_object, .Lcollision_cross_object_boundary_pointer_start+2
    .size collision_cross_object_boundary_pointer_object, 6

    .text

    # Contiguous code-pointer array consumed through the sparse indexed access
    # above.  No individual cell receives preferred_data_access evidence; the
    # bounded indexed-load-to-register-jump pattern must retain all nine.
    .balign 8
    .globl collision_sparse_code_pointer_array
    .type collision_sparse_code_pointer_array, @object
collision_sparse_code_pointer_array:
    .quad .Lcollision_table_target0
    .quad .Lcollision_table_target1
    .quad .Lcollision_table_target2
    .quad .Lcollision_table_target3
    .quad .Lcollision_table_target0
    .quad .Lcollision_table_target1
    .quad .Lcollision_table_target2
    .quad .Lcollision_table_target3
    .quad .Lcollision_table_target0
    .size collision_sparse_code_pointer_array, .-collision_sparse_code_pointer_array

    # Directly consumed by the indexed memory-indirect jump above.  There is
    # deliberately no separate scalar load-to-jump witness for this array.
    .balign 8
    .globl collision_direct_indexed_code_pointer_array
    .type collision_direct_indexed_code_pointer_array, @object
collision_direct_indexed_code_pointer_array:
    .quad .Lcollision_table_target0
    .quad .Lcollision_table_target1
    .quad .Lcollision_table_target2
    .quad .Lcollision_table_target3
    .size collision_direct_indexed_code_pointer_array, .-collision_direct_indexed_code_pointer_array

    # Negative companion: the same contiguous code-looking values are raw
    # integers in a separate symbol-delimited array with no control-flow use.
    # Evidence from the preceding real jump table must not cross this label.
    .balign 8
    .globl collision_unused_code_like_array
    .type collision_unused_code_like_array, @object
collision_unused_code_like_array:
    .quad 0x6c6190
    .quad 0x6c6193
    .quad 0x6c6196
    .quad 0x6c6199
    .quad 0x6c6190
    .quad 0x6c6193
    .quad 0x6c6196
    .quad 0x6c6199
    .quad 0x6c6190
    .size collision_unused_code_like_array, .-collision_unused_code_like_array

    # Five 40-byte records exercise a repeated pointer field that is hidden
    # from the ordinary address-array heuristic by an interleaved pointer into
    # a different object.  Neither target has an exact source symbol.
    .balign 8
    .globl collision_strided_records
    .type collision_strided_records, @object
collision_strided_records:
    .quad .Lcollision_strided_target0
    .quad collision_labeled_interleaved_interior
    .zero 24
    .quad .Lcollision_strided_target1
    .quad collision_labeled_interleaved_interior
    .zero 24
    .quad .Lcollision_strided_target2
    .quad collision_labeled_interleaved_interior
    .zero 24
    .quad .Lcollision_strided_target3
    .quad collision_labeled_interleaved_interior
    .zero 24
    .quad .Lcollision_strided_target4
    .quad collision_labeled_interleaved_interior
    .zero 24
    .size collision_strided_records, .-collision_strided_records

    # Negative control: five equally spaced address-shaped scalar fields are
    # not enough when their record stride is only three pointer widths.  Exact
    # pointers into a different object are interleaved so address-array
    # adjacency cannot accidentally decide the scalar fields.
    .balign 8
    .globl collision_short_stride_scalars
    .type collision_short_stride_scalars, @object
collision_short_stride_scalars:
    .quad 0x70003b
    .quad collision_labeled_interleaved_interior
    .quad 0
    .quad 0x70003b
    .quad collision_labeled_interleaved_interior
    .quad 0
    .quad 0x70003b
    .quad collision_labeled_interleaved_interior
    .quad 0
    .quad 0x70003b
    .quad collision_labeled_interleaved_interior
    .quad 0
    .quad 0x70003b
    .quad collision_labeled_interleaved_interior
    .quad 0
    .size collision_short_stride_scalars, .-collision_short_stride_scalars

    # Packed scalar fields can also form a three-member address-like sequence
    # at a byte stride that is not a whole number of pointer widths.  Brotli's
    # static-dictionary buckets contain this exact 22-byte pattern.  It is not
    # pointer-array evidence even though all three values land in one data
    # segment.
    .balign 8
    .globl collision_irregular_stride_scalars
    .type collision_irregular_stride_scalars, @object
collision_irregular_stride_scalars:
    .quad 0x700307
    .zero 14
    .quad 0x70030f
    .zero 14
    .quad 0x700317
    .quad 0
    .size collision_irregular_stride_scalars, .-collision_irregular_stride_scalars

    # Negative boundary control: two four-record groups would form one
    # eight-member, four-pointer-width run without the original symbol at the
    # midpoint.  Neither side alone reaches the required five members.
    .balign 8
    .globl collision_boundary_split_records
    .type collision_boundary_split_records, @object
collision_boundary_split_records:
    .quad .Lcollision_strided_target0
    .quad collision_labeled_interleaved_interior
    .zero 16
    .quad .Lcollision_strided_target0
    .quad collision_labeled_interleaved_interior
    .zero 16
    .quad .Lcollision_strided_target0
    .quad collision_labeled_interleaved_interior
    .zero 16
    .quad .Lcollision_strided_target0
    .quad collision_labeled_interleaved_interior
    .zero 16
    .globl collision_record_boundary
collision_record_boundary:
    .quad .Lcollision_strided_target0
    .quad collision_labeled_interleaved_interior
    .zero 16
    .quad .Lcollision_strided_target0
    .quad collision_labeled_interleaved_interior
    .zero 16
    .quad .Lcollision_strided_target0
    .quad collision_labeled_interleaved_interior
    .zero 16
    .quad .Lcollision_strided_target0
    .quad collision_labeled_interleaved_interior
    .zero 16
    .size collision_boundary_split_records, .-collision_boundary_split_records

    # Negative gap control: a genuine five-record run is followed by one
    # missing record slot and then a congruent raw scalar.  Recovery may keep
    # the five proven pointer fields, but it must not jump across the hole and
    # reinterpret the scalar as a pointer.
    .balign 8
    .globl collision_gap_records
    .type collision_gap_records, @object
collision_gap_records:
    .quad .Lcollision_strided_target0
    .quad collision_labeled_interleaved_interior
    .zero 16
    .quad .Lcollision_strided_target0
    .quad collision_labeled_interleaved_interior
    .zero 16
    .quad .Lcollision_strided_target0
    .quad collision_labeled_interleaved_interior
    .zero 16
    .quad .Lcollision_strided_target0
    .quad collision_labeled_interleaved_interior
    .zero 16
    .quad .Lcollision_strided_target0
    .quad collision_labeled_interleaved_interior
    .zero 16
    .zero 32
    .quad 0x700417
    .quad collision_labeled_interleaved_interior
    .zero 16
    .size collision_gap_records, .-collision_gap_records

    # A descriptor field can be separated from a later five-record pointer
    # run by a null record.  Its preceding u32 byte length and a retained
    # pointer two records later provide independent evidence: target1 is
    # exactly eight bytes after target0.  This models the sparse OpenSSL
    # ASN1_OBJECT.data fields that must relocate when section layout changes.
    .balign 8
    .globl collision_length_delimited_records
    .type collision_length_delimited_records, @object
collision_length_delimited_records:
    .long 0
    .long 8
    .quad .Lcollision_strided_target0
    .zero 24
    .zero 40
    .long 0
    .long 0
    .quad .Lcollision_strided_target1
    .zero 24
    .long 0
    .long 0
    .quad .Lcollision_strided_target2
    .zero 24
    .long 0
    .long 0
    .quad .Lcollision_strided_target3
    .zero 24
    .long 0
    .long 0
    .quad .Lcollision_strided_target4
    .zero 24
    .long 0
    .long 0
    .quad .Lcollision_strided_target0
    .zero 24
    .size collision_length_delimited_records, .-collision_length_delimited_records

    # A mismatched length has the same source/destination shape but is not
    # sufficient evidence.  Its isolated first field must remain literal.
    .balign 8
    .globl collision_bad_length_delimited_records
    .type collision_bad_length_delimited_records, @object
collision_bad_length_delimited_records:
    .long 0
    .long 7
    .quad .Lcollision_strided_target0
    .zero 24
    .zero 40
    .long 0
    .long 0
    .quad .Lcollision_strided_target1
    .zero 24
    .long 0
    .long 0
    .quad .Lcollision_strided_target2
    .zero 24
    .long 0
    .long 0
    .quad .Lcollision_strided_target3
    .zero 24
    .long 0
    .long 0
    .quad .Lcollision_strided_target4
    .zero 24
    .long 0
    .long 0
    .quad .Lcollision_strided_target0
    .zero 24
    .size collision_bad_length_delimited_records, .-collision_bad_length_delimited_records

    # A large descriptor object can begin with a pointer whose low bytes also
    # form a short NUL-terminated string.  The first field is referenced as the
    # table base, which is normally negative string evidence, but five records
    # repeat the same anonymous-string pointer at a 40-byte stride.
    .section .rodata
    .balign 8
    .globl collision_leading_repeated_string_records
    .type collision_leading_repeated_string_records, @object
collision_leading_repeated_string_records:
    .quad .Lcollision_repeated_string_target
    .quad 4
    .quad collision_short_string_literal
    .quad 8
    .quad -1
    .quad .Lcollision_repeated_string_target
    .quad 4
    .quad collision_short_string_literal
    .quad 8
    .quad -1
    .quad .Lcollision_repeated_string_target
    .quad 4
    .quad collision_short_string_literal
    .quad 8
    .quad -1
    .quad .Lcollision_repeated_string_target
    .quad 4
    .quad collision_short_string_literal
    .quad 8
    .quad -1
    .quad .Lcollision_repeated_string_target
    .quad 4
    .quad collision_short_string_literal
    .quad 8
    .quad -1
    .size collision_leading_repeated_string_records, .-collision_leading_repeated_string_records

    # Negative control: four records repeat the same address-shaped scalar.
    # Referencing the object start makes its first field look like a short
    # string, and four records are intentionally insufficient for recovery.
    .balign 8
    .globl collision_four_repeated_string_scalars
    .type collision_four_repeated_string_scalars, @object
collision_four_repeated_string_scalars:
    .quad 0x742b60
    .quad 4
    .quad collision_short_string_literal
    .quad 8
    .quad -1
    .quad 0x742b60
    .quad 4
    .quad collision_short_string_literal
    .quad 8
    .quad -1
    .quad 0x742b60
    .quad 4
    .quad collision_short_string_literal
    .quad 8
    .quad -1
    .quad 0x742b60
    .quad 4
    .quad collision_short_string_literal
    .quad 8
    .quad -1
    .size collision_four_repeated_string_scalars, .-collision_four_repeated_string_scalars

    # Four compiler-generated descriptor records can carry two pointer/length
    # fields at the same record stride.  The first field begins at the exact
    # destination OBJECT, while every later target is an unlabeled interior
    # address.  Alternating 40- and 80-byte source gaps keep the fields from
    # looking like an ordinary contiguous pointer array.  Keep the source
    # symbol as NOTYPE: real compiler constant pools need not have an enclosing
    # source OBJECT symbol.
    .balign 8
    .globl collision_sized_descriptor_records
collision_sized_descriptor_records:
    .quad collision_sized_descriptor_target+0
    .quad 4
    .zero 24
    .quad collision_sized_descriptor_target+8
    .quad 4
    .zero 64
    .quad collision_sized_descriptor_target+16
    .quad 5
    .zero 24
    .quad collision_sized_descriptor_target+24
    .quad 5
    .zero 64
    .quad collision_sized_descriptor_target+32
    .quad 6
    .zero 24
    .quad collision_sized_descriptor_target+40
    .quad 6
    .zero 64
    .quad collision_sized_descriptor_target+48
    .quad 7
    .zero 24
    .quad collision_sized_descriptor_target+56
    .quad 7
    .zero 64
    .size collision_sized_descriptor_records, .-collision_sized_descriptor_records

    # Negative control: the same descriptor layout has one out-of-sequence
    # primary target.  An exact first target and plausible lengths alone must
    # not promote the remaining address-shaped integers.
    .balign 8
    .globl collision_bad_sized_descriptor_records
collision_bad_sized_descriptor_records:
    .quad collision_bad_sized_descriptor_target+0
    .quad 4
    .zero 24
    .quad collision_bad_sized_descriptor_target+8
    .quad 4
    .zero 64
    .quad collision_bad_sized_descriptor_target+16
    .quad 5
    .zero 24
    .quad collision_bad_sized_descriptor_target+24
    .quad 5
    .zero 64
    .quad collision_bad_sized_descriptor_target+33
    .quad 6
    .zero 24
    .quad collision_bad_sized_descriptor_target+40
    .quad 6
    .zero 64
    .quad collision_bad_sized_descriptor_target+48
    .quad 7
    .zero 24
    .quad collision_bad_sized_descriptor_target+56
    .quad 7
    .zero 64
    .size collision_bad_sized_descriptor_records, .-collision_bad_sized_descriptor_records

    .text

    # Negative control modeled on Brotli's dense uint64 entropy tables.  Only
    # every eighth qword happens to equal an unlabeled interior data address;
    # the table is nevertheless accessed at an eight-byte multiplier.
    .balign 8
    .globl collision_dense_scalar_lattice
    .type collision_dense_scalar_lattice, @object
collision_dense_scalar_lattice:
    # A zero run creates an inferred data-access limit before the address-like
    # cells.  The object-wide dense-load witness must still reach them even
    # though preferred_data_access does not.
    .zero 64
    .quad 0x700307
    .zero 56
    .quad 0x70030f
    .zero 56
    .quad 0x700317
    .zero 56
    .quad 0x70031f
    .zero 56
    .quad 0x700327
    .zero 56
    .size collision_dense_scalar_lattice, .-collision_dense_scalar_lattice

    .balign 8
    .globl collision_dense_scalar32_lattice
    .type collision_dense_scalar32_lattice, @object
collision_dense_scalar32_lattice:
    # These values land in an unlabeled data-segment gap outside every
    # nonzero destination OBJECT, mirroring the four kNonZeroRepsBits escapes.
    .quad 0x700403
    .zero 24
    .quad 0x700405
    .zero 24
    .quad 0x700407
    .zero 24
    .quad 0x700409
    .zero 24
    .quad 0x70040b
    .zero 24
    .size collision_dense_scalar32_lattice, .-collision_dense_scalar32_lattice

    .balign 8
    .globl collision_dense_u32_scalar_table
    .type collision_dense_u32_scalar_table, @object
collision_dense_u32_scalar_table:
    .long 1
    .long 2
    # Keep the address-like pair beyond an inferred access-propagation limit.
    # The indexed uint32_t load still describes the complete OBJECT, including
    # scalar cells after this zero run.
    .zero 64
    # On this fixture collision_strided_data_object is exactly 0x700010.
    # These are ordinary 32-bit numeric entries, not a stored pointer.
    .long 0x700010
    .long 0
    .long 3
    .long 4
    .long 5
    .long 6
    .size collision_dense_u32_scalar_table, .-collision_dense_u32_scalar_table

    # Positive control with the same source layout and raw values.  The code
    # above directly dereferences the value loaded from this table.
    .balign 8
    .globl collision_dense_pointer_lattice
    .type collision_dense_pointer_lattice, @object
collision_dense_pointer_lattice:
    .quad 0x700307
    .zero 56
    .quad 0x70030f
    .zero 56
    .quad 0x700317
    .zero 56
    .quad 0x70031f
    .zero 56
    .quad 0x700327
    .zero 56
    .size collision_dense_pointer_lattice, .-collision_dense_pointer_lattice

    # Aligned genuine pointers with the same dense source layout.  The load
    # returns its result, like OpenSSL's standard-method accessor.
    .balign 8
    .globl collision_dense_aligned_pointer_lattice
    .type collision_dense_aligned_pointer_lattice, @object
collision_dense_aligned_pointer_lattice:
    .quad 0x700308
    .zero 56
    .quad 0x700310
    .zero 56
    .quad 0x700318
    .zero 56
    .quad 0x700320
    .zero 56
    .quad 0x700328
    .zero 56
    .size collision_dense_aligned_pointer_lattice, .-collision_dense_aligned_pointer_lattice

    # All six string starts have address residue one modulo eight.  This
    # deliberately exercises the misaligned-target dense-scalar penalty.
    .byte 0
.Lcollision_dense_string0:
    .asciz "string0"
.Lcollision_dense_string1:
    .asciz "string1"
.Lcollision_dense_string2:
    .asciz "string2"
.Lcollision_dense_string3:
    .asciz "string3"
.Lcollision_dense_string4:
    .asciz "string4"
.Lcollision_dense_string5:
    .asciz "string5"
    .balign 8
    .globl collision_dense_string_pointer_lattice
    .type collision_dense_string_pointer_lattice, @object
collision_dense_string_pointer_lattice:
    .quad .Lcollision_dense_string0
    .quad .Lcollision_dense_string1
    .quad .Lcollision_dense_string2
    .quad .Lcollision_dense_string3
    .quad .Lcollision_dense_string4
    .quad .Lcollision_dense_string5
    .size collision_dense_string_pointer_lattice, .-collision_dense_string_pointer_lattice

    # Mixed-object isolation control.  Both subarrays are misaligned and share
    # the same OBJECT.  Only offsets 320 and above are loaded and dereferenced
    # as pointers; offsets below 320 remain scalar collisions.
    .balign 8
    .globl collision_dense_mixed_object
    .type collision_dense_mixed_object, @object
collision_dense_mixed_object:
    .quad 0x700307
    .zero 56
    .quad 0x70030f
    .zero 56
    .quad 0x700317
    .zero 56
    .quad 0x70031f
    .zero 56
    .quad 0x700327
    .zero 56
    .quad 0x700337
    .zero 56
    .quad 0x70033f
    .zero 56
    .quad 0x700347
    .zero 56
    .quad 0x70034f
    .zero 56
    .quad 0x700357
    .zero 56
    .size collision_dense_mixed_object, .-collision_dense_mixed_object

    # Nested-source isolation control.  The outer symbol spans both siblings;
    # selecting the smallest containing OBJECT prevents the scalar sibling's
    # dense load from penalizing genuine pointers in its unused sibling.
    .balign 8
    .globl collision_dense_nested_outer
    .type collision_dense_nested_outer, @object
collision_dense_nested_outer:
    .globl collision_dense_nested_scalar
    .type collision_dense_nested_scalar, @object
collision_dense_nested_scalar:
    .quad 0x700307
    .zero 56
    .quad 0x70030f
    .zero 56
    .quad 0x700317
    .zero 56
    .quad 0x70031f
    .zero 56
    .quad 0x700327
    .zero 56
    .size collision_dense_nested_scalar, .-collision_dense_nested_scalar
    .globl collision_dense_nested_pointer
    .type collision_dense_nested_pointer, @object
collision_dense_nested_pointer:
    .quad 0x700337
    .zero 56
    .quad 0x70033f
    .zero 56
    .quad 0x700347
    .zero 56
    .quad 0x70034f
    .zero 56
    .quad 0x700357
    .zero 56
    .size collision_dense_nested_pointer, .-collision_dense_nested_pointer
    .size collision_dense_nested_outer, .-collision_dense_nested_outer

    # A fixed-address data object makes the packed 0x70003b scalar above a
    # deterministic strict-interior collision.  Filler bytes deliberately do
    # not resemble addresses.
    .section .collision_data,"a",@progbits
    .balign 8
    .globl collision_data_object
    .type collision_data_object, @object
collision_data_object:
    .fill 0x3b, 1, 0xa5
    .byte 0x31
    .fill 0x44, 1, 0xa5
    .globl collision_labeled_data_interior
    .type collision_labeled_data_interior, @object
collision_labeled_data_interior:
    .byte 0x32
    .size collision_labeled_data_interior, 1
    .fill 0x7f, 1, 0xa5
.Lcollision_data_dereference_target:
    .byte 0x33
    .fill 0xff, 1, 0xa5
.Lcollision_data_array_target0:
    .byte 0x34
    .fill 7, 1, 0xa5
.Lcollision_data_array_target1:
    .byte 0x35
    .fill 7, 1, 0xa5
.Lcollision_data_array_target2:
    .byte 0x36
    .fill 0xef, 1, 0xa5
.Lcollision_data_relocated_target:
    .byte 0x37
    .fill 0xff, 1, 0xa5
    .size collision_data_object, .-collision_data_object

    # Fixed-address exact code symbol used only as the destination-side half
    # of the unaligned scalar collision above.
    .section .collision_exact_code,"ax",@progbits
    .balign 16
    .globl collision_exact_code_target
    .type collision_exact_code_target, @function
collision_exact_code_target:
    xorl %eax, %eax
    ret
    .size collision_exact_code_target, .-collision_exact_code_target

    # Its little-endian address bytes are 00 44 48 00..., matching the
    # zero-padding-plus-"DH" window above.
    .section .collision_zero_prefix_target,"ax",@progbits
    .globl collision_zero_prefix_target
    .type collision_zero_prefix_target, @function
collision_zero_prefix_target:
    xorl %eax, %eax
    ret
    .size collision_zero_prefix_target, .-collision_zero_prefix_target

    # Keep this table symbol as NOTYPE, matching compiler-emitted anonymous
    # switch tables that are not enclosed by an OBJECT symbol.
    .section .collision_relative_table,"a",@progbits
    .globl collision_relative_jump_table
collision_relative_jump_table:
    .long collision_relative_jump_target0-collision_relative_jump_table
    .long collision_relative_jump_target1-collision_relative_jump_table
    .long collision_relative_jump_target2-collision_relative_jump_table

    .section .collision_relative_targets,"ax",@progbits
    .globl collision_relative_jump_target0
    .type collision_relative_jump_target0, @function
collision_relative_jump_target0:
    xorl %eax, %eax
    ret
    .fill 13, 1, 0x90
    .size collision_relative_jump_target0, .-collision_relative_jump_target0
    .globl collision_relative_jump_target1
    .type collision_relative_jump_target1, @function
collision_relative_jump_target1:
    xorl %eax, %eax
    ret
    .size collision_relative_jump_target1, .-collision_relative_jump_target1

    .section .collision_relative_target2,"ax",@progbits
    .globl collision_relative_jump_target2
    .type collision_relative_jump_target2, @function
collision_relative_jump_target2:
    xorl %eax, %eax
    ret
    .size collision_relative_jump_target2, .-collision_relative_jump_target2

    .section .collision_data,"a",@progbits

    # Deliberate unlabeled data-segment gap for
    # collision_dense_scalar32_lattice.  Its first byte is also the genuine
    # target of collision_overlapping_aligned_pointer; the local label is not
    # retained in the linked symbol table.
.Lcollision_unobject_target:
    .byte 0xd5
    .zero 15

    .balign 8
    .globl collision_strided_data_object
    .type collision_strided_data_object, @object
collision_strided_data_object:
    .fill 7, 1, 0xb5
.Lcollision_strided_target0:
    .byte 0x41
    .fill 7, 1, 0xb5
.Lcollision_strided_target1:
    .byte 0x42
    .fill 7, 1, 0xb5
.Lcollision_strided_target2:
    .byte 0x43
    .fill 7, 1, 0xb5
.Lcollision_strided_target3:
    .byte 0x44
    .fill 7, 1, 0xb5
.Lcollision_strided_target4:
    .byte 0x45
    .fill 0x17, 1, 0xb5
    .size collision_strided_data_object, .-collision_strided_data_object

    .balign 8
    .globl collision_interleaved_data_object
    .type collision_interleaved_data_object, @object
collision_interleaved_data_object:
    .fill 7, 1, 0xc5
.Lcollision_interleaved_target0:
    .globl collision_labeled_interleaved_interior
    .type collision_labeled_interleaved_interior, @object
collision_labeled_interleaved_interior:
    .byte 0x51
    .size collision_labeled_interleaved_interior, 1
    .fill 7, 1, 0xc5
.Lcollision_interleaved_target1:
    .byte 0x52
    .fill 7, 1, 0xc5
.Lcollision_interleaved_target2:
    .byte 0x53
    .fill 7, 1, 0xc5
.Lcollision_interleaved_target3:
    .byte 0x54
    .fill 7, 1, 0xc5
.Lcollision_interleaved_target4:
    .byte 0x55
    .fill 0x17, 1, 0xc5
    .size collision_interleaved_data_object, .-collision_interleaved_data_object

    # Destination objects for the sized descriptor-record fixtures above.
    # Interior bytes deliberately have no labels, so only the record lattice
    # can distinguish their stored addresses from coincidental integers.
    .balign 8
    .globl collision_sized_descriptor_target
    .type collision_sized_descriptor_target, @object
collision_sized_descriptor_target:
    .fill 80, 1, 0xd5
    .size collision_sized_descriptor_target, .-collision_sized_descriptor_target

    .balign 8
    .globl collision_bad_sized_descriptor_target
    .type collision_bad_sized_descriptor_target, @object
collision_bad_sized_descriptor_target:
    .fill 80, 1, 0xe5
    .size collision_bad_sized_descriptor_target, .-collision_bad_sized_descriptor_target

    # Positive control: the target has no symbol or unwind entry and is known
    # as a function entry only because it appears in a function-pointer
    # section.  The pointer label makes the data cell easy to inspect without
    # adding symbol provenance to its target.
    .section .init_array,"aw",@init_array
    .balign 8
    .globl collision_init_pointer
    .type collision_init_pointer, @object
collision_init_pointer:
    .quad .Lcollision_init_target
    .size collision_init_pointer, .-collision_init_pointer

    # Mapped but unlabeled destination whose address is spelled by the short
    # string above.  Keeping the local label out of the linked symbol table
    # ensures destination identity alone supplies no source-field evidence.
    .section .collision_short_string_target,"a",@progbits
    .zero 16
.Lcollision_data_referenced_short_string_target:
    .byte 0xe5

    .section .note.GNU-stack,"",@progbits
