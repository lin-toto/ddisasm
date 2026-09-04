.text

.globl _start
.type _start, @function
_start:

    # Select a table copy whose low address bits match the stack.  This is a
    # reduced form of an idiom used by hand-written lookup-table assembly.
    leaq .Ltable(%rip), %r14
    leaq 0x300(%rsp), %rbp
    subq %r14, %rbp
    andq $0x300, %rbp
    leaq (%r14,%rbp), %r14

    # MASK's lowest set bit is 0x100, so the selected address must retain a
    # zero low byte after reconstruction.  Also materialize an earlier base,
    # add a constant, and load the selected table through a fixed displacement.
    # Aligning only .Ltable would insert padding between these two labels and
    # silently change the effective address of that load.
    movq %r14, %rax
    andl $0xff, %eax
    leaq .Ltable_base(%rip), %rbx
    leaq 0x880(%rbx), %rbx
    movzbl -0x80(%rbx), %ebx
    xorl $6, %ebx
    orl %ebx, %eax
    movl %eax, %edi
    movl $60, %eax
    syscall
.size _start, . - _start

# Keep the base exactly 0x800 bytes before the selected table.  It deliberately
# has no ELF symbol or alignment metadata of its own; ddisasm must infer that
# its alignment is coupled to .Ltable by the constant-derived load above.
.balign 256
.Ltable_base:
    .byte 0x06
    .fill 0x7ff, 1, 0x5a

# Keep this target absent from the ELF symbol table.  ddisasm must infer its
# label from the PC-relative LEA and recover alignment from the arithmetic.
.Ltable:
    # Four deterministic, identical 256-byte copies.  The first byte (0x06)
    # is not an instruction in x86-64 mode, helping the frontend classify the
    # inferred target as data without giving it an ELF symbol.
    .macro table_copy
    .set table_i, 0
    .rept 256
    .byte ((table_i * 197 + 6) & 255)
    .set table_i, table_i + 1
    .endr
    .endm
    table_copy
    table_copy
    table_copy
    table_copy

.section .note.GNU-stack,"",@progbits
