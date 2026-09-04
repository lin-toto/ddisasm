import platform
import unittest

import gtirb

import snippets


class DataAccessTests(unittest.TestCase):
    @unittest.skipUnless(
        platform.system() == "Linux", "This test is linux only."
    )
    def test_x86_simple(self):
        module = snippets.asm_to_gtirb(
            """
            .access:
            movl .data0(%rip), %eax
            jmp .end
            .data0:
                .long 0
            .end:
            """
        )

        accesses = snippets.parse_souffle_output(
            module, "arch.simple_data_load"
        )
        self.assertIn(
            (
                next(module.symbols_named(".access")).referent.address,
                next(module.symbols_named(".data0")).referent.address,
                4,
            ),
            accesses,
        )

    @unittest.skipUnless(
        platform.system() == "Linux", "This test is linux only."
    )
    def test_x86_simple_non_move_vector_read(self):
        """A memory-source arithmetic instruction records its full read."""
        module = snippets.asm_to_gtirb(
            """
            .address:
            leaq .data0(%rip), %rax
            .access:
            vpaddd .data0(%rip), %zmm12, %zmm12
            jmp .end
            .p2align 6
            .data0:
                .long 0, 1, 2, 3, 4, 5, 6, 7
                .long 8, 9, 10, 11, 12, 13, 14, 15
            .end:
            """
        )

        access = next(module.symbols_named(".access")).referent.address
        address = next(module.symbols_named(".address")).referent.address
        data = next(module.symbols_named(".data0")).referent
        accesses = snippets.parse_souffle_output(
            module, "arch.simple_data_load"
        )
        self.assertIn((access, data.address, 64), accesses)

        memory_accesses = list(
            snippets.parse_souffle_output(module, "arch.memory_access") or []
        )
        self.assertFalse(
            any(
                access_type == "LOAD" and ea == address
                for access_type, ea, *_ in memory_accesses
            ),
            "LEA is address generation, not a memory load",
        )

        self.assertEqual(
            [
                block
                for block in module.code_blocks
                if block.address < data.address + 64
                and block.address + block.size > data.address
            ],
            [],
        )

    @unittest.skipUnless(
        platform.system() == "Linux", "This test is linux only."
    )
    def test_x86_non_move_scalar_read_is_not_value_load(self):
        """A read-modify-write operand is a read, not a replacement load."""
        constant_value = 0x12345678
        module = snippets.asm_to_gtirb(
            f"""
            .access:
            addq .constant(%rip), %rax
            .use:
            movq (%rax), %rcx
            jmp .end
            .p2align 3
            .constant:
                .quad {constant_value}
            .end:
            """
        )

        access = next(module.symbols_named(".access")).referent.address
        constant = next(module.symbols_named(".constant")).referent.address

        simple_reads = list(
            snippets.parse_souffle_output(module, "arch.simple_data_load")
            or []
        )
        self.assertIn((access, constant, 8), simple_reads)

        memory_accesses = list(
            snippets.parse_souffle_output(module, "arch.memory_access") or []
        )
        self.assertFalse(
            any(
                access_type == "LOAD" and ea == access
                for access_type, ea, *_ in memory_accesses
            ),
            "ADD reads memory but does not replace its destination register",
        )

        value_regs = list(
            snippets.parse_souffle_output(module, "value_reg") or []
        )
        self.assertFalse(
            any(
                ea == access
                and reg == "RAX"
                and multiplier == 0
                and value == constant_value
                for ea, reg, _, _, multiplier, value, _ in value_regs
            ),
            "ADD must not make RAX equal to the memory operand",
        )

    @unittest.skipUnless(
        platform.system() == "Linux", "This test is linux only."
    )
    def test_x86_post_function_non_move_fixed_reads_are_data(self):
        """Arithmetic reads establish an anonymous constant-pool extent."""
        module = snippets.asm_to_gtirb(
            """
            .globl read_arithmetic_pool
            .type read_arithmetic_pool, @function
            read_arithmetic_pool:
            .cfi_startproc
                pushq %r14
                leaq .Larithmetic_pool(%rip), %r14
                testl %edi, %edi
                jne .Lread_arithmetic_pool
                nop
            .Lread_arithmetic_pool:
            .read0:
                addl 0(%r14), %eax
            .read1:
                xorl 4(%r14), %eax
            .read2:
                addl 8(%r14), %eax
            .read3:
                xorl 12(%r14), %eax
            .read4:
                addl 40(%r14), %eax
            .read5:
                xorl 44(%r14), %eax
                popq %r14
                retq
            .cfi_endproc
            .size read_arithmetic_pool, . - read_arithmetic_pool

            .p2align 4
            .Larithmetic_pool:
                .byte 0x8b, 0x90, 0xcc, 0x3b, 0x7f, 0x66, 0x9e, 0xa0
                .byte 0xb2, 0x73, 0xaa, 0x4c, 0x58, 0xe8, 0x7a, 0xb6
                .byte 0xbe, 0x82, 0x4f, 0xe9, 0x2f, 0x37, 0xef, 0xc6
                .byte 0x1c, 0x6f, 0xd3, 0xf1, 0xa5, 0x53, 0xff, 0x54
                .byte 0x1d, 0x2d, 0x68, 0xde, 0xfa, 0x27, 0xe5, 0x10
                .byte 0xfd, 0xc1, 0xe6, 0xb3, 0xc2, 0x88, 0x56, 0xb0

            .globl after_arithmetic_pool
            .type after_arithmetic_pool, @function
            after_arithmetic_pool:
                xorl %eax, %eax
                retq
            .size after_arithmetic_pool, . - after_arithmetic_pool

            .data
            .p2align 3
                .quad .Larithmetic_pool + 1
            .text
            """
        )

        reads = {
            next(module.symbols_named(f".read{i}")).referent.address
            for i in range(6)
        }
        value_loads = list(
            snippets.parse_souffle_output(module, "arch.memory_access") or []
        )
        self.assertFalse(
            any(
                access_type == "LOAD" and ea in reads
                for access_type, ea, *_ in value_loads
            ),
            "arithmetic reads must not become register-replacement loads",
        )

        memory_reads = list(
            snippets.parse_souffle_output(module, "arch.memory_read") or []
        )
        self.assertEqual(
            {ea for ea, *_ in memory_reads if ea in reads},
            reads,
        )

        marker = bytes.fromhex(
            "8b90cc3b7f669ea0b273aa4c58e87ab6"
            "be824fe92f37efc61c6fd3f1a553ff54"
            "1d2d68defa27e510fdc1e6b3c28856b0"
        )
        matches = []
        for section in module.sections:
            for interval in section.byte_intervals:
                if interval.address is None:
                    continue
                offset = bytes(interval.contents).find(marker)
                if offset >= 0:
                    matches.append(interval.address + offset)
        self.assertEqual(len(matches), 1)
        pool_address = matches[0]
        pool_end = pool_address + len(marker)
        self.assertEqual(
            [
                block
                for block in module.code_blocks
                if block.address < pool_end
                and block.address + block.size > pool_address
            ],
            [],
        )

    @unittest.skipUnless(
        platform.system() == "Linux", "This test is linux only."
    )
    def test_x86_post_function_non_move_indexed_reads_are_data(self):
        """Indexed arithmetic reads establish a post-function table."""
        module = snippets.asm_to_gtirb(
            """
            .globl read_indexed_arithmetic_pool
            .type read_indexed_arithmetic_pool, @function
            read_indexed_arithmetic_pool:
            .cfi_startproc
                pushq %rbp
            .indexed_base_definition:
                leaq .Lindexed_arithmetic_pool(%rip), %rbp
                andl $7, %edi
                testl %esi, %esi
                jne .Lindexed_arithmetic_reads
                nop
            .Lindexed_arithmetic_reads:
            .indexed_read0:
                addl 0(%rbp,%rdi,8), %eax
            .indexed_read1:
                xorl 4(%rbp,%rdi,8), %eax
                popq %rbp
                retq
            .cfi_endproc
            .size read_indexed_arithmetic_pool, \
                . - read_indexed_arithmetic_pool

            .p2align 4
            .Lindexed_arithmetic_pool:
                .rept 8
                .long 0x428a2f98, 0x71374491
                .endr

            .globl after_indexed_arithmetic_pool
            .type after_indexed_arithmetic_pool, @function
            after_indexed_arithmetic_pool:
                xorl %eax, %eax
                retq
            .size after_indexed_arithmetic_pool, \
                . - after_indexed_arithmetic_pool

            .data
            .p2align 3
                .quad .Lindexed_arithmetic_pool + 1
            .text
            """
        )

        definition = next(
            module.symbols_named(".indexed_base_definition")
        ).referent.address
        loads = {
            next(module.symbols_named(f".indexed_read{i}")).referent.address
            for i in range(2)
        }
        indexed_uses = list(
            snippets.parse_souffle_output(
                module, "pc_relative_indexed_data_use"
            )
            or []
        )
        self.assertEqual(
            {
                load_ea
                for def_ea, _, load_ea in indexed_uses
                if def_ea == definition and load_ea in loads
            },
            loads,
        )

        after = next(
            module.symbols_named("after_indexed_arithmetic_pool")
        ).referent.address
        pool_address = after - 64
        self.assertEqual(
            [
                block
                for block in module.code_blocks
                if pool_address <= block.address < after
            ],
            [],
        )

    @unittest.skipUnless(
        platform.system() == "Linux", "This test is linux only."
    )
    def test_x86_post_function_moved_fixed_reads_are_data(self):
        """Fixed reads through a selected table base establish data."""
        module = snippets.asm_to_gtirb(
            """
            .globl read_moved_fixed_pool
            .type read_moved_fixed_pool, @function
            read_moved_fixed_pool:
            .cfi_startproc
                pushq %r14
                movq %rdi, %r14
            .moved_fixed_definition:
                leaq .Lmoved_fixed_pool(%rip), %r10
                testl %esi, %esi
                cmove %r10, %r14
            .moved_fixed_read0:
                addq 0(%r14), %rax
            .moved_fixed_read1:
                xorq 32(%r14), %rax
            .moved_fixed_read2:
                addq 64(%r14), %rax
            .moved_fixed_read3:
                xorq 96(%r14), %rax
                popq %r14
                retq
            .cfi_endproc
            .size read_moved_fixed_pool, . - read_moved_fixed_pool

            .p2align 4
            .Lmoved_fixed_pool:
                .byte 0x51, 0xf4, 0xa7, 0x50, 0x51, 0xf4, 0xa7, 0x50
                .byte 0x7e, 0x41, 0x65, 0x53, 0x7e, 0x41, 0x65, 0x53
                .byte 0x1a, 0x17, 0xa4, 0xc3, 0x3a, 0x27, 0x5e, 0x96
                .byte 0x3b, 0xab, 0x6b, 0xcb, 0x1f, 0x9d, 0x45, 0xf1
                .byte 0xac, 0xfa, 0x58, 0xab, 0x4b, 0xe3, 0x03, 0x93
                .byte 0x20, 0x30, 0xfa, 0x55, 0xad, 0x76, 0x6d, 0xf6
                .byte 0x88, 0xcc, 0x76, 0x91, 0xf5, 0x02, 0x4c, 0x25
                .byte 0x4f, 0xe5, 0xd7, 0xfc, 0xc5, 0x2a, 0xcb, 0xd7
                .byte 0x26, 0x35, 0x44, 0x80, 0x62, 0xa3, 0x8f, 0xb5
                .byte 0x49, 0xde, 0xb1, 0x5a, 0xba, 0x1b, 0x67, 0x25
                .byte 0xea, 0x0e, 0x98, 0x45, 0x5d, 0xfe, 0xc0, 0xe1
                .byte 0xc3, 0x2f, 0x75, 0x02, 0x81, 0x4c, 0xf0, 0x12
                .byte 0x8d, 0x46, 0x97, 0xa3, 0x6b, 0xd3, 0xf9, 0xc6

            .globl after_moved_fixed_pool
            .type after_moved_fixed_pool, @function
            after_moved_fixed_pool:
                xorl %eax, %eax
                retq
            .size after_moved_fixed_pool, . - after_moved_fixed_pool

            .data
            .p2align 3
                .quad .Lmoved_fixed_pool + 1
            .text
            """
        )

        definition = next(
            module.symbols_named(".moved_fixed_definition")
        ).referent.address
        loads = {
            next(module.symbols_named(f".moved_fixed_read{i}")).referent.address
            for i in range(4)
        }
        uses = list(
            snippets.parse_souffle_output(
                module, "metadata_function_reachable_fixed_data_use"
            )
            or []
        )
        self.assertEqual(
            {
                load_ea
                for def_ea, _, load_ea, _, _ in uses
                if def_ea == definition and load_ea in loads
            },
            loads,
        )

        after = next(
            module.symbols_named("after_moved_fixed_pool")
        ).referent.address
        pool_address = after - 104
        self.assertEqual(
            [
                block
                for block in module.code_blocks
                if pool_address <= block.address < after
            ],
            [],
        )

    @unittest.skipUnless(
        platform.system() == "Linux", "This test is linux only."
    )
    def test_x86_moved_fixed_base_redefinition_blocks_data_use(self):
        """A redefined selected base cannot identify a later pool read."""
        module = snippets.asm_to_gtirb(
            """
            .globl read_redefined_moved_pool
            .type read_redefined_moved_pool, @function
            read_redefined_moved_pool:
            .cfi_startproc
                pushq %r14
            .redefined_moved_definition:
                leaq .Lredefined_moved_pool(%rip), %r10
                testl %esi, %esi
                cmove %r10, %r14
                movq %rdi, %r14
            .redefined_moved_read0:
                addq 0(%r14), %rax
            .redefined_moved_read1:
                xorq 32(%r14), %rax
                popq %r14
                retq
            .cfi_endproc
            .size read_redefined_moved_pool, . - read_redefined_moved_pool

            .p2align 4
            .Lredefined_moved_pool:
                .rept 8
                .quad 0x71374491428a2f98
                .endr

            .globl after_redefined_moved_pool
            .type after_redefined_moved_pool, @function
            after_redefined_moved_pool:
                xorl %eax, %eax
                retq
            .size after_redefined_moved_pool, . - after_redefined_moved_pool
            """
        )

        definition = next(
            module.symbols_named(".redefined_moved_definition")
        ).referent.address
        loads = {
            next(module.symbols_named(f".redefined_moved_read{i}")).referent.address
            for i in range(2)
        }
        uses = list(
            snippets.parse_souffle_output(
                module, "metadata_function_reachable_fixed_data_use"
            )
            or []
        )
        self.assertFalse(
            any(
                def_ea == definition and load_ea in loads
                for def_ea, _, load_ea, _, _ in uses
            )
        )

    @unittest.skipUnless(
        platform.system() == "Linux", "This test is linux only."
    )
    def test_x86_referenced_zero_size_object_extent(self):
        """A referenced zero-sized OBJECT is data through the next symbol."""
        module = snippets.asm_to_gtirb(
            """
            leaq K256(%rip), %rax
            movdqu (%rax), %xmm0
            jmp after_table
            .align 16
            .type K256, @object
            K256:
                .long 0x428a2f98, 0x71374491
                .long 0xb5c0fbcf, 0xe9b5dba5
                .long 0x428a2f98, 0x71374491
                .long 0xb5c0fbcf, 0xe9b5dba5
                .long 0x3956c25b, 0x59f111f1
                .long 0x923f82a4, 0xab1c5ed5
                .long 0xd807aa98, 0x12835b01
                .long 0x243185be, 0x550c7dc3
            .type after_table, @function
            after_table:
                xorl %eax, %eax
            """
        )

        table = next(module.symbols_named("K256")).referent
        after = next(module.symbols_named("after_table")).referent
        self.assertIsInstance(table, gtirb.DataBlock)
        self.assertEqual(table.address + table.size, after.address)

        code_in_table = [
            block
            for block in module.code_blocks
            if table.address <= block.address < after.address
        ]
        self.assertEqual(code_in_table, [])

    @unittest.skipUnless(
        platform.system() == "Linux", "This test is linux only."
    )
    def test_x86_interior_referenced_zero_size_object_extent(self):
        """An interior reference protects its zero-sized OBJECT extent."""
        module = snippets.asm_to_gtirb(
            """
            leaq K256+16(%rip), %rax
            movdqu (%rax), %xmm0
            jmp after_table
            .align 16
            .type K256, @object
            K256:
                .long 0x428a2f98, 0x71374491
                .long 0xb5c0fbcf, 0xe9b5dba5
                .long 0x428a2f98, 0x71374491
                .long 0xb5c0fbcf, 0xe9b5dba5
                .long 0x3956c25b, 0x59f111f1
                .long 0x923f82a4, 0xab1c5ed5
                .long 0xd807aa98, 0x12835b01
                .long 0x243185be, 0x550c7dc3
            .type after_table, @function
            after_table:
                xorl %eax, %eax
            """
        )

        table = next(module.symbols_named("K256")).referent
        after = next(module.symbols_named("after_table")).referent
        self.assertIsInstance(table, gtirb.DataBlock)

        # The interior reference may split the protected extent into adjacent
        # DataBlocks.  Require complete, gap-free data coverage rather than a
        # particular block partition.
        data_in_table = sorted(
            (
                block
                for block in module.data_blocks
                if table.address <= block.address < after.address
            ),
            key=lambda block: block.address,
        )
        cursor = table.address
        for block in data_in_table:
            self.assertEqual(block.address, cursor)
            cursor += block.size
            self.assertLessEqual(cursor, after.address)
        self.assertEqual(cursor, after.address)

        code_in_table = [
            block
            for block in module.code_blocks
            if table.address <= block.address < after.address
        ]
        self.assertEqual(code_in_table, [])

    @unittest.skipUnless(
        platform.system() == "Linux", "This test is linux only."
    )
    def test_x86_zero_size_object_function_alias_remains_code(self):
        """A zero-sized OBJECT alias at a function entry stays code."""
        module = snippets.asm_to_gtirb(
            """
            leaq ZERO_OBJECT(%rip), %rax
            jmp after_alias
            .type ZERO_OBJECT, @object
            .size ZERO_OBJECT, 0
            ZERO_OBJECT:
            .type alias_function, @function
            alias_function:
                xorl %eax, %eax
                retq
            after_alias:
                xorl %eax, %eax
            """
        )

        zero_object = next(module.symbols_named("ZERO_OBJECT")).referent
        alias_function = next(module.symbols_named("alias_function")).referent
        self.assertIsInstance(alias_function, gtirb.CodeBlock)
        self.assertIs(zero_object, alias_function)
        self.assertGreater(alias_function.size, 0)

    @unittest.skipUnless(
        platform.system() == "Linux", "This test is linux only."
    )
    def test_x86_zero_size_object_fde_entry_remains_code(self):
        """A zero-sized OBJECT alias at an FDE-only entry stays code."""
        module = snippets.asm_to_gtirb(
            """
            leaq ZERO_OBJECT(%rip), %rax
            movq (%rax), %rax
            jmp after_alias

            .p2align 4
            .type ZERO_OBJECT, @object
            .size ZERO_OBJECT, 0
            ZERO_OBJECT:
            .cfi_startproc
                xorl %eax, %eax
                retq
            .cfi_endproc

            .globl after_alias
            .type after_alias, @function
            after_alias:
                xorl %eax, %eax
            """
        )

        zero_object = next(module.symbols_named("ZERO_OBJECT")).referent
        after_alias = next(module.symbols_named("after_alias")).referent
        self.assertIsInstance(zero_object, gtirb.CodeBlock)

        code = [
            block
            for block in module.code_blocks
            if block.address < after_alias.address
            and block.address + block.size > zero_object.address
        ]
        data = [
            block
            for block in module.data_blocks
            if block.address < after_alias.address
            and block.address + block.size > zero_object.address
        ]
        self.assertNotEqual(code, [])
        self.assertEqual(data, [])

    @unittest.skipUnless(
        platform.system() == "Linux", "This test is linux only."
    )
    def test_x86_post_function_notype_fixed_load_pool_is_data(self):
        """A fixed-load pool reached through an interior base stays data."""
        module = snippets.asm_to_gtirb(
            """
            .globl read_fixed_pool
            .type read_fixed_pool, @function
            read_fixed_pool:
                pushq %rbp
                leaq fixed_pool+16(%rip), %rbp
                # The second byte of this real instruction also decodes as a
                # stand-alone `leave`, which would appear to redefine %rbp if
                # overlapping non-candidate decodes were treated as code.
                testl %ecx, %ecx
                jmp .Lread_pool
            .Lread_pool:
                movdqu -16(%rbp), %xmm0
                movdqu 0(%rbp), %xmm1
                popq %rbp
                retq
            .size read_fixed_pool, . - read_fixed_pool

            .align 16
            .globl fixed_pool
            fixed_pool:
                .byte 0x98, 0x2f, 0x8a, 0x42
                .byte 0x91, 0x44, 0x37, 0x71
                .byte 0xcf, 0xfb, 0xc0, 0xb5
                .byte 0xa5, 0xdb, 0xb5, 0xe9
                .byte 0x85, 0x0a, 0xb7, 0x27
                .byte 0x38, 0x21, 0x48, 0x8d
                .byte 0x06, 0x1b, 0x2e, 0xfc
                .byte 0x6d, 0x2c, 0x4d, 0xc3

            .globl after_fixed_pool
            .type after_fixed_pool, @function
            after_fixed_pool:
                xorl %eax, %eax
                retq
            .size after_fixed_pool, . - after_fixed_pool
            """
        )

        pool_symbol = next(module.symbols_named("fixed_pool"))
        after_symbol = next(module.symbols_named("after_fixed_pool"))
        pool = pool_symbol.referent
        after = after_symbol.referent

        self.assertIsInstance(pool, gtirb.DataBlock)
        self.assertEqual(after.address - pool.address, 32)

        # Each independently referenced address may start its own DataBlock.
        # What matters is that the whole pool is covered by data without gaps,
        # not whether the serializer represents it as one block or several.
        data_in_pool = sorted(
            (
                block
                for block in module.data_blocks
                if pool.address <= block.address < after.address
            ),
            key=lambda block: block.address,
        )
        cursor = pool.address
        for block in data_in_pool:
            self.assertEqual(block.address, cursor)
            cursor += block.size
            self.assertLessEqual(cursor, after.address)
        self.assertEqual(cursor, after.address)
        self.assertEqual(sum(block.size for block in data_in_pool), 32)
        self.assertEqual(
            [
                block
                for block in module.code_blocks
                if pool.address <= block.address < after.address
            ],
            [],
        )

    @unittest.skipUnless(
        platform.system() == "Linux", "This test is linux only."
    )
    def test_x86_post_function_anonymous_fixed_load_pool_is_data(self):
        """A symbol-free fixed-load pool after its reader stays data."""
        module = snippets.asm_to_gtirb(
            """
            .globl read_anonymous_fixed_pool
            .type read_anonymous_fixed_pool, @function
            read_anonymous_fixed_pool:
                pushq %rbp
                pushq %r14
                leaq .Lanonymous_fixed_pool(%rip), %r14
                leaq .Lanonymous_indexed_pool(%rip), %rbp
                movl 0(%r14), %eax
                movl 4(%r14), %ecx
                andl $255, %edi
                movl 0(%rbp,%rdi,8), %r9d
                movl 2052(%rbp,%rdi,8), %r10d
                testl %esi, %esi
                je .Llate_fixed_loads
                nop
            .Llate_fixed_loads:
                movl 40(%r14), %edx
                movl 44(%r14), %esi
                movl 48(%r14), %edi
                movl 52(%r14), %r8d
                popq %r14
                popq %rbp
                retq
            .size read_anonymous_fixed_pool, . - read_anonymous_fixed_pool

            .align 16
            .Lanonymous_fixed_pool:
                .byte 0x8b, 0x90, 0xcc, 0x3b, 0x7f, 0x66, 0x9e, 0xa0
                .byte 0xb2, 0x73, 0xaa, 0x4c, 0x58, 0xe8, 0x7a, 0xb6
                .byte 0xbe, 0x82, 0x4f, 0xe9, 0x2f, 0x37, 0xef, 0xc6
                .byte 0x1c, 0x6f, 0xd3, 0xf1, 0xa5, 0x53, 0xff, 0x54
                .byte 0x1d, 0x2d, 0x68, 0xde, 0xfa, 0x27, 0xe5, 0x10
                # These final bytes are scalar constants even though they can
                # be decoded independently as a return-ending instruction
                # sequence.
                .byte 0xfd, 0xc1, 0xe6, 0xb3, 0xc2, 0x88, 0x56, 0xb0

                .zero 16
            .Lanonymous_indexed_pool:
                # A separate indexed table follows the fixed constants, as is
                # common in hand-written routines that share several lookup
                # layouts.  It deliberately has no input symbol either.
                .rept 256
                .byte 0x00, 0x70, 0x70, 0x70, 0x70, 0x00, 0x70, 0x70
                .byte 0x00, 0x82, 0x82, 0x82, 0x2c, 0x00, 0x2c, 0x2c
                .endr

            .globl after_anonymous_fixed_pool
            .type after_anonymous_fixed_pool, @function
            after_anonymous_fixed_pool:
                xorl %eax, %eax
                retq
            .size after_anonymous_fixed_pool, . - after_anonymous_fixed_pool

            # An address-shaped scalar elsewhere makes the constant bytes a
            # plausible standalone code target.  The accessed-pool evidence
            # must outweigh that coincidental decode.
            .data
            .align 8
                .quad .Lanonymous_fixed_pool + 40
            .text
            """
        )

        marker = bytes.fromhex(
            "8b90cc3b7f669ea0b273aa4c58e87ab6"
            "be824fe92f37efc61c6fd3f1a553ff54"
            "1d2d68defa27e510fdc1e6b3c28856b0"
        )
        matches = []
        for section in module.sections:
            for interval in section.byte_intervals:
                if interval.address is None:
                    continue
                offset = bytes(interval.contents).find(marker)
                if offset >= 0:
                    matches.append(interval.address + offset)

        self.assertEqual(len(matches), 1)
        pool_address = matches[0]
        pool_end = pool_address + len(marker)
        self.assertEqual(
            [
                block
                for block in module.code_blocks
                if block.address < pool_end
                and block.address + block.size > pool_address
            ],
            [],
        )

        data_in_pool = sorted(
            (
                max(block.address, pool_address),
                min(block.address + block.size, pool_end),
            )
            for block in module.data_blocks
            if block.address < pool_end
            and block.address + block.size > pool_address
        )
        covered_until = pool_address
        for start, end in data_in_pool:
            self.assertLessEqual(start, covered_until)
            covered_until = max(covered_until, end)
        self.assertEqual(covered_until, pool_end)

    @unittest.skipUnless(
        platform.system() == "Linux", "This test is linux only."
    )
    def test_x86_post_function_anonymous_interior_fixed_base_is_data(self):
        """Negative fixed loads extend an anonymous pool below its base."""
        module = snippets.asm_to_gtirb(
            """
            .globl read_anonymous_interior_fixed_pool
            .type read_anonymous_interior_fixed_pool, @function
            read_anonymous_interior_fixed_pool:
                pushq %r14
                leaq .Lanonymous_interior_fixed_pool+32(%rip), %r14
                testl %edi, %edi
                jne .Lread_anonymous_interior_fixed_pool
                nop
            .Lread_anonymous_interior_fixed_pool:
                movl -32(%r14), %eax
                movl -28(%r14), %ecx
                movl 0(%r14), %edx
                movl 4(%r14), %esi
                popq %r14
                retq
            .size read_anonymous_interior_fixed_pool, \
                . - read_anonymous_interior_fixed_pool

            .p2align 8
            .Lanonymous_interior_fixed_pool:
                .byte 0x99, 0x79, 0x82, 0x5a
                .byte 0x99, 0x79, 0x82, 0x5a
                .byte 0x99, 0x79, 0x82, 0x5a
                .byte 0x99, 0x79, 0x82, 0x5a
                .byte 0x99, 0x79, 0x82, 0x5a
                .byte 0x99, 0x79, 0x82, 0x5a
                .byte 0x99, 0x79, 0x82, 0x5a
                .byte 0x99, 0x79, 0x82, 0x5a
                .byte 0xa1, 0xeb, 0xd9, 0x6e
                .byte 0xa1, 0xeb, 0xd9, 0x6e

            .globl after_anonymous_interior_fixed_pool
            .type after_anonymous_interior_fixed_pool, @function
            after_anonymous_interior_fixed_pool:
                xorl %eax, %eax
                retq
            .size after_anonymous_interior_fixed_pool, \
                . - after_anonymous_interior_fixed_pool

            .data
            .align 8
                .quad .Lanonymous_interior_fixed_pool + 1
            .text
            """
        )

        marker = bytes.fromhex(
            "9979825a9979825a9979825a9979825a"
            "9979825a9979825a9979825a9979825a"
        )
        matches = []
        for section in module.sections:
            for interval in section.byte_intervals:
                if interval.address is None:
                    continue
                offset = bytes(interval.contents).find(marker)
                if offset >= 0:
                    matches.append(interval.address + offset)

        self.assertEqual(len(matches), 1)
        pool_address = matches[0]
        pool_end = pool_address + len(marker)
        self.assertEqual(
            [
                block
                for block in module.code_blocks
                if block.address < pool_end
                and block.address + block.size > pool_address
            ],
            [],
        )

        data_in_pool = sorted(
            (
                max(block.address, pool_address),
                min(block.address + block.size, pool_end),
            )
            for block in module.data_blocks
            if block.address < pool_end
            and block.address + block.size > pool_address
        )
        covered_until = pool_address
        for start, end in data_in_pool:
            self.assertLessEqual(start, covered_until)
            covered_until = max(covered_until, end)
        self.assertEqual(covered_until, pool_end)

    @unittest.skipUnless(
        platform.system() == "Linux", "This test is linux only."
    )
    def test_x86_post_function_notype_redefined_base_not_data_extent(self):
        """A real base-register redefinition prevents pool inference."""
        module = snippets.asm_to_gtirb(
            """
            .globl read_redefined_pool
            .type read_redefined_pool, @function
            read_redefined_pool:
                pushq %rbp
                leaq redefined_pool+16(%rip), %rbp
                movq %rax, %rbp
                testl %ecx, %ecx
                jmp .Lread_redefined_pool
            .Lread_redefined_pool:
                movdqu -16(%rbp), %xmm0
                movdqu 0(%rbp), %xmm1
                popq %rbp
                retq
            .size read_redefined_pool, . - read_redefined_pool

            .align 16
            .globl redefined_pool
            redefined_pool:
                .byte 0x98, 0x2f, 0x8a, 0x42
                .byte 0x91, 0x44, 0x37, 0x71
                .byte 0xcf, 0xfb, 0xc0, 0xb5
                .byte 0xa5, 0xdb, 0xb5, 0xe9
                .byte 0x85, 0x0a, 0xb7, 0x27
                .byte 0x38, 0x21, 0x48, 0x8d
                .byte 0x06, 0x1b, 0x2e, 0xfc
                .byte 0x6d, 0x2c, 0x4d, 0xc3

            .globl after_redefined_pool
            .type after_redefined_pool, @function
            after_redefined_pool:
                xorl %eax, %eax
                retq
            .size after_redefined_pool, . - after_redefined_pool
            """
        )

        pool = next(module.symbols_named("redefined_pool")).referent
        after = next(module.symbols_named("after_redefined_pool")).referent
        self.assertEqual(after.address - pool.address, 32)
        self.assertNotEqual(
            [
                block
                for block in module.code_blocks
                if pool.address <= block.address < after.address
            ],
            [],
        )

    @unittest.skipUnless(
        platform.system() == "Linux", "This test is linux only."
    )
    def test_x86_post_function_indexed_redefined_base_not_data_use(self):
        """A redefined PC-relative base cannot identify an indexed pool."""
        module = snippets.asm_to_gtirb(
            """
            .globl indexed_reader
            .type indexed_reader, @function
            indexed_reader:
            .cfi_startproc
                leaq .Lindexed_pool(%rip), %rbp
                movq %rax, %rbp
                testl %esi, %esi
                jne .Lloads
                nop
            .Lloads:
            .load1:
                movl 0(%rbp,%rdi,8), %ecx
            .load2:
                movl 4(%rbp,%rdi,8), %edx
                retq
            .cfi_endproc
            .size indexed_reader, . - indexed_reader

            .p2align 4
            .Lindexed_pool:
                .rept 8
                .long 0x12345678, 0x23456789
                .endr

            .globl after_indexed_pool
            .type after_indexed_pool, @function
            after_indexed_pool:
                xorl %eax, %eax
            """
        )

        definition = next(
            module.symbols_named("indexed_reader")
        ).referent.address
        load1 = next(module.symbols_named(".load1")).referent.address
        load2 = next(module.symbols_named(".load2")).referent.address
        redefinitions = list(
            snippets.parse_souffle_output(
                module, "register_redefined_between"
            )
            or []
        )
        indexed_uses = list(
            snippets.parse_souffle_output(
                module, "pc_relative_indexed_data_use"
            )
            or []
        )
        self.assertFalse(
            any(
                def_ea == definition and load_ea in (load1, load2)
                for def_ea, _, load_ea in indexed_uses
            ),
            "indexed-table evidence survived a base-register redefinition",
        )
        self.assertIn((definition, load1, "RBP"), redefinitions)
        self.assertIn((definition, load2, "RBP"), redefinitions)

    @unittest.skipUnless(
        platform.system() == "Linux", "This test is linux only."
    )
    def test_x86_composite(self):
        module = snippets.asm_to_gtirb(
            """
            .ref:
            leaq .data0(%rip), %rax
            .load:
            mov (.data1 - .data0)(%rax), %eax
            jmp .end
            .data0:
                .long 0
            .data1:
                .long 0
            .end:
            """
        )
        accesses = snippets.parse_souffle_output(
            module, "composite_data_access"
        )
        self.assertIn(
            (
                next(module.symbols_named(".ref")).referent.address,
                next(module.symbols_named(".load")).referent.address,
                next(module.symbols_named(".data1")).referent.address,
                4,
            ),
            accesses,
        )

    @unittest.skipUnless(
        platform.system() == "Linux", "This test is linux only."
    )
    def test_arm_simple(self):
        module = snippets.asm_to_gtirb(
            """
            .access:
            ldr r0, .data0
            .data0:
                .long 0
            .end:
            """,
            arch=gtirb.Module.ISA.ARM,
        )

        accesses = snippets.parse_souffle_output(
            module, "arch.simple_data_load"
        )
        self.assertIn(
            (
                next(module.symbols_named(".access")).referent.address,
                next(module.symbols_named(".data0")).referent.address,
                4,
            ),
            accesses,
        )

    @unittest.skipUnless(
        platform.system() == "Linux", "This test is linux only."
    )
    def test_arm_composite_ldr(self):
        module = snippets.asm_to_gtirb(
            """
            .ref:
            adr r0, .data0
            .load:
            ldr r0, [r0, #.data1-.data0]
            .data0:
                .long 0
            .data1:
                .long 0
            .end:
            """,
            arch=gtirb.Module.ISA.ARM,
        )

        accesses = snippets.parse_souffle_output(
            module, "composite_data_access"
        )
        self.assertIn(
            (
                next(module.symbols_named(".ref")).referent.address,
                next(module.symbols_named(".load")).referent.address,
                next(module.symbols_named(".data1")).referent.address,
                4,
            ),
            accesses,
        )

    @unittest.skipUnless(
        platform.system() == "Linux", "This test is linux only."
    )
    def test_arm_composite_ldm(self):
        module = snippets.asm_to_gtirb(
            """
            .ref:
            adr r0, .data0
            .load:
            ldm r0, {r0, r1, r2}
            .data0:
                .long 0
                .long 1
                .long 2
            .end:
            """,
            arch=gtirb.Module.ISA.ARM,
        )

        accesses = snippets.parse_souffle_output(
            module, "composite_data_access"
        )
        self.assertIn(
            (
                next(module.symbols_named(".ref")).referent.address,
                next(module.symbols_named(".load")).referent.address,
                next(module.symbols_named(".data0")).referent.address,
                12,
            ),
            accesses,
        )

    @unittest.skipUnless(
        platform.system() == "Linux", "This test is linux only."
    )
    def test_arm_composite_vld(self):
        module = snippets.asm_to_gtirb(
            """
            .ref:
            adr r0, .data0
            .load:
            vld1.8 {d0}, [r0]
            b .end
            .data0:
                .byte 0
            .align 2
            .end:
            """,
            arch=gtirb.Module.ISA.ARM,
        )

        accesses = snippets.parse_souffle_output(
            module, "composite_data_access"
        )
        self.assertIn(
            (
                next(module.symbols_named(".ref")).referent.address,
                next(module.symbols_named(".load")).referent.address,
                next(module.symbols_named(".data0")).referent.address,
                8,
            ),
            accesses,
        )
