import platform
import shutil
import unittest
from disassemble_reassemble_check import compile, cd, disassemble
from pathlib import Path
import gtirb


ex_asm_dir = Path("./examples/") / "asm_examples"
ex_arm64_asm_dir = Path("./examples/") / "arm64_asm_examples"
ex_riscv_asm_dir = Path("./examples/") / "riscv_asm_examples"


class SymbolicOperandsTests(unittest.TestCase):
    @unittest.skipUnless(
        platform.system() == "Linux"
        and shutil.which("aarch64-linux-gnu-gcc"),
        "This test requires the AArch64 cross toolchain.",
    )
    def test_aarch64_ldp_x_register_uses_pointer_width(self):
        """An LDP into X registers reports an eight-byte element width."""
        binary = Path("ex")
        with cd(ex_arm64_asm_dir / "ex_ldp_pointer_width"):
            self.assertTrue(
                compile(
                    "aarch64-linux-gnu-gcc",
                    "aarch64-linux-gnu-g++",
                    "",
                    [],
                )
            )
            module = disassemble(
                binary, extra_args=["--with-souffle-relations"]
            ).ir().modules[0]

        marker = (0x820030).to_bytes(8, "little") + (5).to_bytes(
            8, "little"
        )
        source_addresses = []
        for section in module.sections:
            for interval in section.byte_intervals:
                if interval.address is None:
                    continue
                offset = bytes(interval.contents).find(marker)
                if offset >= 0:
                    source_addresses.append(interval.address + offset)
        self.assertEqual(len(source_addresses), 1)
        source_address = source_addresses[0]

        preferred_accesses = module.aux_data["souffleOutputs"].data[
            "disassembly.preferred_data_access"
        ][1].splitlines()
        source_access_sizes = {
            int(row.split("\t")[1], 0)
            for row in preferred_accesses
            if int(row.split("\t")[0], 0) == source_address
        }
        self.assertEqual(source_access_sizes, {8})

        source_interval = next(
            interval
            for section in module.sections
            for interval in section.byte_intervals
            if interval.address is not None
            and interval.address <= source_address
            and source_address + 8 <= interval.address + interval.size
        )
        expressions = list(
            source_interval.symbolic_expressions_at(
                range(source_address, source_address + 8)
            )
        )
        self.assertEqual(len(expressions), 1)
        expression = expressions[0][2]
        self.assertIsInstance(expression, gtirb.SymAddrConst)
        self.assertEqual(expression.symbol.name, "pointer_target")

    @unittest.skipUnless(
        platform.system() == "Linux"
        and shutil.which("aarch64-linux-gnu-gcc"),
        "This test requires the AArch64 cross toolchain.",
    )
    def test_aarch64_dense_u32_object_is_not_a_pointer_window(self):
        """Keep adjacent uint32 table cells numeric on AArch64."""
        binary = Path("ex")
        with cd(
            ex_arm64_asm_dir / "ex_dense_u32_object_pointer_collision"
        ):
            self.assertTrue(
                compile(
                    "aarch64-linux-gnu-gcc",
                    "aarch64-linux-gnu-g++",
                    "",
                    [],
                )
            )
            module = disassemble(binary).ir().modules[0]

        scalar_table = next(
            module.symbols_named("dense_u32_table")
        ).referent
        self.assertIsInstance(scalar_table, gtirb.DataBlock)
        for offset in (0x378, 0x7e8):
            scalar_expressions = list(
                scalar_table.byte_interval.symbolic_expressions_at(
                    range(
                        scalar_table.address + offset,
                        scalar_table.address + offset + 8,
                    )
                )
            )
            self.assertEqual(scalar_expressions, [])

        # The destination at 0x820080 is also the start of an inferred,
        # unlabeled interior string.  Destination plausibility must not turn
        # the scalar table cell into a pointer.
        target_symbol = next(
            module.symbols_named("collision_target_object")
        )
        target_region = target_symbol.referent
        self.assertIsInstance(target_region, gtirb.DataBlock)
        self.assertEqual(
            module.aux_data["elfSymbolInfo"].data[target_symbol][0],
            0x40,
        )
        self.assertTrue(
            any(
                candidate.address == 0x820080
                for candidate in target_region.byte_interval.blocks
                if isinstance(candidate, gtirb.DataBlock)
            )
        )

        # The later, genuinely pointer-valued records must remain symbolic.
        # They are deliberately anonymous at the source so their sequence can
        # exercise the object-end boundary above without a label masking it.
        for offset, target_offset in (
            (0x868, 0),
            (0x8e8, 8),
            (0x968, 16),
        ):
            expressions = list(
                scalar_table.byte_interval.symbolic_expressions_at(
                    range(
                        scalar_table.address + offset,
                        scalar_table.address + offset + 8,
                    )
                )
            )
            self.assertEqual(len(expressions), 1)
            expression = expressions[0][2]
            self.assertIsInstance(expression, gtirb.SymAddrConst)
            self.assertEqual(
                expression.symbol.referent.address + expression.offset,
                0x820000 + target_offset,
            )

        pointer_table = next(
            module.symbols_named("dense_pointer_table")
        ).referent
        self.assertIsInstance(pointer_table, gtirb.DataBlock)
        pointer_expressions = list(
            pointer_table.byte_interval.symbolic_expressions_at(
                range(pointer_table.address, pointer_table.address + 8)
            )
        )
        self.assertEqual(len(pointer_expressions), 1)
        expression = pointer_expressions[0][2]
        self.assertIsInstance(expression, gtirb.SymAddrConst)
        self.assertEqual(
            expression.symbol.referent.address + expression.offset,
            0x820080,
        )

    @unittest.skipUnless(
        platform.system() == "Linux"
        and shutil.which("aarch64-linux-gnu-gcc"),
        "This test requires the AArch64 cross toolchain.",
    )
    def test_completed_page_address_spill_is_not_a_second_split_load(self):
        """Do not attach LO12 twice across a completed-pointer spill."""
        binary = Path("ex")
        with cd(ex_arm64_asm_dir / "ex_completed_split_load_spill"):
            self.assertTrue(
                compile(
                    "aarch64-linux-gnu-gcc",
                    "aarch64-linux-gnu-g++",
                    "",
                    [],
                )
            )
            module = disassemble(binary).ir().modules[0]

        main = next(module.symbols_named("main")).referent
        completed_pointer = next(module.symbols_named("completed_pointer"))
        stack_split_target = next(module.symbols_named("stack_split_target"))
        self.assertIsInstance(main, gtirb.CodeBlock)

        def expressions_at(instruction_offset):
            return list(
                main.byte_interval.symbolic_expressions_at(
                    range(
                        main.address + instruction_offset,
                        main.address + instruction_offset + 4,
                    )
                )
            )

        def resolved_address(expression):
            self.assertIsInstance(expression, gtirb.SymAddrConst)
            symbol = expression.symbol
            base = (
                symbol.referent.address
                if symbol.referent is not None
                else symbol.value
            )
            return base + expression.offset

        def symbol_address(symbol):
            return (
                symbol.referent.address
                if symbol.referent is not None
                else symbol.value
            )

        # The first ADRP/ADD pair genuinely materializes completed_pointer.
        for offset in (4, 8):
            expressions = expressions_at(offset)
            self.assertEqual(len(expressions), 1)
            self.assertEqual(
                resolved_address(expressions[0][2]),
                symbol_address(completed_pointer),
            )

        # These operate on the already completed pointer after a stack reload.
        self.assertEqual(expressions_at(20), [])
        self.assertEqual(expressions_at(24), [])

        # The positive control deliberately spills the ADRP page before ADD.
        for offset in (28, 40):
            expressions = expressions_at(offset)
            self.assertEqual(len(expressions), 1)
            self.assertEqual(
                resolved_address(expressions[0][2]),
                symbol_address(stack_split_target),
            )

    @unittest.skipUnless(
        platform.system() == "Linux"
        and shutil.which("aarch64-linux-gnu-gcc"),
        "This test requires the AArch64 cross toolchain.",
    )
    def test_adr_page_aligned_base_keeps_exact_target(self):
        """Keep an ADR base exact when a later instruction adds a field offset."""
        binary = Path("ex")
        with cd(ex_arm64_asm_dir / "ex_adr_not_split_load"):
            self.assertTrue(
                compile(
                    "aarch64-linux-gnu-gcc",
                    "aarch64-linux-gnu-g++",
                    "",
                    [],
                )
            )
            module = disassemble(binary).ir().modules[0]

        main = next(module.symbols_named("main")).referent
        page_struct = next(module.symbols_named("page_struct")).referent
        page_message = next(module.symbols_named("page_message"))
        self.assertIsInstance(main, gtirb.CodeBlock)
        self.assertIsInstance(page_struct, gtirb.DataBlock)
        self.assertEqual(page_struct.address % 4096, 0)

        def expression_at(instruction_offset):
            expressions = list(
                main.byte_interval.symbolic_expressions_at(
                    range(
                        main.address + instruction_offset,
                        main.address + instruction_offset + 4,
                    )
                )
            )
            self.assertEqual(len(expressions), 1)
            return expressions[0][2]

        def resolved_address(expression):
            self.assertIsInstance(expression, gtirb.SymAddrConst)
            symbol = expression.symbol
            base = (
                symbol.referent.address
                if symbol.referent is not None
                else symbol.value
            )
            return base + expression.offset

        page_message_address = (
            page_message.referent.address
            if page_message.referent is not None
            else page_message.value
        )

        # The ADR itself names the exact page-aligned base.  Only the ADD
        # names the field sixty-four bytes into the object.
        self.assertEqual(resolved_address(expression_at(16)), page_struct.address)
        self.assertEqual(
            resolved_address(expression_at(20)),
            page_message_address,
        )

    @unittest.skipUnless(
        platform.system() == "Linux"
        and shutil.which("riscv64-linux-gnu-gcc")
        and shutil.which("qemu-riscv64"),
        "This test requires the RV64 cross toolchain and qemu-user.",
    )
    def test_riscv_stack_adjustment_numeric_collision(self):
        """Keep an address-shaped RV64 stack adjustment literal."""
        binary = Path("ex")
        with cd(ex_riscv_asm_dir / "ex_stack_adjustment_collision"):
            self.assertTrue(
                compile(
                    "riscv64-linux-gnu-gcc",
                    "riscv64-linux-gnu-g++",
                    "-O0",
                    [],
                    exec_wrapper=(
                        "qemu-riscv64 -R 0x4000000000 "
                        "-L /usr/riscv64-linux-gnu"
                    ),
                )
            )
            module = disassemble(binary).ir().modules[0]

        def expressions_for(symbol_name, size=8):
            block = next(module.symbols_named(symbol_name)).referent
            self.assertIsInstance(block, gtirb.CodeBlock)
            return list(
                block.byte_interval.symbolic_expressions_at(
                    range(block.address, block.address + size)
                )
            )

        # The completed value updates SP.  Even though 0x70040 is an exact
        # function address, both instruction immediates are scalar frame-size
        # arithmetic and must remain raw.
        self.assertEqual(
            expressions_for("rv_stack_adjustment_collision"), []
        )

        # The same LUI/ADDI value is a real address when it feeds a memory
        # base, so the new stack-specific evidence must not suppress it.
        target = next(module.symbols_named("rv_exact_collision_target"))
        self.assertIsInstance(target.referent, gtirb.CodeBlock)
        self.assertEqual(target.referent.address, 0x70040)
        address_expressions = expressions_for("rv_address_positive_control")
        self.assertEqual(len(address_expressions), 2)
        for _, _, expression in address_expressions:
            self.assertIsInstance(expression, gtirb.SymAddrConst)
            self.assertEqual(
                expression.symbol.referent.address + expression.offset,
                target.referent.address,
            )

        # Exact symbol identity does not override the completed value's direct
        # use as a scalar multiplier.  Binding this numeric constant to the
        # unrelated function would silently change it after code relayout.
        self.assertEqual(
            expressions_for("rv_exact_symbol_multiplier_collision"), []
        )

        # A neutral-score LUI/ADDI value that merely lands on an unlabeled
        # instruction interior is still a scalar, even when subsequently used
        # by arithmetic.  Relayout must not bind it to an inferred code label.
        self.assertEqual(
            expressions_for("rv_unlabeled_scalar_collision"), []
        )

        # The same unlabeled interior value remains recoverable as an address
        # when the completed value is directly dereferenced.
        interior_address_expressions = expressions_for(
            "rv_unlabeled_address_positive_control"
        )
        self.assertEqual(len(interior_address_expressions), 2)
        for _, _, expression in interior_address_expressions:
            self.assertIsInstance(expression, gtirb.SymAddrConst)
            self.assertEqual(
                expression.symbol.referent.address + expression.offset,
                0x70044,
            )

        # Passing or returning an unlabeled data address need not produce a
        # local dereference.  Both halves must still relocate at neutral score.
        data_address_expressions = expressions_for(
            "rv_unlabeled_data_address_return"
        )
        self.assertEqual(len(data_address_expressions), 2)
        for _, _, expression in data_address_expressions:
            self.assertIsInstance(expression, gtirb.SymAddrConst)
            self.assertEqual(
                expression.symbol.referent.address + expression.offset,
                0x71004,
            )

        # An unrelated instruction between LUI and STORE must not break the
        # reaching definition that identifies their shared absolute address.
        interleaved_store_expressions = expressions_for(
            "rv_interleaved_store_positive_control", size=16
        )
        self.assertEqual(len(interleaved_store_expressions), 2)
        interleaved_store_target = next(
            module.symbols_named("rv_interleaved_store_target")
        ).referent
        self.assertIsInstance(interleaved_store_target, gtirb.DataBlock)
        for _, _, expression in interleaved_store_expressions:
            self.assertIsInstance(expression, gtirb.SymAddrConst)
            self.assertEqual(
                expression.symbol.referent.address + expression.offset,
                interleaved_store_target.address,
            )

        # A zero low half makes Capstone render the table-base ADDI as MV.
        # The three 32-bit absolute entries still need symbolic expressions so
        # that a later link rebases their code targets.
        table = next(
            module.symbols_named("rv_absolute_jump_table_zero_lo_table")
        ).referent
        self.assertIsInstance(table, gtirb.DataBlock)
        table_entry_size = 4
        table_entry_count = 3
        table_expressions = [
            (table.byte_interval.address + offset, expression)
            for offset, expression in table.byte_interval.symbolic_expressions.items()
            if table.address
            <= table.byte_interval.address + offset
            < table.address + table_entry_size * table_entry_count
        ]
        self.assertEqual(len(table_expressions), table_entry_count)
        expected_targets = {
            next(module.symbols_named(name)).referent.address
            for name in (
                "rv_absolute_jump_table_case0",
                "rv_absolute_jump_table_case1",
                "rv_absolute_jump_table_case2",
            )
        }
        resolved_targets = {
            address: expression.symbol.referent.address + expression.offset
            for address, expression in table_expressions
            if isinstance(expression, gtirb.SymAddrConst)
        }
        self.assertEqual(
            resolved_targets,
            {
                table.address: next(
                    module.symbols_named("rv_absolute_jump_table_case0")
                ).referent.address,
                table.address + 4: next(
                    module.symbols_named("rv_absolute_jump_table_case1")
                ).referent.address,
                table.address + 8: next(
                    module.symbols_named("rv_absolute_jump_table_case2")
                ).referent.address,
            },
        )
        self.assertEqual(set(resolved_targets.values()), expected_targets)

        # The middle fixed-width string slot spells "MD5".  Those bytes also
        # equal the mapped address 0x35444d on little-endian RV64, but the
        # adjacent padded string slots establish that it must stay literal.
        string_pool = next(
            module.symbols_named("rv_dense_short_string_pool")
        ).referent
        self.assertIsInstance(string_pool, gtirb.DataBlock)
        md5_slot = string_pool.address + 8
        md5_expressions = [
            expression
            for offset, expression in (
                string_pool.byte_interval.symbolic_expressions.items()
            )
            if string_pool.byte_interval.address + offset == md5_slot
        ]
        self.assertEqual(md5_expressions, [])

        # A long name may end in the slot immediately before another padded
        # short name.  The short name is directly referenced by code and has a
        # following fixed-width string neighbor, so its accidental address
        # value must still remain literal.
        referenced_md5 = next(
            module.symbols_named("rv_referenced_short_md5")
        ).referent
        self.assertIsInstance(referenced_md5, gtirb.DataBlock)
        referenced_md5_expressions = [
            expression
            for offset, expression in (
                referenced_md5.byte_interval.symbolic_expressions.items()
            )
            if referenced_md5.byte_interval.address + offset
            == referenced_md5.address
        ]
        self.assertEqual(referenced_md5_expressions, [])

    @unittest.skipUnless(
        platform.system() == "Linux", "This test is linux only."
    )
    def test_exact_exception_symbol_immediate(self):
        """Retain an exact-symbol immediate into an exception section."""
        binary = Path("ex")
        with cd(ex_asm_dir / "ex_misaligned_fde"):
            self.assertTrue(compile("gcc", "g++", "-O0", []))
            module = disassemble(binary).ir().modules[0]

        code_block = next(
            module.symbols_named("exception_symbol_immediate")
        ).referent
        self.assertIsInstance(code_block, gtirb.CodeBlock)
        expressions = list(
            code_block.byte_interval.symbolic_expressions_at(
                range(code_block.address, code_block.address + code_block.size)
            )
        )
        self.assertEqual(len(expressions), 1)
        _, _, expression = expressions[0]
        self.assertIsInstance(expression, gtirb.SymAddrConst)
        exact_target = next(module.symbols_named("exact_fde_start")).referent
        self.assertEqual(
            expression.symbol.referent.address + expression.offset,
            exact_target.address,
        )

    @unittest.skipUnless(
        platform.system() == "Linux", "This test is linux only."
    )
    def test_movz_movk_numeric_collision(self):
        """Keep scalar MOVZ/MOVK values literal across later relayouts."""
        binary = Path("ex")
        with cd(ex_arm64_asm_dir / "ex_movz_movk"):
            self.assertTrue(
                compile(
                    "aarch64-linux-gnu-gcc",
                    "aarch64-linux-gnu-g++",
                    "-O0",
                    [],
                )
            )
            module = disassemble(binary).ir().modules[0]

        def expressions_for(symbol_name, offset=0, size=None):
            block = next(module.symbols_named(symbol_name)).referent
            self.assertIsInstance(block, gtirb.CodeBlock)
            if size is None:
                size = block.size - offset
            return list(
                block.byte_interval.symbolic_expressions_at(
                    range(
                        block.address + offset,
                        block.address + offset + size,
                    )
                )
            )

        # Both 16-bit slices of the numeric 0x700142 materialization must be
        # raw immediates even though that value is inside a data OBJECT and
        # its shifted/masked result is subsequently used as an array index.
        self.assertEqual(
            expressions_for("movz_movk_numeric_collision", offset=8, size=8),
            [],
        )

        # The value 0x700101 is an equally unlabeled interior target, but its
        # value-preserving MOV plus constant ADD and eventual LDRB-base use
        # provide independent address evidence.  Both MOVZ/MOVK slices must
        # therefore remain symbolic.
        address_expressions = expressions_for(
            "movz_movk_interior_address", size=8
        )
        self.assertEqual(len(address_expressions), 2)
        for _, _, expression in address_expressions:
            self.assertIsInstance(expression, gtirb.SymAddrConst)
            self.assertEqual(
                expression.symbol.referent.address + expression.offset,
                0x700101,
            )

        # A MOVZ/MOVK scalar can also collide with an unlabeled instruction.
        # Direct use as a logical mask is scalar evidence, so relayout must not
        # bind either slice to the unrelated code block at 0x710010.
        self.assertEqual(
            expressions_for("movz_movk_code_mask_collision", size=8),
            [],
        )

        # The same unlabeled instruction value remains symbolic when the
        # completed value is directly used as a branch destination.
        code_address_expressions = expressions_for(
            "movz_movk_code_address_control", size=8
        )
        self.assertEqual(len(code_address_expressions), 2)
        for _, _, expression in code_address_expressions:
            self.assertIsInstance(expression, gtirb.SymAddrConst)
            self.assertEqual(
                expression.symbol.referent.address + expression.offset,
                0x710010,
            )

    @unittest.skipUnless(
        platform.system() == "Linux", "This test is linux only."
    )
    def test_printable_exact_data_pointer(self):
        """Retain exact-symbol pointers whose low bytes resemble strings."""
        binary = Path("ex")
        with cd(ex_asm_dir / "ex_printable_exact_data_pointer"):
            self.assertTrue(compile("gcc", "g++", "-O0", []))
            module = disassemble(binary).ir().modules[0]

        for descriptor_name, target_name, expected_prefix in (
            ("generator_19_descriptor", "generator_19_value", b"\x18{o\x00"),
            ("generator_5_descriptor", "generator_5_value", b"8{o\x00"),
            ("generator_2_descriptor", "generator_2_value", b"X{o\x00"),
        ):
            descriptor = next(module.symbols_named(descriptor_name)).referent
            target = next(module.symbols_named(target_name)).referent
            self.assertIsInstance(descriptor, gtirb.DataBlock)
            self.assertIsInstance(target, gtirb.DataBlock)
            self.assertEqual(
                bytes(
                    descriptor.byte_interval.contents[
                        descriptor.offset : descriptor.offset + 4
                    ]
                ),
                expected_prefix,
            )
            expressions = list(
                descriptor.byte_interval.symbolic_expressions_at(
                    range(descriptor.address, descriptor.address + 8)
                )
            )
            self.assertEqual(len(expressions), 1)
            _, _, expression = expressions[0]
            self.assertIsInstance(expression, gtirb.SymAddrConst)
            self.assertEqual(
                expression.symbol.referent.address + expression.offset,
                target.address,
            )

        # A real anonymous short string can coincidentally encode the address
        # of an exact symbol too.  Unlike the labeled descriptor fields above,
        # it has no independent pointer provenance and must stay literal.
        tail_symbol = next(module.symbols_named("name_6"))
        tail_address = (
            tail_symbol.referent.address
            if tail_symbol.referent is not None
            else tail_symbol.value
        )
        anonymous_string_address = tail_address + len(b"1024\0")
        anonymous_target = next(
            module.symbols_named("generator_2_value")
        ).referent
        anonymous_intervals = [
            interval
            for section in module.sections
            for interval in section.byte_intervals
            if interval.address is not None
            and interval.address <= anonymous_string_address
            and anonymous_string_address + 8
            <= interval.address + interval.size
        ]
        self.assertEqual(len(anonymous_intervals), 1)
        anonymous_interval = anonymous_intervals[0]
        anonymous_offset = anonymous_string_address - anonymous_interval.address
        self.assertEqual(
            int.from_bytes(
                anonymous_interval.contents[
                    anonymous_offset : anonymous_offset + 8
                ],
                "little",
            ),
            anonymous_target.address,
        )
        anonymous_expressions = [
            item
            for section in module.sections
            for interval in section.byte_intervals
            if interval.address is not None
            for item in interval.symbolic_expressions_at(
                range(anonymous_string_address, anonymous_string_address + 8)
            )
        ]
        self.assertEqual(anonymous_expressions, [])

        # A named multiword descriptor can instead begin with a pointer to an
        # anonymous string.  Its low bytes also spell short text, but the
        # source OBJECT boundary plus the independently inferred target string
        # establish a real pointer field.
        descriptor_symbol = next(
            module.symbols_named("anonymous_string_descriptor")
        )
        descriptor = descriptor_symbol.referent
        self.assertIsInstance(descriptor, gtirb.DataBlock)
        # A retained expression at the first field may split the original
        # 40-byte OBJECT into multiple GTIRB data blocks.  Check the original
        # ELF symbol size rather than requiring its first referent to span the
        # entire object.
        self.assertEqual(
            module.aux_data["elfSymbolInfo"].data[descriptor_symbol][0],
            40,
        )
        self.assertEqual(
            bytes(
                descriptor.byte_interval.contents[
                    descriptor.offset : descriptor.offset + 4
                ]
            ),
            b"A}o\0",
        )
        descriptor_expressions = list(
            descriptor.byte_interval.symbolic_expressions_at(
                range(descriptor.address, descriptor.address + 8)
            )
        )
        self.assertEqual(len(descriptor_expressions), 1)
        _, _, descriptor_expression = descriptor_expressions[0]
        self.assertIsInstance(descriptor_expression, gtirb.SymAddrConst)
        target_symbol = descriptor_expression.symbol
        target_base = (
            target_symbol.referent.address
            if target_symbol.referent is not None
            else target_symbol.value
        )
        self.assertEqual(
            target_base + descriptor_expression.offset,
            0x6F7D41,
        )

        # A named array of { anonymous string pointer, function pointer }
        # records supplies independent structure for both columns.  The four
        # string addresses deliberately encode printable three-byte prefixes
        # in their source fields; all must remain symbolic so relayout updates
        # them together with their parser-function partners.
        parser_table_symbol = next(
            module.symbols_named("parser_descriptor_table")
        )
        parser_table = parser_table_symbol.referent
        self.assertIsInstance(parser_table, gtirb.DataBlock)
        self.assertEqual(
            module.aux_data["elfSymbolInfo"].data[parser_table_symbol][0],
            64,
        )

        def resolved_address(expression):
            self.assertIsInstance(expression, gtirb.SymAddrConst)
            symbol = expression.symbol
            base = (
                symbol.referent.address
                if symbol.referent is not None
                else symbol.value
            )
            return base + expression.offset

        for record, expected_name in enumerate(
            (0x6F4D35, 0x6F4D42, 0x6F4D55, 0x6F4D68)
        ):
            name_offset = record * 16
            name_expressions = list(
                parser_table.byte_interval.symbolic_expressions_at(
                    range(
                        parser_table.address + name_offset,
                        parser_table.address + name_offset + 8,
                    )
                )
            )
            self.assertEqual(len(name_expressions), 1)
            self.assertEqual(
                resolved_address(name_expressions[0][2]),
                expected_name,
            )

            parser_symbol = next(module.symbols_named(f"parser_{record}"))
            parser_address = (
                parser_symbol.referent.address
                if parser_symbol.referent is not None
                else parser_symbol.value
            )
            parser_offset = name_offset + 8
            parser_expressions = list(
                parser_table.byte_interval.symbolic_expressions_at(
                    range(
                        parser_table.address + parser_offset,
                        parser_table.address + parser_offset + 8,
                    )
                )
            )
            self.assertEqual(len(parser_expressions), 1)
            self.assertEqual(
                resolved_address(parser_expressions[0][2]),
                parser_address,
            )

    @unittest.skipUnless(
        platform.system() == "Linux", "This test is linux only."
    )
    def test_data_integer_matching_interior_address(self):
        """
        Numeric data fields that happen to equal unlabeled interior code or
        data-object addresses must stay literal. Independent pointer evidence
        from symbols, function entries, relocations, loads, calls, and indexed
        pointer tables must remain effective.
        """
        binary = Path("ex")
        with cd(ex_asm_dir / "ex_interior_code_literal"):
            self.assertTrue(compile("gcc", "g++", "-O0", []))
            module = disassemble(binary).ir().modules[0]
            symbol = next(module.symbols_named("collision_literal"))
            block = symbol.referent
            self.assertIsInstance(block, gtirb.DataBlock)

            def raw_pointer(module_block, offset):
                begin = module_block.offset + offset
                contents = module_block.byte_interval.contents
                return int.from_bytes(contents[begin : begin + 8], "little")

            def expression_at(module_block, offset):
                return list(
                    module_block.byte_interval.symbolic_expressions_at(
                        range(
                            module_block.address + offset,
                            module_block.address + offset + 8,
                        )
                    )
                )

            def data_location_for_symbol(symbol_name):
                """Return the containing block and symbol-relative offset.

                A label in the interior of an inferred data block is retained
                as an integral GTIRB symbol rather than being made the block's
                referent.  Both forms identify the same byte location.
                """
                data_symbol = next(module.symbols_named(symbol_name))
                if isinstance(data_symbol.referent, gtirb.DataBlock):
                    return data_symbol.referent, 0
                self.assertIsNotNone(data_symbol.value)
                address = data_symbol.value
                containing = [
                    candidate
                    for section in module.sections
                    for interval in section.byte_intervals
                    for candidate in interval.blocks
                    if isinstance(candidate, gtirb.DataBlock)
                    and candidate.address is not None
                    and candidate.address <= address
                    and address < candidate.address + candidate.size
                ]
                self.assertEqual(len(containing), 1)
                return containing[0], address - containing[0].address

            def expressions_for_code_symbol(symbol_name):
                code_block = next(module.symbols_named(symbol_name)).referent
                self.assertIsInstance(code_block, gtirb.CodeBlock)
                return list(
                    code_block.byte_interval.symbolic_expressions_at(
                        range(code_block.address, code_block.address + code_block.size)
                    )
                )

            # A moved immediate that is directly shifted as a scalar must not
            # become an address merely because its numeric value lands inside
            # a data OBJECT.  A genuine immediate used as a memory base remains
            # symbolic and resolves to its original interior target.
            self.assertEqual(
                expressions_for_code_symbol("collision_shifted_immediate_scalar"),
                [],
            )
            immediate_address_expressions = expressions_for_code_symbol(
                "collision_immediate_address_use"
            )
            self.assertEqual(len(immediate_address_expressions), 1)
            _, _, immediate_address_expression = immediate_address_expressions[0]
            self.assertIsInstance(immediate_address_expression, gtirb.SymAddrConst)
            self.assertEqual(
                immediate_address_expression.symbol.referent.address
                + immediate_address_expression.offset,
                0x700101,
            )

            literal_expressions = list(
                block.byte_interval.symbolic_expressions_at(
                    range(block.address, block.address + 8)
                )
            )
            self.assertEqual(literal_expressions, [])

            for offset, expected_symbol in (
                (8, "collision_function"),
                (16, "collision_labeled_interior"),
            ):
                pointer_expressions = list(
                    block.byte_interval.symbolic_expressions_at(
                        range(block.address + offset, block.address + offset + 8)
                    )
                )
                self.assertEqual(len(pointer_expressions), 1)
                _, _, expression = pointer_expressions[0]
                self.assertIsInstance(expression, gtirb.SymAddrConst)
                self.assertEqual(expression.symbol.name, expected_symbol)

            # Loaded-register call, direct-memory call, all indexed table
            # entries, and the symbol-free direct-call function entry.
            for offset in (24, 32, 40, 48, 56, 64, 80, 96, 104):
                pointer_expressions = expression_at(block, offset)
                self.assertEqual(len(pointer_expressions), 1)
                _, _, expression = pointer_expressions[0]
                self.assertIsInstance(expression, gtirb.SymAddrConst)
                self.assertIsInstance(expression.symbol.referent, gtirb.CodeBlock)
                self.assertEqual(
                    expression.symbol.referent.address, raw_pointer(block, offset)
                )

            # An address-shaped value used only as a scaled integer index is
            # not sufficient evidence to restore symbolic pointer status.
            self.assertEqual(expression_at(block, 72), [])

            # An aligned short NUL-terminated field in a string pool can have
            # the same raw bytes as a mapped address.  The adjacent longer
            # string distinguishes it from printable pointer bytes in a
            # descriptor record, so the field must remain literal.
            short_string = next(
                module.symbols_named("collision_short_string_literal")
            ).referent
            self.assertIsInstance(short_string, gtirb.DataBlock)
            self.assertEqual(
                bytes(
                    short_string.byte_interval.contents[
                        short_string.offset : short_string.offset + 8
                    ]
                ),
                b"ABC\x00\x00\x00\x00\x00",
            )
            self.assertEqual(expression_at(short_string, 0), [])

            # A data table can be the only reference to a short option name.
            # Even though the padded bytes numerically equal a mapped address,
            # the incoming aligned pointer and adjacent string identify the
            # source slot as text rather than as a pointer field.
            data_referenced_short_string = next(
                module.symbols_named(
                    "collision_data_referenced_short_string_literal"
                )
            ).referent
            self.assertIsInstance(
                data_referenced_short_string, gtirb.DataBlock
            )
            self.assertEqual(
                bytes(
                    data_referenced_short_string.byte_interval.contents[
                        data_referenced_short_string.offset
                        : data_referenced_short_string.offset + 8
                    ]
                ),
                b"pss\x00\x00\x00\x00\x00",
            )
            self.assertEqual(
                raw_pointer(data_referenced_short_string, 0), 0x737370
            )
            self.assertEqual(
                expression_at(data_referenced_short_string, 0), []
            )

            # The same source evidence must work without a neighboring
            # string.  This models a standalone compiler literal followed by
            # zero-filled padding before an unrelated object.
            isolated_referenced_short_string = next(
                module.symbols_named(
                    "collision_isolated_referenced_short_string_literal"
                )
            ).referent
            self.assertIsInstance(
                isolated_referenced_short_string, gtirb.DataBlock
            )
            self.assertEqual(
                bytes(
                    isolated_referenced_short_string.byte_interval.contents[
                        isolated_referenced_short_string.offset
                        : isolated_referenced_short_string.offset + 8
                    ]
                ),
                b"ABC\x00\x00\x00\x00\x00",
            )
            self.assertEqual(
                raw_pointer(isolated_referenced_short_string, 0), 0x434241
            )
            self.assertEqual(
                expression_at(isolated_referenced_short_string, 0), []
            )

            # A referenced descriptor table can begin with a pointer whose
            # little-endian bytes also form a short string.  Five records with
            # the same anonymous-string pointer at one fixed field offset are
            # structural evidence that the leading field is a pointer.
            repeated_string_records = next(
                module.symbols_named(
                    "collision_leading_repeated_string_records"
                )
            ).referent
            self.assertIsInstance(repeated_string_records, gtirb.DataBlock)
            for offset in (0, 40, 80, 120, 160):
                expressions = expression_at(repeated_string_records, offset)
                self.assertEqual(len(expressions), 1)
                _, _, expression = expressions[0]
                self.assertIsInstance(expression, gtirb.SymAddrConst)
                self.assertEqual(
                    expression.symbol.referent.address + expression.offset,
                    raw_pointer(repeated_string_records, offset),
                )

            # Four repetitions do not establish the same descriptor pattern;
            # the referenced leading address-shaped scalar stays literal.
            four_repeated_scalars = next(
                module.symbols_named(
                    "collision_four_repeated_string_scalars"
                )
            ).referent
            self.assertIsInstance(four_repeated_scalars, gtirb.DataBlock)
            self.assertEqual(
                raw_pointer(four_repeated_scalars, 0), 0x742B60
            )
            self.assertEqual(expression_at(four_repeated_scalars, 0), [])

            # A referenced compiler string can contain an unaligned byte
            # window that exactly equals a real symbol address.  The string
            # start, not its accidental interior window, has source evidence.
            referenced_long_string = next(
                module.symbols_named(
                    "collision_referenced_long_string_literal"
                )
            ).referent
            self.assertIsInstance(referenced_long_string, gtirb.DataBlock)
            self.assertEqual(
                bytes(
                    referenced_long_string.byte_interval.contents[
                        referenced_long_string.offset
                        : referenced_long_string.offset + 10
                    ]
                ),
                b"ffdhe3072\x00",
            )
            self.assertEqual(
                raw_pointer(referenced_long_string, 6), 0x323730
            )
            self.assertEqual(expression_at(referenced_long_string, 6), [])

            # A string-tail collision can also begin at a naturally aligned
            # address.  The bytes "pem\0" at +8 equal an exact original symbol
            # address, but the independently referenced enclosing string is
            # stronger source-boundary evidence and must remain byte literal.
            referenced_aligned_tail = next(
                module.symbols_named(
                    "collision_referenced_aligned_tail_string_literal"
                )
            ).referent
            self.assertIsInstance(referenced_aligned_tail, gtirb.DataBlock)
            self.assertEqual(
                bytes(
                    referenced_aligned_tail.byte_interval.contents[
                        referenced_aligned_tail.offset
                        : referenced_aligned_tail.offset + 12
                    ]
                ),
                b"providerpem\x00",
            )
            self.assertEqual(
                raw_pointer(referenced_aligned_tail, 8), 0x6D6570
            )
            self.assertEqual(expression_at(referenced_aligned_tail, 8), [])

            # A short referenced string may begin one byte after a zero
            # padding byte.  The overlapping eight-byte value equals the exact
            # code symbol 0x484400, but changing it on relayout would corrupt
            # the literal "DH" suffix.
            zero_prefixed_string, zero_prefixed_string_offset = (
                data_location_for_symbol(
                    "collision_zero_prefixed_referenced_string_literal"
                )
            )
            self.assertEqual(
                raw_pointer(
                    zero_prefixed_string, zero_prefixed_string_offset - 1
                ),
                0x484400,
            )
            self.assertEqual(
                expression_at(
                    zero_prefixed_string, zero_prefixed_string_offset - 1
                ),
                [],
            )

            # The referenced suffix can be only one printable byte.  Here two
            # preceding zeros plus "w\0" equal the exact address 0x770000, but
            # the overlapping source is literal storage and must stay raw.
            single_char_string, single_char_string_offset = (
                data_location_for_symbol(
                    "collision_zero_prefixed_single_char_literal"
                )
            )
            self.assertEqual(
                raw_pointer(single_char_string, single_char_string_offset - 2),
                0x770000,
            )
            self.assertEqual(
                expression_at(
                    single_char_string, single_char_string_offset - 2
                ),
                [],
            )

            # The identical overlapping shape remains symbolic when code
            # loads and dereferences the pointer-width field itself.
            (
                zero_prefixed_pointer_string,
                zero_prefixed_pointer_string_offset,
            ) = data_location_for_symbol(
                "collision_zero_prefixed_pointer_string"
            )
            self.assertEqual(
                raw_pointer(
                    zero_prefixed_pointer_string,
                    zero_prefixed_pointer_string_offset - 1,
                ),
                0x484400,
            )
            zero_prefixed_pointer_expression = expression_at(
                zero_prefixed_pointer_string,
                zero_prefixed_pointer_string_offset - 1,
            )
            self.assertEqual(len(zero_prefixed_pointer_expression), 1)
            _, _, expression = zero_prefixed_pointer_expression[0]
            self.assertIsInstance(expression, gtirb.SymAddrConst)
            self.assertEqual(
                expression.symbol.referent.address + expression.offset,
                0x484400,
            )

            # Loading and dereferencing the complete field remains stronger
            # pointer evidence for the otherwise identical one-byte suffix.
            (
                single_char_pointer,
                single_char_pointer_offset,
            ) = data_location_for_symbol(
                "collision_zero_prefixed_single_char_pointer"
            )
            self.assertEqual(
                raw_pointer(
                    single_char_pointer, single_char_pointer_offset - 2
                ),
                0x770000,
            )
            single_char_pointer_expression = expression_at(
                single_char_pointer, single_char_pointer_offset - 2
            )
            self.assertEqual(len(single_char_pointer_expression), 1)
            _, _, expression = single_char_pointer_expression[0]
            self.assertIsInstance(expression, gtirb.SymAddrConst)
            self.assertEqual(
                expression.symbol.referent.address + expression.offset,
                0x770000,
            )

            # The matching aligned qword remains symbolic when code loads and
            # dereferences that field directly.
            referenced_aligned_pointer = next(
                module.symbols_named(
                    "collision_referenced_aligned_tail_pointer_control"
                )
            ).referent
            self.assertIsInstance(referenced_aligned_pointer, gtirb.DataBlock)
            aligned_tail_expression = expression_at(
                referenced_aligned_pointer, 8
            )
            self.assertEqual(len(aligned_tail_expression), 1)
            _, _, expression = aligned_tail_expression[0]
            self.assertIsInstance(expression, gtirb.SymAddrConst)
            self.assertEqual(
                expression.symbol.referent.address + expression.offset,
                0x6D6570,
            )

            # The same printable bytes are a genuine packed pointer when an
            # exact pointer-width load consumes the unaligned field.
            referenced_long_pointer = next(
                module.symbols_named(
                    "collision_referenced_long_string_pointer_control"
                )
            ).referent
            self.assertIsInstance(referenced_long_pointer, gtirb.DataBlock)
            referenced_long_expression = expression_at(
                referenced_long_pointer, 6
            )
            self.assertEqual(len(referenced_long_expression), 1)
            _, _, expression = referenced_long_expression[0]
            self.assertIsInstance(expression, gtirb.SymAddrConst)
            self.assertEqual(
                expression.symbol.referent.address + expression.offset,
                0x323730,
            )

            # Identical bytes are a genuine pointer in the positive control:
            # its loaded value is directly dereferenced.
            short_string_pointer = next(
                module.symbols_named("collision_short_string_pointer_control")
            ).referent
            self.assertIsInstance(short_string_pointer, gtirb.DataBlock)
            pointer_expression = expression_at(short_string_pointer, 0)
            self.assertEqual(len(pointer_expression), 1)
            _, _, expression = pointer_expression[0]
            self.assertIsInstance(expression, gtirb.SymAddrConst)
            self.assertEqual(
                expression.symbol.referent.address + expression.offset,
                0x434241,
            )

            # A genuine aligned pointer can overlap a second address-shaped
            # eight-byte window that begins inside it.  Here the interior
            # window at +6 happens to equal the exact address of an unrelated
            # symbol; source alignment must keep the expression at +0 and
            # reject the overlapping interior candidate.
            overlapping_pointer = next(
                module.symbols_named("collision_overlapping_aligned_pointer")
            ).referent
            self.assertIsInstance(overlapping_pointer, gtirb.DataBlock)
            aligned_expression = expression_at(overlapping_pointer, 0)
            self.assertEqual(len(aligned_expression), 1)
            _, _, expression = aligned_expression[0]
            self.assertIsInstance(expression, gtirb.SymAddrConst)
            self.assertEqual(
                expression.symbol.referent.address + expression.offset,
                raw_pointer(overlapping_pointer, 0),
            )
            self.assertEqual(
                int.from_bytes(
                    overlapping_pointer.byte_interval.contents[
                        overlapping_pointer.offset
                        + 6 : overlapping_pointer.offset
                        + 14
                    ],
                    "little",
                ),
                0x700000,
            )
            self.assertEqual(expression_at(overlapping_pointer, 6), [])

            # A weak unaligned window may happen to equal an exact code
            # symbol merely by straddling two naturally aligned scalar slots.
            # Exact destination identity does not establish a source-field
            # boundary when no relocation, label, access, or array evidence
            # anchors the unaligned start.
            unaligned_scalar = next(
                module.symbols_named(
                    "collision_unaligned_exact_symbol_scalar"
                )
            ).referent
            self.assertIsInstance(unaligned_scalar, gtirb.DataBlock)
            self.assertEqual(
                int.from_bytes(
                    unaligned_scalar.byte_interval.contents[
                        unaligned_scalar.offset
                        + 14 : unaligned_scalar.offset
                        + 22
                    ],
                    "little",
                ),
                0x500000,
            )
            self.assertEqual(expression_at(unaligned_scalar, 14), [])

            # The same unanchored collision remains numeric when its source
            # window starts inside the final bytes of a declared OBJECT and
            # continues into anonymous padding.  A pointer field cannot be
            # established merely from an exact destination symbol.
            object_tail_scalar = next(
                module.symbols_named(
                    "collision_unaligned_object_tail_scalar"
                )
            ).referent
            self.assertIsInstance(object_tail_scalar, gtirb.DataBlock)
            self.assertEqual(raw_pointer(object_tail_scalar, 4), 0x500000)
            self.assertEqual(expression_at(object_tail_scalar, 4), [])

            # The reverse shape is equally unsafe: an unanchored pointer-width
            # window can begin in anonymous padding and cross the start of a
            # named scalar object.  Reinterpreting the bytes at object-2 as an
            # exact-symbol pointer would corrupt the object's leading field
            # when the unrelated destination moves.
            object_head_scalar, object_head_offset = data_location_for_symbol(
                "collision_unaligned_object_head_scalar"
            )
            self.assertEqual(
                raw_pointer(object_head_scalar, object_head_offset - 2),
                0x500000,
            )
            self.assertEqual(
                expression_at(object_head_scalar, object_head_offset - 2),
                [],
            )

            # The same boundary crossing remains symbolic when code performs
            # an exact pointer-width load and dereferences the loaded value.
            (
                cross_boundary_pointer,
                cross_boundary_pointer_offset,
            ) = data_location_for_symbol(
                "collision_cross_object_boundary_pointer_object"
            )
            cross_boundary_expression = expression_at(
                cross_boundary_pointer, cross_boundary_pointer_offset - 2
            )
            self.assertEqual(len(cross_boundary_expression), 1)
            _, _, expression = cross_boundary_expression[0]
            self.assertIsInstance(expression, gtirb.SymAddrConst)
            self.assertEqual(
                expression.symbol.referent.address,
                raw_pointer(
                    cross_boundary_pointer,
                    cross_boundary_pointer_offset - 2,
                ),
            )

            # Three genuine relative switch entries remain SymAddrAddr
            # expressions, while the pointer-width window beginning two bytes
            # into the first entry is only a byte coincidence with the exact
            # code symbol at 0x500000.
            relative_table = next(
                module.symbols_named("collision_relative_jump_table")
            ).referent
            self.assertIsInstance(relative_table, gtirb.DataBlock)
            self.assertEqual(raw_pointer(relative_table, 2), 0x500000)
            expressions = relative_table.byte_interval.symbolic_expressions
            relative_starts = {
                relative_table.byte_interval.address + offset
                for offset, expression in expressions.items()
                if isinstance(expression, gtirb.SymAddrAddr)
                and relative_table.address
                <= relative_table.byte_interval.address + offset
                < relative_table.address + 12
            }
            self.assertEqual(
                relative_starts,
                {
                    relative_table.address,
                    relative_table.address + 4,
                    relative_table.address + 8,
                },
            )
            self.assertNotIn(
                relative_table.address + 2,
                {
                    relative_table.byte_interval.address + offset
                    for offset, expression in expressions.items()
                    if isinstance(expression, gtirb.SymAddrConst)
                },
            )

            # Even when an address-shaped integer indexes a pointer-table load
            # whose result is called, the index is not itself a code pointer.
            self.assertEqual(expression_at(block, 112), [])

            # An indexed indirect branch may expose only sparse data-access
            # witnesses for a contiguous code-pointer array.  The bounded
            # indexed load flows directly to a register jump, with no scalar
            # per-cell witness.  Every pointer-width member of that exact
            # all-code array must remain symbolic.
            sparse_code_array = next(
                module.symbols_named("collision_sparse_code_pointer_array")
            ).referent
            self.assertIsInstance(sparse_code_array, gtirb.DataBlock)
            for offset in range(0, 72, 8):
                sparse_expression = expression_at(sparse_code_array, offset)
                self.assertEqual(len(sparse_expression), 1)
                _, _, expression = sparse_expression[0]
                self.assertIsInstance(expression, gtirb.SymAddrConst)
                self.assertIsInstance(expression.symbol.referent, gtirb.CodeBlock)
                self.assertEqual(
                    expression.symbol.referent.address,
                    raw_pointer(sparse_code_array, offset),
                )

            # A direct indexed memory-indirect jump supplies table-level
            # control-flow evidence without defining an intermediate load
            # register.  All members of that exact table must relocate.
            direct_indexed_code_array = next(
                module.symbols_named(
                    "collision_direct_indexed_code_pointer_array"
                )
            ).referent
            self.assertIsInstance(direct_indexed_code_array, gtirb.DataBlock)
            for offset in range(0, 32, 8):
                indexed_expression = expression_at(
                    direct_indexed_code_array, offset
                )
                self.assertEqual(len(indexed_expression), 1)
                _, _, expression = indexed_expression[0]
                self.assertIsInstance(expression, gtirb.SymAddrConst)
                self.assertIsInstance(expression.symbol.referent, gtirb.CodeBlock)
                self.assertEqual(
                    expression.symbol.referent.address,
                    raw_pointer(direct_indexed_code_array, offset),
                )

            # An adjacent, separately labeled array of code-looking integers
            # has no control-flow witness.  Recovery for the real table must
            # not cross the source label and reinterpret these scalars.
            unused_code_like_array = next(
                module.symbols_named("collision_unused_code_like_array")
            ).referent
            self.assertIsInstance(unused_code_like_array, gtirb.DataBlock)
            for offset in range(0, 72, 8):
                self.assertEqual(
                    expression_at(unused_code_like_array, offset), []
                )

            # Packed 16-bit scalar values can numerically collide with an
            # unlabeled address strictly inside a known data object.  That is
            # not sufficient pointer evidence.
            self.assertEqual(raw_pointer(block, 120), 0x70003B)
            self.assertEqual(expression_at(block, 120), [])

            # Exact target symbols, pointer-sized load/dereference evidence,
            # and a three-entry pointer array each retain genuine pointers
            # into that same data object.
            self.assertEqual(expression_at(block, 128), [])
            exact_data_expression = expression_at(block, 136)
            self.assertEqual(len(exact_data_expression), 1)
            exact_data_target = next(
                module.symbols_named("collision_labeled_data_interior")
            ).referent
            self.assertEqual(exact_data_target.address, raw_pointer(block, 136))
            _, _, exact_expression = exact_data_expression[0]
            self.assertIsInstance(exact_expression, gtirb.SymAddrConst)
            self.assertEqual(
                exact_expression.symbol.referent.address + exact_expression.offset,
                raw_pointer(block, 136),
            )
            for offset in (144, 160, 168, 176):
                data_pointer_expressions = expression_at(block, offset)
                self.assertEqual(len(data_pointer_expressions), 1)
                _, _, expression = data_pointer_expressions[0]
                self.assertIsInstance(expression, gtirb.SymAddrConst)
                self.assertIsInstance(expression.symbol.referent, gtirb.DataBlock)
                self.assertEqual(
                    expression.symbol.referent.address + expression.offset,
                    raw_pointer(block, offset),
                )

            # Without retained relocation evidence, the otherwise-unused
            # interior data address is no stronger than an accidental scalar.
            self.assertEqual(expression_at(block, 152), [])
            self.assertEqual(expression_at(block, 184), [])
            self.assertEqual(expression_at(block, 192), [])

            # Without retained relocation evidence, the otherwise-unused
            # interior address is no stronger than an accidental integer.
            self.assertEqual(expression_at(block, 88), [])

            # In the companion binary, the retained relocation is independent
            # evidence for an otherwise unlabeled interior code address.
            relocated_module = disassemble(Path("ex_reloc")).ir().modules[0]
            relocated_block = next(
                relocated_module.symbols_named("collision_literal")
            ).referent
            relocated_expressions = expression_at(relocated_block, 88)
            self.assertEqual(len(relocated_expressions), 1)
            _, _, expression = relocated_expressions[0]
            self.assertIsInstance(expression, gtirb.SymAddrConst)
            relocated_begin = relocated_block.offset + 88
            relocated_value = int.from_bytes(
                relocated_block.byte_interval.contents[
                    relocated_begin : relocated_begin + 8
                ],
                "little",
            )
            self.assertEqual(expression.symbol.referent.address, relocated_value)
            self.assertEqual(expression_at(relocated_block, 0), [])
            self.assertEqual(expression_at(relocated_block, 72), [])
            self.assertEqual(expression_at(relocated_block, 112), [])
            self.assertEqual(expression_at(relocated_block, 120), [])

            relocated_data_expressions = expression_at(relocated_block, 192)
            self.assertEqual(len(relocated_data_expressions), 1)
            _, _, relocated_data_expression = relocated_data_expressions[0]
            self.assertIsInstance(relocated_data_expression, gtirb.SymAddrConst)
            self.assertEqual(
                relocated_data_expression.symbol.referent.address
                + relocated_data_expression.offset,
                raw_pointer(relocated_block, 192),
            )

            # Five same-field pointers at a 40-byte record stride retain
            # symbolization even though interleaved pointers into another
            # object prevent the ordinary address-array heuristic from seeing
            # them as a contiguous pointer sequence.
            strided_block = next(
                module.symbols_named("collision_strided_records")
            ).referent
            self.assertIsInstance(strided_block, gtirb.DataBlock)
            for offset in (0, 8, 40, 48, 80, 88, 120, 128, 160, 168):
                strided_expressions = expression_at(strided_block, offset)
                self.assertEqual(len(strided_expressions), 1)
                _, _, strided_expression = strided_expressions[0]
                self.assertIsInstance(strided_expression, gtirb.SymAddrConst)
                self.assertIsInstance(
                    strided_expression.symbol.referent, gtirb.DataBlock
                )
                self.assertEqual(
                    strided_expression.symbol.referent.address
                    + strided_expression.offset,
                    raw_pointer(strided_block, offset),
                )

            # Five members are still insufficient at a three-pointer-width
            # stride: these packed scalar fields must stay literal.  Their
            # exact-symbol interleaved controls remain genuine pointers.
            short_stride_block = next(
                module.symbols_named("collision_short_stride_scalars")
            ).referent
            self.assertIsInstance(short_stride_block, gtirb.DataBlock)
            for offset in (0, 24, 48, 72, 96):
                self.assertEqual(raw_pointer(short_stride_block, offset), 0x70003B)
                self.assertEqual(expression_at(short_stride_block, offset), [])
            for offset in (8, 32, 56, 80, 104):
                short_pointer_expressions = expression_at(
                    short_stride_block, offset
                )
                self.assertEqual(len(short_pointer_expressions), 1)
                _, _, short_pointer_expression = short_pointer_expressions[0]
                self.assertIsInstance(
                    short_pointer_expression, gtirb.SymAddrConst
                )
                self.assertEqual(
                    short_pointer_expression.symbol.referent.address
                    + short_pointer_expression.offset,
                    raw_pointer(short_stride_block, offset),
                )

            # Three packed qwords at a 22-byte stride reproduce Brotli's
            # static-dictionary bucket collision.  The spacing is not a whole
            # number of pointer widths, so the sequence is not a pointer
            # array and all three values must remain literal.
            irregular_stride_block = next(
                module.symbols_named("collision_irregular_stride_scalars")
            ).referent
            self.assertIsInstance(irregular_stride_block, gtirb.DataBlock)
            for offset, value in (
                (0, 0x700307),
                (22, 0x70030F),
                (44, 0x700317),
            ):
                self.assertEqual(
                    raw_pointer(irregular_stride_block, offset), value
                )
                self.assertEqual(
                    expression_at(irregular_stride_block, offset), []
                )

            # An original source label splits an otherwise regular run into
            # two groups of four.  Evidence must not propagate across it.
            boundary_block = next(
                module.symbols_named("collision_boundary_split_records")
            ).referent
            self.assertIsInstance(boundary_block, gtirb.DataBlock)
            for offset in (0, 32, 64, 96, 128, 160, 192, 224):
                self.assertEqual(expression_at(boundary_block, offset), [])
            for offset in (8, 40, 72, 104, 136, 168, 200, 232):
                boundary_control = expression_at(boundary_block, offset)
                self.assertEqual(len(boundary_control), 1)
                _, _, boundary_expression = boundary_control[0]
                self.assertIsInstance(boundary_expression, gtirb.SymAddrConst)
                self.assertEqual(
                    boundary_expression.symbol.referent.address
                    + boundary_expression.offset,
                    raw_pointer(boundary_block, offset),
                )

            # Exact-stride recovery retains a proven five-member run, but
            # cannot jump over a missing record and promote a congruent raw
            # scalar after the gap.
            gap_block = next(
                module.symbols_named("collision_gap_records")
            ).referent
            self.assertIsInstance(gap_block, gtirb.DataBlock)
            for offset in (0, 32, 64, 96, 128):
                gap_pointer = expression_at(gap_block, offset)
                self.assertEqual(len(gap_pointer), 1)
                _, _, gap_expression = gap_pointer[0]
                self.assertIsInstance(gap_expression, gtirb.SymAddrConst)
                self.assertEqual(
                    gap_expression.symbol.referent.address
                    + gap_expression.offset,
                    raw_pointer(gap_block, offset),
                )
            self.assertEqual(raw_pointer(gap_block, 192), 0x700417)
            self.assertEqual(expression_at(gap_block, 192), [])
            for offset in (8, 40, 72, 104, 136, 200):
                gap_control = expression_at(gap_block, offset)
                self.assertEqual(len(gap_control), 1)
                _, _, gap_control_expression = gap_control[0]
                self.assertIsInstance(
                    gap_control_expression, gtirb.SymAddrConst
                )
                self.assertEqual(
                    gap_control_expression.symbol.referent.address
                    + gap_control_expression.offset,
                    raw_pointer(gap_block, offset),
                )

            # A positive u32 length immediately before an isolated pointer,
            # plus a retained pointer two records later to target+length,
            # recovers the sparse descriptor field.  The five later fields
            # establish the 40-byte record stride without bridging the null
            # record at offset 40.
            length_block = next(
                module.symbols_named("collision_length_delimited_records")
            ).referent
            self.assertIsInstance(length_block, gtirb.DataBlock)
            length_expression = expression_at(length_block, 8)
            self.assertEqual(len(length_expression), 1)
            _, _, expression = length_expression[0]
            self.assertIsInstance(expression, gtirb.SymAddrConst)
            self.assertEqual(
                expression.symbol.referent.address + expression.offset,
                raw_pointer(length_block, 8),
            )
            self.assertEqual(
                raw_pointer(length_block, 88) - raw_pointer(length_block, 8),
                8,
            )
            for offset in (88, 128, 168, 208, 248):
                self.assertEqual(len(expression_at(length_block, offset)), 1)

            # The structurally identical negative control has a length of
            # seven while the later destination is eight bytes farther on.
            # Its isolated first field therefore remains a raw integer.
            bad_length_block = next(
                module.symbols_named("collision_bad_length_delimited_records")
            ).referent
            self.assertIsInstance(bad_length_block, gtirb.DataBlock)
            self.assertEqual(
                raw_pointer(bad_length_block, 88)
                - raw_pointer(bad_length_block, 8),
                8,
            )
            self.assertEqual(expression_at(bad_length_block, 8), [])
            for offset in (88, 128, 168, 208, 248):
                self.assertEqual(len(expression_at(bad_length_block, offset)), 1)

            # Four records with two pointer/length fields form a strong
            # two-dimensional lattice.  The exact object-base target anchors
            # the primary field; constant source and destination strides then
            # retain all seven unlabeled interior targets even though the
            # source constant pool has no enclosing OBJECT symbol.
            sized_block, sized_base = data_location_for_symbol(
                "collision_sized_descriptor_records"
            )
            for offset in (0, 40, 120, 160, 240, 280, 360, 400):
                sized_expressions = expression_at(
                    sized_block, sized_base + offset
                )
                self.assertEqual(len(sized_expressions), 1)
                _, _, sized_expression = sized_expressions[0]
                self.assertIsInstance(sized_expression, gtirb.SymAddrConst)
                self.assertEqual(
                    sized_expression.symbol.referent.address
                    + sized_expression.offset,
                    raw_pointer(sized_block, sized_base + offset),
                )

            # One broken destination stride invalidates the otherwise similar
            # negative lattice.  The exact first target remains independently
            # symbolic, while every unlabeled interior value stays literal.
            bad_sized_block, bad_sized_base = data_location_for_symbol(
                "collision_bad_sized_descriptor_records"
            )
            self.assertEqual(
                len(expression_at(bad_sized_block, bad_sized_base)), 1
            )
            for offset in (40, 120, 160, 240, 280, 360, 400):
                self.assertEqual(
                    expression_at(bad_sized_block, bad_sized_base + offset),
                    [],
                )

            # A densely indexed uint64 table is not a pointer table merely
            # because regularly spaced scalar values resemble data addresses.
            # Even using a loaded scalar as a scaled memory index is not
            # pointer evidence.
            dense_scalar = next(
                module.symbols_named("collision_dense_scalar_lattice")
            ).referent
            self.assertIsInstance(dense_scalar, gtirb.DataBlock)
            for offset in (64, 128, 192, 256, 320):
                self.assertEqual(expression_at(dense_scalar, offset), [])

            dense_scalar32 = next(
                module.symbols_named("collision_dense_scalar32_lattice")
            ).referent
            self.assertIsInstance(dense_scalar32, gtirb.DataBlock)
            for offset in (0, 32, 64, 96, 128):
                self.assertEqual(expression_at(dense_scalar32, offset), [])

            # Two adjacent uint32_t entries beyond a zero-run access limit form
            # the aligned 64-bit value 0x700010, which is an exact symbol
            # address in this fixture.  The object-level dense four-byte access
            # still proves that the source fields are scalar even where local
            # preferred-access propagation stops.
            dense_u32_scalar = next(
                module.symbols_named("collision_dense_u32_scalar_table")
            ).referent
            self.assertIsInstance(dense_u32_scalar, gtirb.DataBlock)
            self.assertEqual(expression_at(dense_u32_scalar, 72), [])

            # The matching dense table remains symbolic when its loaded value
            # is directly dereferenced as a memory base.
            dense_pointer = next(
                module.symbols_named("collision_dense_pointer_lattice")
            ).referent
            self.assertIsInstance(dense_pointer, gtirb.DataBlock)
            for offset in (0, 64, 128, 192, 256):
                dense_expression = expression_at(dense_pointer, offset)
                self.assertEqual(len(dense_expression), 1)
                _, _, expression = dense_expression[0]
                self.assertIsInstance(expression, gtirb.SymAddrConst)
                self.assertIsInstance(expression.symbol.referent, gtirb.DataBlock)
                self.assertEqual(
                    expression.symbol.referent.address + expression.offset,
                    raw_pointer(dense_pointer, offset),
                )

            # A matching dense source table of aligned genuine pointers is
            # returned by its accessor instead of immediately dereferenced.
            # Target alignment keeps it outside the packed-scalar penalty.
            dense_aligned_pointer = next(
                module.symbols_named("collision_dense_aligned_pointer_lattice")
            ).referent
            self.assertIsInstance(dense_aligned_pointer, gtirb.DataBlock)
            for offset in (0, 64, 128, 192, 256):
                aligned_expression = expression_at(dense_aligned_pointer, offset)
                self.assertEqual(len(aligned_expression), 1)
                _, _, expression = aligned_expression[0]
                self.assertIsInstance(expression, gtirb.SymAddrConst)
                self.assertEqual(raw_pointer(dense_aligned_pointer, offset) % 8, 0)
                self.assertEqual(
                    expression.symbol.referent.address + expression.offset,
                    raw_pointer(dense_aligned_pointer, offset),
                )

            # Misaligned, symbol-free string starts are also genuine pointer
            # evidence when at least three members of the same dense array
            # point to independently inferred string starts.  The accessor
            # only returns the loaded pointer; it does not dereference it.
            dense_string_pointer = next(
                module.symbols_named("collision_dense_string_pointer_lattice")
            ).referent
            self.assertIsInstance(dense_string_pointer, gtirb.DataBlock)
            for offset in (0, 8, 16, 24, 32, 40):
                string_expression = expression_at(dense_string_pointer, offset)
                self.assertEqual(len(string_expression), 1)
                _, _, expression = string_expression[0]
                self.assertIsInstance(expression, gtirb.SymAddrConst)
                resolved = expression.symbol.referent.address + expression.offset
                self.assertEqual(resolved, raw_pointer(dense_string_pointer, offset))
                self.assertEqual(resolved % 8, 1)

            # A directly dereferenced pointer load elsewhere in the same
            # source OBJECT must recover only its own subarray, never the
            # unrelated scalar subarray.
            dense_mixed = next(
                module.symbols_named("collision_dense_mixed_object")
            ).referent
            self.assertIsInstance(dense_mixed, gtirb.DataBlock)
            for offset in (0, 64, 128, 192, 256):
                self.assertEqual(expression_at(dense_mixed, offset), [])
            for offset in (320, 384, 448, 512, 576):
                mixed_pointer_expression = expression_at(dense_mixed, offset)
                self.assertEqual(len(mixed_pointer_expression), 1)
                _, _, expression = mixed_pointer_expression[0]
                self.assertIsInstance(expression, gtirb.SymAddrConst)
                self.assertEqual(
                    expression.symbol.referent.address + expression.offset,
                    raw_pointer(dense_mixed, offset),
                )

            # A broad outer symbol cannot let the dense load in one nested
            # sibling penalize an unused pointer array in the other sibling.
            dense_nested_scalar = next(
                module.symbols_named("collision_dense_nested_scalar")
            ).referent
            dense_nested_pointer = next(
                module.symbols_named("collision_dense_nested_pointer")
            ).referent
            for offset in (0, 64, 128, 192, 256):
                self.assertEqual(
                    expression_at(dense_nested_scalar, offset), []
                )
                nested_pointer_expression = expression_at(
                    dense_nested_pointer, offset
                )
                self.assertEqual(len(nested_pointer_expression), 1)
                _, _, expression = nested_pointer_expression[0]
                self.assertIsInstance(expression, gtirb.SymAddrConst)
                self.assertEqual(
                    expression.symbol.referent.address + expression.offset,
                    raw_pointer(dense_nested_pointer, offset),
                )

            # Constructor/destructor tables provide function-entry evidence
            # without requiring a target symbol or an unwind record.
            init_block = next(
                module.symbols_named("collision_init_pointer")
            ).referent
            init_expressions = list(
                init_block.byte_interval.symbolic_expressions_at(
                    range(init_block.address, init_block.address + 8)
                )
            )
            self.assertEqual(len(init_expressions), 1)
            _, _, init_expression = init_expressions[0]
            self.assertIsInstance(init_expression, gtirb.SymAddrConst)
            init_target = init_expression.symbol.referent
            self.assertIsInstance(init_target, gtirb.CodeBlock)
            function_entries = {
                entry
                for entries in module.aux_data["functionEntries"].data.values()
                for entry in entries
            }
            self.assertIn(init_target, function_entries)

    @unittest.skipUnless(
        platform.system() == "Linux", "This test is linux only."
    )
    def test_lea_results(self):
        """
        Test that
         - LEA is always symbolized when it is a PC-relative
         - Other LEA operation might be used for normal arithmetic
           If the result is compared to a non-symbolic operand or
           multiplied, the negative heuristic will prevent symbolization.
        """
        binary = Path("ex")
        with cd(ex_asm_dir / "ex_symbolic_operand_heuristics"):
            self.assertTrue(compile("gcc", "g++", "-O0", []))
            ir_library = disassemble(binary).ir()
            m = ir_library.modules[0]

            # check that we symbolize the LEA instructions with 0 offset
            symbolized = [
                "rip_lea",
                "rip_lea_misleading",
                "rip_lea_misleading_call_rdi",
                "rip_lea_misleading_call_rdx",
            ]
            for name in symbolized:
                symbol = next(m.symbols_named(name))
                block = symbol.referent
                self.assertIsInstance(block, gtirb.CodeBlock)
                _, _, sym_expr = next(
                    block.byte_interval.symbolic_expressions_at(
                        range(block.address, block.address + block.size)
                    )
                )
                self.assertIsInstance(sym_expr, gtirb.SymAddrConst)
                self.assertEqual(sym_expr.offset, 0)
            # check that we don't symbolize LEA instructions used for
            # regular arithmetic
            not_symbolized = ["lea_multiplied", "lea_cmp"]
            for name in not_symbolized:
                symbol = next(m.symbols_named(name))
                block = symbol.referent
                self.assertIsInstance(block, gtirb.CodeBlock)
                self.assertFalse(
                    list(
                        block.byte_interval.symbolic_expressions_at(
                            range(block.address, block.address + block.size)
                        )
                    )
                )

    @unittest.skipUnless(
        platform.system() == "Linux", "This test is linux only."
    )
    def test_lea_sym_minus_sym(self):
        """
        Test cases where the displacement of indirect operand in LEA is the
        distance between EAs.
        Such displacements should be symbolized as symbol_minus_symbol.
        """
        binary = Path("ex")
        with cd(ex_asm_dir / "ex_sym_minus_sym"):
            self.assertTrue(compile("gcc", "g++", "-O0", []))
            ir_library = disassemble(binary).ir()
            m = ir_library.modules[0]

            # check that we symbolize the LEA instructions
            symbolized = [
                ("lea_sym_minus_sym1", "target2", "lea_sym_minus_sym1"),
                ("lea_sym_minus_sym2", "target1", "target2"),
            ]
            for name, sym1, sym2 in symbolized:
                symbol = next(m.symbols_named(name))
                block = symbol.referent
                self.assertIsInstance(block, gtirb.CodeBlock)
                _, _, sym_expr = next(
                    block.byte_interval.symbolic_expressions_at(
                        range(block.address, block.address + block.size)
                    )
                )
                self.assertIsInstance(sym_expr, gtirb.SymAddrAddr)
                self.assertEqual(sym_expr.scale, 1)
                self.assertEqual(sym_expr.offset, 0)
                self.assertEqual(sym_expr.symbol1.name, sym1)
                self.assertEqual(sym_expr.symbol2.name, sym2)

    @unittest.skipUnless(
        platform.system() == "Linux", "This test is linux only."
    )
    def test_lsda_symbol_selection(self):
        """
        Test that LSDA symbol-minus-symbol expressions use the best available
        symbol (e.g. a FUNC/GLOBAL symbol) rather than a boundary label such as
        .L_<addr>_END, when multiple symbols share the same address.
        """
        binary = Path("ex")
        with cd(ex_asm_dir / "ex_symbol_selection4"):
            self.assertTrue(compile("g++", "g++", "-O0", []))
            ir_library = disassemble(binary).ir()
            m = ir_library.modules[0]

            # check that we symbolize the LEA instructions
            symbolized = [
                ("CHECK_SYMBOL", "_bar", "_bar"),
            ]
            for name, sym1, sym2 in symbolized:
                symbol = next(m.symbols_named(name))
                block = symbol.referent
                self.assertIsInstance(block, gtirb.DataBlock)
                _, _, sym_expr = next(
                    block.byte_interval.symbolic_expressions_at(
                        range(block.address, block.address + block.size)
                    )
                )
                self.assertIsInstance(sym_expr, gtirb.SymAddrAddr)
                self.assertEqual(sym_expr.scale, 1)
                self.assertEqual(sym_expr.offset, 0)
                self.assertEqual(sym_expr.symbol1.name, sym1)
                self.assertEqual(sym_expr.symbol2.name, sym2)


if __name__ == "__main__":
    unittest.main()
