import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

import gtirb

from disassemble_reassemble_check import disassemble
from snippets import parse_souffle_output


@unittest.skipUnless(shutil.which("gcc"), "GCC required")
class BssPointerArrayTest(unittest.TestCase):
    def lift(self, fields, target_section=".bss", arch="x64"):
        # Passing the table to another function prevents a direct absolute
        # load from independently supplying pointer-width access evidence.
        compiler, entry, consume = {
            "x64": ("gcc", """
                lea records(%rip), %rdi
                call consume
                xor %edi, %edi
                mov $60, %eax
                syscall
            """, "mov 32(%rdi), %rax; mov (%rax), %rax; ret"),
            "aarch64": ("aarch64-linux-gnu-gcc", """
                adrp x0, records
                add x0, x0, :lo12:records
                bl consume
                mov x0, #0
                mov x8, #93
                svc #0
            """, "ldr x1, [x0, #32]; ldr x0, [x1]; ret"),
            "riscv64": ("riscv64-linux-gnu-gcc", """
                .option norelax
                la a0, records
                call consume
                li a0, 0
                li a7, 93
                ecall
            """, "ld t0, 32(a0); ld a0, 0(t0); ret"),
        }[arch]
        if not shutil.which(compiler):
            self.skipTest(f"{compiler} required")
        source = f"""
            .text
            .globl _start
            .type _start, %function
            _start:
                {entry}
            .size _start, .-_start
            .type consume, %function
            consume:
                {consume}
            .size consume, .-consume
            .section .rodata
            name_string: .asciz "entry"
            .section .data.rel.ro, "aw", %progbits
            .balign 8
            .type records, %object
            records:
                .quad name_string
                .zero 24
                {fields}
            .size records, .-records
            {target_section}
            .balign 8
            .type storage, %object
            storage: .zero 96
            .size storage, .-storage
            .section .note.GNU-stack, "", %progbits
        """
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            assembly = root / "input.S"
            binary = root / "input"
            assembly.write_text(source)
            subprocess.run(
                [compiler, "-nostdlib", "-no-pie", "-Wl,--build-id=none",
                 f"-Wl,--section-start={target_section}=0x500000",
                 str(assembly), "-o", str(binary)],
                check=True,
            )
            return disassemble(
                binary, extra_args=["--with-souffle-relations"]
            ).ir().modules[0]

    def assert_pointer(self, module, slot_offset, target_offset):
        records = next(module.symbols_named("records")).referent.address
        slot = records + slot_offset
        expressions = [
            expr
            for section in module.sections
            for interval in section.byte_intervals
            for _, _, expr in interval.symbolic_expressions_at(slot)
        ]
        self.assertEqual(len(expressions), 1)
        expr = expressions[0]
        self.assertIsInstance(expr, gtirb.SymAddrConst)
        storage = next(module.symbols_named("storage")).referent.address
        self.assertEqual(expr.symbol.referent.address + expr.offset,
                         storage + target_offset)

    def test_interior_array_includes_uninitialized_destinations(self):
        # Four members exercise both the three-member seed and its extension.
        for section in (".data", ".bss"):
            with self.subTest(section=section):
                module = self.lift(
                    "\n".join(f".quad storage+{n}" for n in (40, 48, 56, 64)),
                    section,
                )
                for index, target in enumerate((40, 48, 56, 64)):
                    self.assert_pointer(module, 32 + 8 * index, target)

    def test_isolated_address_shaped_scalars_stay_numeric(self):
        for count in (1, 2):
            with self.subTest(count=count):
                module = self.lift("\n".join(
                    f".quad storage+{40 + 8 * n}" for n in range(count)))
                records = next(
                    module.symbols_named("records")
                ).referent.address
                for interval in module.byte_intervals:
                    self.assertFalse(list(interval.symbolic_expressions_at(
                        range(records + 32, records + 32 + 8 * count))))

    def test_bss_array_other_architectures(self):
        for arch in ("aarch64", "riscv64"):
            with self.subTest(arch=arch):
                module = self.lift(
                    ".quad storage+40\n.quad storage+48\n.quad storage+56",
                    arch=arch,
                )
                for index, target in enumerate((40, 48, 56)):
                    self.assert_pointer(module, 32 + 8 * index, target)

    def test_original_source_boundary_splits_array(self):
        for boundary in (".globl middle\nmiddle:",
                         ".type tail, @object\ntail:\n.size tail, 8"):
            with self.subTest(boundary=boundary):
                fields = (f".quad storage+40\n{boundary}\n"
                          ".quad storage+48\n.quad storage+56")
                module = self.lift(fields)
                start = (
                    next(module.symbols_named("records")).referent.address + 32
                )
                members = {ea for ea, _, _ in
                           parse_souffle_output(module, "address_array")}
                self.assertNotIn(start, members)

    def test_mixed_target_sections_do_not_seed_array(self):
        module = self.lift(
            ".quad storage+40\n.quad name_string\n.quad storage+56")
        start = next(module.symbols_named("records")).referent.address + 32
        members = {ea for ea, _, _ in
                   parse_souffle_output(module, "address_array")}
        self.assertNotIn(start, members)

    def test_one_past_bss_does_not_complete_array_seed(self):
        module = self.lift(
            ".quad storage+80\n.quad storage+88\n.quad storage+96")
        start = next(module.symbols_named("records")).referent.address + 32
        members = {ea for ea, _, _ in
                   parse_souffle_output(module, "address_array")}
        self.assertTrue({start, start + 8, start + 16}.isdisjoint(members))


if __name__ == "__main__":
    unittest.main()
