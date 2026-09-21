import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

import gtirb
from disassemble_reassemble_check import asm_print, disassemble


@unittest.skipUnless(shutil.which("aarch64-linux-gnu-gcc"), "AArch64 compiler required")
class Arm64SectionBoundariesTest(unittest.TestCase):
    def test_symbol_beyond_owner_uses_relocatable_section_end(self):
        # A linker may associate an aligned sentinel with .data even though
        # its address is just beyond that section, coinciding with .bss's end.
        # It must remain relative to its owning section when .bss moves away.
        source = """
        .text
        .globl _start
        .type _start, %function
        _start:
            adrp x0, outside_owner
            add x0, x0, :lo12:outside_owner
            adrp x1, owner_start
            add x1, x1, :lo12:owner_start
            sub x0, x0, x1
            cmp x0, #4
            cset w0, ne
            mov x8, #93
            svc #0
        .size _start, .-_start
        .data
        .type owner_start, %object
        owner_start: .byte 7
        .size owner_start, .-owner_start
        .type outside_owner, %object
        .set outside_owner, . + 3
        .bss
        .type unrelated_bss, %object
        unrelated_bss: .zero 3
        .size unrelated_bss, .-unrelated_bss
        .section .note.GNU-stack, "", %progbits
        """
        linker_script = """
        SECTIONS {
            . = 0x400000;
            .text : { *(.text) }
            . = 0x480000;
            .data : { *(.data) }
            .bss : { *(.bss) }
            /DISCARD/ : { *(.comment) *(.note*) }
        }
        """
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            assembly, script = root / "input.S", root / "layout.ld"
            assembly.write_text(source)
            script.write_text(linker_script)
            original, printed = root / "input", root / "printed.S"
            compiler = ["aarch64-linux-gnu-gcc", "-nostdlib", "-no-pie"]
            subprocess.run(compiler + [str(assembly), "-Wl,-T," + str(script),
                           "-o", str(original)], check=True, capture_output=True)
            subprocess.run(["qemu-aarch64", str(original)], check=True, timeout=10)
            result = disassemble(original)
            module = result.ir().modules[0]
            data = next(section for section in module.sections if section.name == ".data")
            bss = next(section for section in module.sections if section.name == ".bss")
            self.assertEqual(data.size, 1)
            self.assertEqual(bss.address, data.address + data.size)
            self.assertEqual(bss.size, 3)
            block = next(module.symbols_named("_start")).referent
            for offset in (0, 4):
                key = block.offset + offset
                self.assertIn(key, block.byte_interval.symbolic_expressions)
                expr = block.byte_interval.symbolic_expressions[key]
                self.assertIsInstance(expr, gtirb.SymAddrConst)
                self.assertIs(expr.symbol.referent.section, data)
                self.assertTrue(expr.symbol.at_end)
                self.assertEqual(expr.offset, 3)
            # The initially zero LO12 in the comparison base is still an
            # address fragment, not a scalar bitmask. Both halves must move.
            for offset in (8, 12):
                expr = block.byte_interval.symbolic_expressions[block.offset + offset]
                self.assertIsInstance(expr, gtirb.SymAddrConst)
                self.assertIs(expr.symbol.referent.section, data)
                self.assertFalse(expr.symbol.at_end)
                self.assertEqual(expr.offset, 0)
            self.assertEqual(asm_print(result.ir_path, printed).returncode, 0)
            for data_address, bss_address in ((0x500000, 0x600000), (0x510fff, 0x630000)):
                rebuilt = root / "rebuilt"
                subprocess.run(compiler + [str(printed), "-o", str(rebuilt),
                               f"-Wl,--section-start=.data={data_address:#x}",
                               f"-Wl,--section-start=.bss={bss_address:#x}"],
                               check=True, capture_output=True)
                subprocess.run(["qemu-aarch64", str(rebuilt)], check=True, timeout=10)

    def test_pointer_difference_keeps_the_preceding_section_end(self):
        source = """
        .text
        .globl _start
        .type _start, %function
        _start:
            adrp x0, range_end
            add x0, x0, :lo12:range_end
            adrp x1, range_begin
            add x1, x1, :lo12:range_begin
            sub x0, x0, x1
            cmp x0, #8
            cset w0, ne
            mov x8, #93
            svc #0
        .size _start, .-_start
        .globl other_address
        .type other_address, %function
        other_address:
            adrp x0, other_begin
            add x0, x0, :lo12:other_begin
            ret
        .size other_address, .-other_address
        .section .first, "aw", %progbits
        .balign 8
        range_begin: .quad 0
        range_end:
        .section .second, "aw", %progbits
        other_begin: .quad 0
        .section .note.GNU-stack, "", %progbits
        """
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            assembly = root / "input.S"
            original = root / "input"
            assembly.write_text(source)
            compiler = ["aarch64-linux-gnu-gcc", "-nostdlib", "-no-pie"]
            subprocess.run(compiler + [str(assembly), "-o", str(original)], check=True)
            result = disassemble(original)
            module = result.ir().modules[0]
            first = next(section for section in module.sections if section.name == ".first")
            second = next(section for section in module.sections if section.name == ".second")
            self.assertEqual(first.address + first.size, second.address)
            for name, section, at_end in (("_start", first, True),
                                          ("other_address", second, False)):
                block = next(module.symbols_named(name)).referent
                for offset in (0, 4):
                    expr = block.byte_interval.symbolic_expressions[block.offset + offset]
                    self.assertIsInstance(expr, gtirb.SymAddrConst)
                    self.assertIs(expr.symbol.referent.section, section)
                    self.assertEqual(expr.symbol.at_end, at_end)
                    self.assertEqual(expr.offset, 0)

            printed = root / "printed.S"
            self.assertEqual(asm_print(result.ir_path, printed).returncode, 0)
            for second_address in (0x300008, 0x410000):
                rebuilt = root / "rebuilt"
                subprocess.run(compiler + [str(printed), "-o", str(rebuilt),
                               "-Wl,--section-start=.first=0x300000",
                               f"-Wl,--section-start=.second={second_address}"], check=True)
                subprocess.run(["qemu-aarch64", str(rebuilt)], check=True, timeout=10)


if __name__ == "__main__":
    unittest.main()
