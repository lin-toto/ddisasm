"""RELATIVE relocations in real GOT slots must survive binary relayout."""
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

import gtirb
from gtirb_functions import Function
from gtirb_rewriting import Patch, RewritingContext, patch_constraints
from disassemble_reassemble_check import asm_print, disassemble


@unittest.skipUnless(shutil.which("aarch64-linux-gnu-gcc") and shutil.which("qemu-aarch64"),
                     "AArch64 compiler and QEMU required")
class Arm64RelativeGotTest(unittest.TestCase):
    def test_relative_got_and_ordinary_relative_data_remain_distinct(self):
        source = """
            .text
            .globl via_got
            .type via_got, %function
            via_got:
            got_page: adrp x0, :got:hidden_value
            got_load: ldr x0, [x0, :got_lo12:hidden_value]
                ldr w0, [x0]
                ret
            .size via_got, .-via_got
            .globl via_data
            .type via_data, %function
            via_data:
            data_page: adrp x0, pointer_slot
            data_load: ldr x0, [x0, :lo12:pointer_slot]
                ldr w0, [x0]
                ret
            .size via_data, .-via_data
            .globl via_shared_page
            .type via_shared_page, %function
            via_shared_page:
            shared_page: adrp x0, pointer_slot
            shared_add: add x1, x0, :lo12:pointer_slot
            shared_load: ldr x0, [x0, :lo12:pointer_slot]
                ldr x1, [x1]
                cmp x0, x1
                b.ne bad
                ldr w0, [x0]
                ret
            bad: mov w0, #1
                ret
            .size via_shared_page, .-via_shared_page
            .data
            .balign 8
            .globl hidden_value
            .hidden hidden_value
            .type hidden_value, %object
            hidden_value: .quad 37
            .size hidden_value, 8
            .type pointer_slot, %object
            pointer_slot: .quad hidden_value
            .size pointer_slot, 8
            .section .note.GNU-stack, "", %progbits
        """
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            assembly, original = root / "input.S", root / "libvalues.so"
            assembly.write_text(source)
            compiler = ["aarch64-linux-gnu-gcc", "-nostdlib", "-shared",
                        "-Wl,-soname,libvalues.so"]
            subprocess.run(compiler + [str(assembly), "-o", str(original)],
                           check=True, capture_output=True)
            relocations = subprocess.check_output(
                ["aarch64-linux-gnu-readelf", "-rW", str(original)], text=True)
            self.assertGreaterEqual(relocations.count("R_AARCH64_RELATIVE"), 2, relocations)
            runner_source, runner = root / "main.c", root / "main"
            runner_source.write_text("""
                int via_got(void), via_data(void), via_shared_page(void);
                int main(void) {
                    return via_got() != 37 || via_data() != 37 || via_shared_page() != 37;
                }
            """)
            subprocess.run(["aarch64-linux-gnu-gcc", str(runner_source), "-L" + str(root),
                            "-Wl,-rpath,$ORIGIN", "-lvalues", "-o", str(runner)],
                           check=True, capture_output=True)
            command = ["qemu-aarch64", "-L", "/usr/aarch64-linux-gnu", str(runner)]
            subprocess.run(command, check=True, capture_output=True, timeout=10)
            result = disassemble(original)
            ir = result.ir()
            module = ir.modules[0]

            def attributes(name):
                symbol = next(module.symbols_named(name))
                block = symbol.referent
                address = block.address + (block.size if symbol.at_end else 0)
                return block.byte_interval.symbolic_expressions[
                    address - block.byte_interval.address].attributes

            attribute = gtirb.SymbolicExpression.Attribute
            self.assertIn(attribute.GOT, attributes("got_page"))
            self.assertTrue({attribute.GOT, attribute.LO12} <= attributes("got_load"))
            for name in ("data_page", "data_load", "shared_page", "shared_add", "shared_load"):
                self.assertNotIn(attribute.GOT, attributes(name), name)
            for name in ("data_load", "shared_add", "shared_load"):
                self.assertIn(attribute.LO12, attributes(name), name)
            # Move code as well as data so stale instruction-side addresses
            # cannot remain accidentally correct in an ordinary round trip.
            @patch_constraints()
            def nop(_context):
                return "nop\n" * 9

            context = RewritingContext(module, Function.build_functions(module))
            for block in tuple(module.code_blocks):
                if block.size:
                    context.insert_at(block, 0, Patch.from_function(nop))
            context.apply()
            moved_ir = root / "moved.gtirb"
            ir.save_protobuf(moved_ir)
            printed = root / "printed.S"
            self.assertEqual(asm_print(moved_ir, printed).returncode, 0)
            text = printed.read_text()
            for gap in (0, 272, 8192):
                with self.subTest(gap=gap):
                    prefix = ".zero %d\n" % gap if gap else "// unchanged data placement\n"
                    moved = text.replace("hidden_value:", prefix + "hidden_value:")
                    self.assertNotEqual(moved, text)
                    printed.write_text(moved)
                    rebuilt = subprocess.run(compiler + [str(printed), "-Wa,--fatal-warnings",
                                                         "-o", str(original)], capture_output=True)
                    self.assertEqual(rebuilt.returncode, 0, rebuilt.stderr.decode())
                    executed = subprocess.run(command, capture_output=True, timeout=10)
                    self.assertEqual(executed.returncode, 0, executed.stderr)


if __name__ == "__main__":
    unittest.main()
