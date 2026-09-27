"""Section-relative operands must survive movement without applying addends twice."""
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

import gtirb
from gtirb_functions import Function
from gtirb_rewriting import Patch, RewritingContext, patch_constraints


@unittest.skipUnless(shutil.which("aarch64-linux-gnu-gcc") and shutil.which("qemu-aarch64"),
                     "AArch64 compiler and QEMU required")
class Arm64SectionRelocationTest(unittest.TestCase):
    def check_nop_execution(self, source, relocation_kinds=()):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            assembly, original = root / "input.S", root / "original"
            assembly.write_text(source)
            compiler = ["aarch64-linux-gnu-gcc", "-nostdlib", "-static", "-no-pie"]
            subprocess.run(compiler + ["-Wl,--emit-relocs", str(assembly), "-o", str(original)],
                           check=True, capture_output=True)
            relocations = subprocess.check_output(["readelf", "-Wr", str(original)], text=True)
            for kind in relocation_kinds:
                self.assertRegex(relocations, r"R_AARCH64_" + kind + r"\s+[0-9a-f]+\s+\.text \+")
            subprocess.run(["qemu-aarch64", str(original)], check=True, capture_output=True, timeout=10)
            lifted = root / "lifted.gtirb"
            subprocess.run(["ddisasm", str(original), "--ir", str(lifted), "-j", "1"],
                           check=True, capture_output=True)
            ir = gtirb.IR.load_protobuf(lifted)
            module = ir.modules[0]

            @patch_constraints()
            def nop(_context):
                return "nop"

            context = RewritingContext(module, Function.build_functions(module))
            for block in tuple(module.code_blocks):
                if block.size:
                    context.insert_at(block, 0, Patch.from_function(nop))
            context.apply()
            moved_ir, printed, rewritten = root / "moved.gtirb", root / "moved.S", root / "rewritten"
            ir.save_protobuf(moved_ir)
            subprocess.run(["gtirb-pprinter", "--ir", str(moved_ir), "--asm", str(printed),
                            "--policy", "complete", "--shared", "no"], check=True, capture_output=True)
            subprocess.run(compiler + [str(printed), "-Wl,--section-start=.text=0x500000",
                                       "-Wl,--section-start=.data=0x680000", "-o", str(rewritten)],
                           check=True, capture_output=True)
            actual = subprocess.run(["qemu-aarch64", str(rewritten)], capture_output=True, timeout=10)
            self.assertEqual(actual.returncode, 0, actual.stderr)

    def test_page_and_low_section_addends_survive_nop_insertion(self):
        self.check_nop_execution("""
            .text
            .globl _start
            .type _start, %function
        _start:
            adrp x1, .data+24
            add x1, x1, :lo12:.data+24
            ldr w2, [x1]
            cmp w2, #37
            b.ne bad
            adrp x1, .data+8216
            ldr w2, [x1, :lo12:.data+8216]
            cmp w2, #41
            b.ne bad
            adrp x1, far_value-8192
            add x1, x1, :lo12:far_value-8192
            ldr w2, [x1]
            cmp w2, #37
            b.ne bad
            mov x0, #0
            b done
        bad: mov x0, #1
        done:
            mov x8, #93
            svc #0
            .size _start, .-_start
            .data
            .balign 16
            .zero 24
        value: .word 37
            .zero 8188
            .globl far_value
            .type far_value, %object
        far_value: .word 41
            .size far_value, 4
            .section .note.GNU-stack, "", %progbits
        """)

    def test_section_calls_jumps_and_absolute_pointer_survive_nops(self):
        self.check_nop_execution("""
            .text
            .globl _start
            .type _start, %function
        _start:
            bl .text.callee+16
            cmp w0, #37
            b.ne bad
            b .text.tail+16
        bad:
            mov x0, #1
            mov x8, #93
            svc #0
            .size _start, .-_start
            .section .text.callee,"ax",%progbits
            .rept 4
            nop
            .endr
            .type callee,%function
        callee:
            mov w0, #37
            ret
            .size callee,.-callee
            .section .text.tail,"ax",%progbits
            .rept 4
            nop
            .endr
            .type tail,%function
        tail:
            adrp x1, .data+16
            ldr x1, [x1,:lo12:.data+16]
            blr x1
            cmp w0, #37
            b.ne bad
            mov x0, #0
            mov x8, #93
            svc #0
            .size tail,.-tail
            .data
            .zero 16
            .xword .text.callee+16
            .section .note.GNU-stack,"",%progbits
        """, ("CALL26", "JUMP26", "ABS64"))


if __name__ == "__main__":
    unittest.main()
