"""A linker-erratum page ADR must survive code and target movement."""
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

from gtirb_functions import Function
from gtirb_rewriting import Patch, RewritingContext, patch_constraints
from disassemble_reassemble_check import asm_print, disassemble


@unittest.skipUnless(shutil.which("aarch64-linux-gnu-gcc") and shutil.which("qemu-aarch64"),
                     "AArch64 compiler and QEMU required")
class Arm64RelaxedPageTest(unittest.TestCase):
    def test_erratum_page_adr_survives_independent_movement(self):
        for page_offset in (0xff8, 0xffc):
            with self.subTest(page_offset=page_offset), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                source, original = root / "input.S", root / "original"
                source.write_text("""
                    .text
                    .globl _start
                    .type _start,%function
                    _start:
                        adr x1, target-0xfc0
                        ldr w1, [x1, #0xfc0]
                        cmp w1, #37
                        cset w0, ne
                        mov x8, #93
                        svc #0
                    .size _start, .-_start
                    .data
                    .globl target
                    .type target,%object
                    target: .word 37
                    .size target, 4
                    .section .note.GNU-stack,"",%progbits
                """)
                link = ["aarch64-linux-gnu-gcc", "-nostdlib", "-static", "-no-pie",
                        "-Wl,--build-id=none"]
                subprocess.run(link + [str(source), "-o", str(original),
                                       f"-Wl,-Ttext={0x400000+page_offset:#x}",
                                       "-Wl,-Tdata=0x480fc0"], check=True, capture_output=True)
                subprocess.run(["qemu-aarch64", str(original)], check=True,
                               capture_output=True, timeout=10)
                ir = disassemble(original).ir()
                module = ir.modules[0]

                @patch_constraints()
                def nop(_context):
                    return "nop\n" * 5

                context = RewritingContext(module, Function.build_functions(module))
                for block in tuple(module.code_blocks):
                    if block.size:
                        context.insert_at(block, 0, Patch.from_function(nop))
                context.apply()
                moved, printed = root / "moved.gtirb", root / "moved.S"
                ir.save_protobuf(moved)
                self.assertEqual(asm_print(moved, printed).returncode, 0)
                for data_address in (0x680100, 0x690008):
                    executable = root / "rewritten"
                    subprocess.run(link + [str(printed), "-o", str(executable),
                                           "-Wl,-Ttext=0x500000",
                                           f"-Wl,-Tdata={data_address:#x}"],
                                   check=True, capture_output=True)
                    ran = subprocess.run(["qemu-aarch64", str(executable)],
                                         capture_output=True, timeout=10)
                    self.assertEqual(ran.returncode, 0, ran.stderr)
