"""A local function-plus-offset transfer must follow its moved target block."""
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

from gtirb_functions import Function
from gtirb_rewriting import Patch, RewritingContext, patch_constraints

from disassemble_reassemble_check import asm_print, disassemble


class DirectControlFlowRelocationTest(unittest.TestCase):
    def check_moved_call(self, compiler, runner, source):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            assembly, original = root / "input.S", root / "original"
            assembly.write_text(source)
            link = [compiler, "-nostdlib", "-static", "-no-pie"]
            subprocess.run(link + ["-Wl,--emit-relocs", str(assembly), "-o", str(original)],
                           check=True, capture_output=True)
            subprocess.run([*runner, str(original)], check=True, capture_output=True, timeout=10)
            lifted = disassemble(original)
            ir = lifted.ir()
            module = ir.modules[0]

            @patch_constraints()
            def nop(_context):
                return "nop"

            context = RewritingContext(module, Function.build_functions(module))
            for block in tuple(module.code_blocks):
                if block.size:
                    context.insert_at(block, 0, Patch.from_function(nop))
            context.apply()
            moved = root / "moved.gtirb"
            ir.save_protobuf(moved)
            printed = root / "moved.S"
            self.assertEqual(asm_print(moved, printed).returncode, 0)
            subprocess.run(link + [str(printed), "-o", str(original)],
                           check=True, capture_output=True)
            result = subprocess.run([*runner, str(original)], capture_output=True, timeout=10)
            self.assertEqual(result.returncode, 0, result.stderr)

    @unittest.skipUnless(shutil.which("gcc"), "x64 compiler required")
    def test_x64_local_call_with_addend(self):
        self.check_moved_call("gcc", [], """
            .text
            .globl _start
            .type _start,@function
            _start:
                call callee+1
                mov %eax,%edi
                mov $60,%eax
                syscall
            .size _start,.-_start
            .globl callee
            .type callee,@function
            callee:
                int3
                xor %eax,%eax
                ret
            .size callee,.-callee
            .section .note.GNU-stack,"",@progbits
        """)

    @unittest.skipUnless(shutil.which("aarch64-linux-gnu-gcc") and shutil.which("qemu-aarch64"),
                         "AArch64 compiler and QEMU required")
    def test_aarch64_local_call_with_addend(self):
        self.check_moved_call("aarch64-linux-gnu-gcc", ["qemu-aarch64"], """
            .text
            .globl _start
            .type _start,%function
            _start:
                bl callee+4
                mov x8,#93
                svc #0
            .size _start,.-_start
            .globl callee
            .type callee,%function
            callee:
                brk #0
                mov x0,#0
                ret
            .size callee,.-callee
            .section .note.GNU-stack,"",%progbits
        """)
