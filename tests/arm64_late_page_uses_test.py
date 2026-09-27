"""Late-discovered switch edges must not leave stale page-offset operands."""
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
class Arm64LatePageUsesTest(unittest.TestCase):
    def test_hoisted_page_across_unbounded_switch(self):
        source = """
            .text
            .globl _start
            .type _start,%function
            _start:
                ldr w0,[sp]
                sub w0,w0,#1
                bl pick
                cmp w0,#37
                cset w0,ne
                mov x8,#93
                svc #0
            .size _start,.-_start
            .type pick,%function
            pick:
                stp x22,x30,[sp,#-16]!
                adrp x22,target
                add x4,x22,:lo12:target
                ldr w4,[x4]
                adrp x1,table
                add x1,x1,:lo12:table
                ldrh w2,[x1,w0,uxtw #1]
                adr x3,case0
                add x2,x3,w2,sxth #2
                br x2
            case0:
                add x22,x22,:lo12:target
                b done
            case1:
                add x22,x22,:lo12:target
                b done
            case2:
                add x22,x22,:lo12:target
            done:
                ldr w0,[x22]
                ldp x22,x30,[sp],#16
                ret
            .size pick,.-pick
            .section .rodata,"a",%progbits
            .balign 2
            .type table,%object
            table:
                .hword (case0-case0)/4,(case1-case0)/4,(case2-case0)/4
            .size table,.-table
            .data
            .balign 8
                .zero 64
            .type target,%object
            target: .word 37
            .size target,4
            .section .note.GNU-stack,"",%progbits
        """
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            assembly, original = root / "input.S", root / "original"
            assembly.write_text(source)
            compiler = ["aarch64-linux-gnu-gcc", "-nostdlib", "-static", "-no-pie"]
            subprocess.run(compiler + [str(assembly), "-o", str(original)],
                           check=True, capture_output=True)
            command = ["qemu-aarch64", str(original)]
            for index in range(3):
                subprocess.run(command + ["case"] * index, check=True,
                               capture_output=True, timeout=10)
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
            text = printed.read_text()
            self.assertIn("target:", text)
            # Move the target independently as well: unchanged low address
            # bits must not make a raw offset accidentally pass the test.
            printed.write_text(text.replace("target:", ".zero 272\ntarget:"))
            subprocess.run(compiler + [str(printed), "-o", str(original)],
                           check=True, capture_output=True)
            for index in range(3):
                executed = subprocess.run(command + ["case"] * index,
                                          capture_output=True, timeout=10)
                self.assertEqual(executed.returncode, 0, (index, executed.stderr))
