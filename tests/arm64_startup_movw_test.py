"""A crt address materialization must preserve zero upper MOVK fragments."""
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

from gtirb_functions import Function
from gtirb_rewriting import Patch, RewritingContext, patch_constraints

from disassemble_reassemble_check import asm_print, disassemble


SOURCE = """
    .text
    .globl _start
    .type _start, %function
    _start:
        movz x0, #:abs_g0_nc:main
        movk x0, #:abs_g1_nc:main
        movk x0, #:abs_g2_nc:main
        movk x0, #:abs_g3:main
        movz x3, #:abs_g0_nc:__libc_csu_init
        movk x3, #:abs_g1_nc:__libc_csu_init
        movk x3, #:abs_g2_nc:__libc_csu_init
        movk x3, #:abs_g3:__libc_csu_init
        movz x4, #:abs_g0_nc:__libc_csu_fini
        movk x4, #:abs_g1_nc:__libc_csu_fini
        movk x4, #:abs_g2_nc:__libc_csu_fini
        movk x4, #:abs_g3:__libc_csu_fini
        bl boot
        mov x8, #93
        svc #0
    .size _start, .-_start
    .type boot, %function
    boot:
        stp x19, x20, [sp, #-32]!
        str x30, [sp, #16]
        mov x19, x0
        mov x20, x4
        blr x3
        cmp w0, #17
        b.ne bad
        blr x19
        cmp w0, #29
        b.ne bad
        blr x20
        cmp w0, #43
        b.ne bad
        mov w0, #0
        b done
    bad:
        mov w0, #1
    done:
        ldr x30, [sp, #16]
        ldp x19, x20, [sp], #32
        ret
    .size boot, .-boot
    .globl __libc_csu_init
    .type __libc_csu_init, %function
    __libc_csu_init:
        mov w0, #17
        ret
    .size __libc_csu_init, .-__libc_csu_init
    .globl main
    .type main, %function
    main:
        mov w0, #29
        ret
    .size main, .-main
    .globl __libc_csu_fini
    .type __libc_csu_fini, %function
    __libc_csu_fini:
        mov w0, #43
        ret
    .size __libc_csu_fini, .-__libc_csu_fini
    .section .note.GNU-stack, "", %progbits
"""


@unittest.skipUnless(shutil.which("aarch64-linux-gnu-gcc") and shutil.which("qemu-aarch64"),
                     "AArch64 compiler and QEMU required")
class Arm64StartupMovwTest(unittest.TestCase):
    def test_zero_upper_address_fragments_follow_moved_crt_entries(self):
        # The original symbols are below 4 GiB. NOPs move all three above it,
        # so retaining a raw zero G2 piece is an observable invalid call, even
        # though an ordinary low-address round trip happens to work.
        for relocations in (False, True):
            with self.subTest(emit_relocations=relocations), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                source, binary = root / "input.S", root / "original"
                source.write_text(SOURCE)
                link = ["aarch64-linux-gnu-gcc", "-nostdlib", "-static", "-no-pie",
                        "-Wl,--build-id=none", "-Wl,-Ttext=0xffffff00"]
                flags = ["-Wl,--emit-relocs"] if relocations else []
                subprocess.run(link + flags + [str(source), "-o", str(binary)],
                               check=True, capture_output=True)
                subprocess.run(["qemu-aarch64", str(binary)],
                               check=True, capture_output=True, timeout=10)
                ir = disassemble(binary).ir()
                module = ir.modules[0]

                @patch_constraints()
                def nop(_context):
                    return "nop\n" * 9

                context = RewritingContext(module, Function.build_functions(module))
                for block in tuple(module.code_blocks):
                    if block.size:
                        context.insert_at(block, 0, Patch.from_function(nop))
                context.apply()
                moved = root / "moved.gtirb"
                ir.save_protobuf(moved)
                printed, executable = root / "moved.S", root / "moved"
                self.assertEqual(asm_print(moved, printed).returncode, 0)
                subprocess.run(link + [str(printed), "-Wa,--fatal-warnings", "-o", str(executable)],
                               check=True, capture_output=True)
                executed = subprocess.run(["qemu-aarch64", str(executable)],
                                          capture_output=True, timeout=10)
                self.assertEqual(executed.returncode, 0, executed.stderr)


if __name__ == "__main__":
    unittest.main()

