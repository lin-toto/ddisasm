"""A retained relocation to a static function that shares its address with $x."""
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

import gtirb


@unittest.skipUnless(shutil.which("aarch64-linux-gnu-gcc") and shutil.which("qemu-aarch64"),
                     "AArch64 compiler and QEMU required")
class Arm64StaticFunctionReferenceTest(unittest.TestCase):
    def test_table_word_names_the_function_not_the_mapping_symbol(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source, original = root / "input.S", root / "original"
            # f0 is local and first in .text, so GAS refers to it as .text+0
            # and emits $x at the same address.
            source.write_text("""
                .text
                .type f0, %function
            f0:
                mov x0, #0
                ret
                .size f0, .-f0
                .globl _start
                .type _start, %function
            _start:
                adrp x1, table
                ldr x1, [x1, :lo12:table]
                blr x1
                mov x8, #93
                svc #0
                .size _start, .-_start
                .data
                .p2align 3
            table:
                .quad f0
            """)
            compiler = ["aarch64-linux-gnu-gcc", "-nostdlib", "-static", "-no-pie"]
            subprocess.run(compiler + ["-Wl,--emit-relocs", str(source), "-o", str(original)],
                           check=True, capture_output=True)
            symbols = subprocess.check_output(["readelf", "-Ws", str(original)], text=True)
            self.assertRegex(symbols, r"\$x\b")
            self.assertRegex(subprocess.check_output(["readelf", "-Wr", str(original)], text=True),
                             r"R_AARCH64_ABS64\s+[0-9a-f]+\s+\.text \+ 0")
            lifted = root / "lifted.gtirb"
            subprocess.run(["ddisasm", str(original), "--ir", str(lifted), "-j", "1"],
                           check=True, capture_output=True)
            module = gtirb.IR.load_protobuf(lifted).modules[0]
            table, = (symbol for symbol in module.symbols if symbol.name == "table")
            expression = table.referent.byte_interval.symbolic_expressions[table.referent.offset]
            self.assertEqual(expression.symbol.name, "f0")
            printed, rewritten = root / "lifted.S", root / "rewritten"
            subprocess.run(["gtirb-pprinter", "--ir", str(lifted), "--asm", str(printed),
                            "--policy", "complete", "--shared", "no"], check=True, capture_output=True)
            subprocess.run(compiler + [str(printed), "-o", str(rewritten)], check=True, capture_output=True)
            result = subprocess.run(["qemu-aarch64", str(rewritten)], capture_output=True, timeout=10)
            self.assertEqual(result.returncode, 0, result.stderr)


if __name__ == "__main__":
    unittest.main()
