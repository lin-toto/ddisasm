"""ELF SHN_ABS values must not acquire coincident block referents."""

import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

import gtirb


class AbsoluteSymbolsTest(unittest.TestCase):
    def check_absolute_values(self, compiler, body, flags=()):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            asm = root / "absolute.S"
            asm.write_text(".text\n.globl _start\n.type _start,@function\n"
                           "_start:\n" + body + "\n.size _start,.-_start\n"
                           '.section .rodata,"a"\n.globl ordinary_data\n'
                           "ordinary_data:\n.quad 37\n")
            script = root / "absolute.ld"
            script.write_text("""ENTRY(_start)
SECTIONS {
  . = 0x10000;
  .text : { *(.text) }
  abs_code = ABSOLUTE(ADDR(.text));
  . = 0x20000;
  .rodata : { *(.rodata) }
  abs_data = ABSOLUTE(ADDR(.rodata));
  abs_end = ABSOLUTE(ADDR(.rodata) + SIZEOF(.rodata));
  abs_zero = 0;
}
""")
            binary = root / "absolute"
            subprocess.run([compiler, *flags, "-nostdlib", "-static", "-no-pie",
                            str(asm), "-Wl,-T," + str(script), "-o", str(binary)],
                           check=True, capture_output=True)
            ir_file = root / "absolute.gtirb"
            proc = subprocess.run([os.environ.get("DDISASM", "ddisasm"), str(binary),
                                   "--ir", str(ir_file), "-j", "1"],
                                  capture_output=True, text=True)
            self.assertEqual(proc.returncode, 0, proc.stderr)
            module = gtirb.IR.load_protobuf(ir_file).modules[0]
            start_block = next(module.symbols_named("_start")).referent
            code_address = start_block.byte_interval.address + start_block.offset
            for name, value in (("abs_code", 0x10000), ("abs_data", 0x20000),
                                ("abs_end", 0x20008), ("abs_zero", 0)):
                with self.subTest(symbol=name):
                    if name == "abs_code":
                        value = code_address
                    symbol = next(module.symbols_named(name))
                    self.assertEqual(module.aux_data["elfSymbolInfo"].data[symbol][4],
                                     0xfff1)
                    self.assertIsNone(symbol.referent, name)
                    self.assertEqual(symbol.value, value, name)
                    self.assertFalse(symbol.at_end, name)
            self.assertIsInstance(next(module.symbols_named("_start")).referent,
                                  gtirb.CodeBlock)
            self.assertIsInstance(next(module.symbols_named("ordinary_data")).referent,
                                  gtirb.DataBlock)

    @unittest.skipUnless(shutil.which("gcc"), "native compiler required")
    def test_x64(self):
        self.check_absolute_values("gcc", "mov $60,%eax\nxor %edi,%edi\nsyscall")

    @unittest.skipUnless(shutil.which("aarch64-linux-gnu-gcc"), "AArch64 compiler required")
    def test_aarch64(self):
        self.check_absolute_values("aarch64-linux-gnu-gcc", "mov x0,#0\nmov x8,#93\nsvc #0")

    @unittest.skipUnless(shutil.which("riscv64-linux-gnu-gcc"), "RISC-V compiler required")
    def test_riscv64(self):
        self.check_absolute_values("riscv64-linux-gnu-gcc", ".option norelax\nli a0,0\nli a7,93\necall",
                                   ("-Wl,--no-relax",))


if __name__ == "__main__":
    unittest.main()
