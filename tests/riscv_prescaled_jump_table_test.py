"""Relative dispatch does not require the byte index's reaching definition."""
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

import gtirb


@unittest.skipUnless(shutil.which("riscv64-linux-gnu-gcc") and shutil.which("qemu-riscv64"),
                     "requires RISC-V compiler and QEMU")
class RiscvPrescaledJumpTableTest(unittest.TestCase):
    def test_incoming_byte_index_and_redefined_base(self):
        for compressed in (False, True):
            for redefine in (False, True):
                with self.subTest(compressed=compressed, redefine=redefine), tempfile.TemporaryDirectory() as directory:
                    root = Path(directory)
                    (root / "input.S").write_text(f'''
.option {'rvc' if compressed else 'norvc'}
.option norelax
.text
.globl _start
.type _start,@function
_start:
    li a0,4
    call dispatch
    li a7,93
    ecall
.size _start,.-_start
.type dispatch,@function
dispatch:
.Lbase:
    auipc a4,%pcrel_hi(table)
    addi a4,a4,%pcrel_lo(.Lbase)
    add a0,a0,a4
    lw a0,0(a0)
    {'mv a4,sp' if redefine else ''}
    add a0,a0,a4
    jr a0
.size dispatch,.-dispatch
.type case0,@function
case0: li a0,7
    ret
.size case0,.-case0
.type case1,@function
case1: li a0,9
    ret
.size case1,.-case1
.section .rodata
.balign 4
.globl table
.type table,@object
table: .word case0-table,case1-table
.size table,.-table
.section .note.GNU-stack,"",@progbits
''')
                    cc = ["riscv64-linux-gnu-gcc", "-march=rv64imac", "-mabi=lp64", "-nostdlib", "-static",
                          "-no-pie", "-Wl,--no-relax,--build-id=none"]
                    subprocess.run(cc + [str(root / "input.S"), "-o", str(root / "input")],
                                   check=True, capture_output=True)
                    subprocess.run(["ddisasm", str(root / "input"), "--ir", str(root / "input.gtirb"), "-j", "1"],
                                   check=True, capture_output=True)
                    module = gtirb.IR.load_protobuf(root / "input.gtirb").modules[0]
                    table = next(module.symbols_named("table")).referent
                    for offset in (0, 4):
                        expr = table.byte_interval.symbolic_expressions.get(table.offset + offset)
                        self.assertEqual(isinstance(expr, gtirb.SymAddrAddr), not redefine)
                    if not redefine:
                        subprocess.run(["gtirb-pprinter", "--ir", str(root / "input.gtirb"), "--asm",
                                        str(root / "output.S"), "--policy", "complete"], check=True, capture_output=True)
                        subprocess.run(cc + [str(root / "output.S"), "-o", str(root / "output"),
                                       "-Wl,--section-start=.text=0x500000,--section-start=.rodata=0x680000"],
                                       check=True, capture_output=True)
                        self.assertEqual(subprocess.run(["qemu-riscv64", str(root / "output")], timeout=10).returncode, 9)


if __name__ == "__main__":
    unittest.main()
