"""Copies of an indexed table address must survive disassembly and relayout."""
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

import gtirb


@unittest.skipUnless(shutil.which("riscv64-linux-gnu-gcc") and shutil.which("qemu-riscv64"),
                     "RISC-V compiler and QEMU required")
class RiscvCopiedJumpTableTest(unittest.TestCase):
    def test_copied_address_and_overwrite(self):
        for compressed, overwrite in ((False, False), (True, False), (True, True)):
            with self.subTest(compressed=compressed, overwrite=overwrite), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                (root / "input.S").write_text(f'''
.option {'rvc' if compressed else 'norvc'}
.option norelax
.text
.globl _start
.type _start,@function
_start:
    li a0,2
    call dispatch
    li a7,93
    ecall
.size _start,.-_start
.type dispatch,@function
dispatch:
.Lbase:
    auipc t1,%pcrel_hi(table)
    addi t1,t1,%pcrel_lo(.Lbase)
    slli a3,a0,2
    add t4,a3,t1
    mv a3,t4
    mv t6,a3
    {'mv t6,sp' if overwrite else ''}
    lw a3,0(t6)
    add a3,a3,t1
    jr a3
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
table: .long case0-table,case1-table,case0-table
.size table,.-table
.section .note.GNU-stack,"",@progbits
''')
                cc = ["riscv64-linux-gnu-gcc", "-march=rv64imac", "-mabi=lp64", "-nostdlib",
                      "-static", "-no-pie", "-Wl,--no-relax,--build-id=none"]
                subprocess.run(cc + [str(root / "input.S"), "-o", str(root / "input")],
                               check=True, capture_output=True, timeout=30)
                subprocess.run(["ddisasm", str(root / "input"), "--ir", str(root / "input.gtirb"), "-j", "1"],
                               check=True, capture_output=True, timeout=60)
                module = gtirb.IR.load_protobuf(root / "input.gtirb").modules[0]
                table = next(module.symbols_named("table")).referent
                for offset in (0, 4, 8):
                    expr = table.byte_interval.symbolic_expressions.get(table.offset + offset)
                    self.assertEqual(isinstance(expr, gtirb.SymAddrAddr), not overwrite)
                if not overwrite:
                    subprocess.run(["gtirb-pprinter", "--ir", str(root / "input.gtirb"), "--asm",
                                    str(root / "output.S"), "--policy", "complete"],
                                   check=True, capture_output=True, timeout=30)
                    subprocess.run(cc + [str(root / "output.S"), "-o", str(root / "output"),
                                   "-Wl,--section-start=.text=0x500000,--section-start=.rodata=0x680000"],
                                   check=True, capture_output=True, timeout=30)
                    self.assertEqual(subprocess.run(["qemu-riscv64", str(root / "output")],
                                     capture_output=True, timeout=10).returncode, 7)


if __name__ == "__main__":
    unittest.main()
