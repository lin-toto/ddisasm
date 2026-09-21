import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

import gtirb


class RiscvGpReferencesTest(unittest.TestCase):
    disassembly_options = ()

    @unittest.skipUnless(shutil.which("riscv64-linux-gnu-gcc"), "RISC-V compiler required")
    def test_load_store_and_address_operands(self):
        for bits in (32, 64):
            for compressed in (False, True):
                with self.subTest(bits=bits, compressed=compressed), tempfile.TemporaryDirectory() as directory:
                    root = Path(directory)
                    source = root / "gp.S"
                    source.write_text(f"""
.option {'rvc' if compressed else 'norvc'}
.option norelax
.text
.globl _start, probe_load, probe_store, probe_address
.type _start,@function
_start:
    auipc gp,%pcrel_hi(__global_pointer$)
    addi gp,gp,%pcrel_lo(_start)
probe_load:
    lbu t0,-2048(gp)
    addi t0,t0,1
probe_store:
    sb t0,-2048(gp)
probe_address:
    addi a0,gp,-2048
    li a7,93
    ecall
.size _start,.-_start
.section .sdata,"aw",@progbits
.globl value, __global_pointer$
.type value,@object
value: .byte 37
.size value,.-value
.set __global_pointer$,value+2048
""")
                    script = root / "gp.ld"
                    script.write_text("ENTRY(_start)\nSECTIONS { . = 0x10000; "
                                      ".text : { *(.text) } . = 0x30000; .sdata : { *(.sdata) } }\n")
                    binary = root / "gp"
                    subprocess.run([
                        "riscv64-linux-gnu-gcc", f"-march=rv{bits}imac",
                        f"-mabi={'ilp32' if bits == 32 else 'lp64'}", "-nostdlib",
                        "-static", "-no-pie", str(source), f"-Wl,-T,{script},--no-relax",
                        "-o", str(binary),
                    ], check=True, capture_output=True)
                    output = root / "gp.gtirb"
                    subprocess.run([
                        "ddisasm", str(binary), "--ir", str(output), "-j", "1",
                        "--debug-dir", str(root / "debug"), *self.disassembly_options,
                    ], check=True)
                    module = gtirb.IR.load_protobuf(output).modules[0]
                    for name in ("probe_load", "probe_store", "probe_address"):
                        block = next(module.symbols_named(name)).referent
                        self.assertIsInstance(block, gtirb.CodeBlock, name)
                        expression = block.byte_interval.symbolic_expressions.get(block.offset)
                        self.assertIsInstance(expression, gtirb.SymAddrAddr, name)
                        self.assertEqual(expression.symbol1.name, "value", name)
                        self.assertEqual(expression.symbol2.name, "__global_pointer$", name)
                        self.assertEqual((expression.scale, expression.offset), (1, 0), name)


if __name__ == "__main__":
    unittest.main()
