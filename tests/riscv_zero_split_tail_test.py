import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

import gtirb


@unittest.skipUnless(shutil.which("riscv64-linux-gnu-gcc") and shutil.which("qemu-riscv64"),
                     "RV64 compiler and emulator required")
class RiscvZeroSplitTailTest(unittest.TestCase):
    def test_zero_low_fragment_relocates_with_its_high_half(self):
        source = """
        .option norvc
        .option norelax
        .text
        .globl _start
        .type _start,@function
        _start:
            auipc t0,%pcrel_hi(value)
            addi t0,t0,%pcrel_lo(_start)
            lw a0,0(t0)
            li a7,93
            ecall
        .size _start,.-_start
        .data
        .globl value
        .type value,@object
        value: .word 7
        .size value,.-value
        .section .note.GNU-stack,"",@progbits
        """
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            assembly, original = root / "input.S", root / "input"
            assembly.write_text(source)
            compiler = ["riscv64-linux-gnu-gcc", "-march=rv64imac", "-mabi=lp64",
                        "-nostdlib", "-static", "-no-pie", "-Wl,--no-relax,--build-id=none"]
            subprocess.run(compiler + [str(assembly), "-o", str(original),
                           "-Wl,--section-start=.text=0x400000",
                           "-Wl,--section-start=.data=0x480000"], check=True, capture_output=True)
            self.assertEqual(subprocess.run(["qemu-riscv64", str(original)],
                             capture_output=True, timeout=10).returncode, 7)
            ir_path = root / "input.gtirb"
            subprocess.run(["ddisasm", str(original), "--ir", str(ir_path), "-j", "1"],
                           check=True, capture_output=True)
            module = gtirb.IR.load_protobuf(ir_path).modules[0]
            start = next(module.symbols_named("_start")).referent
            expressions = start.byte_interval.symbolic_expressions
            high, low = expressions[start.offset], expressions[start.offset + 4]
            self.assertIsInstance(high, gtirb.SymAddrConst)
            self.assertEqual(high.symbol.name, "value")
            self.assertIsInstance(low, gtirb.SymAddrConst)
            self.assertEqual(low.symbol.referent.address, start.address)
            attributes = gtirb.SymbolicExpression.Attribute
            self.assertTrue({attributes.PCREL, attributes.LO}.issubset(low.attributes))
            printed = root / "printed.S"
            subprocess.run(["gtirb-pprinter", "--ir", str(ir_path), "--asm", str(printed),
                            "--policy", "complete"], check=True, capture_output=True)
            for data_address in (0x601ffc, 0x680040):
                with self.subTest(data_address=data_address):
                    rebuilt = root / "rebuilt"
                    subprocess.run(compiler + [str(printed), "-o", str(rebuilt),
                                   "-Wl,--section-start=.text=0x500000",
                                   f"-Wl,--section-start=.data={data_address:#x}"],
                                   check=True, capture_output=True)
                    self.assertEqual(subprocess.run(["qemu-riscv64", str(rebuilt)],
                                     capture_output=True, timeout=10).returncode, 7)


if __name__ == "__main__":
    unittest.main()
