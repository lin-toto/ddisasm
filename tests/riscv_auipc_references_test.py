import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

import gtirb


class RiscvAuipcReferencesTest(unittest.TestCase):
    disassembly_options = ()

    @unittest.skipUnless(shutil.which("riscv64-linux-gnu-gcc"), "RISC-V compiler required")
    def test_rv32_compressed_call_uses_rv32_decoder(self):
        # C.JAL shares its encoding space with RV64 C.ADDIW. Common integer
        # fixtures alone can pass even when only the RV64 loader was built.
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "call.S"
            source.write_text(".option rvc\n.text\n.globl _start,callee\n"
                              ".type _start,@function\n_start:\nc.jal callee\nli a7,93\necall\n"
                              ".size _start,.-_start\n.type callee,@function\n"
                              "callee:\nli a0,7\nret\n.size callee,.-callee\n")
            binary = root / "call"
            subprocess.run(["riscv64-linux-gnu-gcc", "-march=rv32imac", "-mabi=ilp32",
                            "-nostdlib", "-static", "-no-pie", "-Wl,--no-relax,--build-id=none",
                            str(source), "-o", str(binary)], check=True, capture_output=True)
            output = root / "call.gtirb"
            subprocess.run(["ddisasm", str(binary), "--ir", str(output), "-j", "1",
                            *self.disassembly_options], check=True, capture_output=True)
            module = gtirb.IR.load_protobuf(output).modules[0]
            entry = next(module.symbols_named("_start")).referent
            callee = next(module.symbols_named("callee")).referent
            self.assertIsInstance(entry, gtirb.CodeBlock)
            self.assertTrue(any(edge.label.type == gtirb.Edge.Type.Call and edge.target is callee
                                for edge in entry.outgoing_edges))

    @unittest.skipUnless(shutil.which("riscv64-linux-gnu-gcc"), "RISC-V compiler required")
    def test_ambiguous_pairs_have_diagnostics(self):
        for bits in (32, 64):
            for compressed in (False, True):
                for ambiguity in ("none", "addresses", "definitions"):
                    with self.subTest(bits=bits, compressed=compressed, ambiguity=ambiguity), \
                            tempfile.TemporaryDirectory() as directory:
                        root = Path(directory)
                        source = root / "pair.S"
                        if ambiguity == "definitions":
                            consumers = "beqz a0,probe\naddi t0,t0,4\nprobe: lbu a0,0(t0)"
                        else:
                            consumers = f"lbu a0,0(t0)\nlbu a1,{4 if ambiguity == 'addresses' else 0}(t0)"
                        source.write_text(f"""
.option {'rvc' if compressed else 'norvc'}
.option norelax
.text
.balign 4096
.globl _start
.type _start,@function
_start:
    auipc t0,%pcrel_hi(value)
    {consumers}
    li a7,93
    ecall
.size _start,.-_start
.data
.balign 4096
value: .word 7,9
""")
                        binary = root / "pair"
                        subprocess.run([
                            "riscv64-linux-gnu-gcc", f"-march=rv{bits}imac",
                            f"-mabi={'ilp32' if bits == 32 else 'lp64'}", "-nostdlib", "-static",
                            "-no-pie", "-Wl,--no-relax,--build-id=none", str(source), "-o", str(binary),
                        ], check=True, capture_output=True)
                        output = root / "pair.gtirb"
                        result = subprocess.run([
                            "ddisasm", str(binary), "--ir", str(output), "-j", "1",
                            *self.disassembly_options,
                        ], check=True, capture_output=True, text=True)
                        module = gtirb.IR.load_protobuf(output).modules[0]
                        diagnostics = module.aux_data["riscvUnresolvedPcrelReferences"].data
                        block = next(module.symbols_named("_start")).referent
                        high = block.byte_interval.symbolic_expressions.get(block.offset)
                        if ambiguity != "none":
                            self.assertIsNone(high)
                            self.assertIn("unresolved RISC-V AUIPC pair", result.stderr)
                            reason = ("multiple completed addresses" if ambiguity == "addresses"
                                      else "multiple reaching definitions")
                            self.assertIn(reason, result.stderr)
                            self.assertIn(f"0x{block.address:x}", result.stderr)
                            self.assertTrue(diagnostics)
                            self.assertTrue(all(high == block.address and low > high and why == reason
                                                for high, low, why in diagnostics))
                        else:
                            self.assertIsInstance(high, gtirb.SymAddrConst)
                            self.assertNotIn("unresolved RISC-V AUIPC pair", result.stderr)
                            self.assertEqual(diagnostics, [])

    @unittest.skipUnless(shutil.which("riscv64-linux-gnu-gcc"), "RISC-V compiler required")
    def test_plt_load_names_instruction_not_external_symbol(self):
        for bits in (32, 64):
            with self.subTest(bits=bits), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                flags = ["riscv64-linux-gnu-gcc", f"-march=rv{bits}imac",
                         f"-mabi={'ilp32' if bits == 32 else 'lp64'}", "-nostdlib"]
                library = root / "library.S"
                library.write_text(".text\n.globl value\n.type value,@function\nvalue: ret\n")
                subprocess.run([*flags, "-shared", "-fPIC", str(library),
                                "-o", str(root / "libvalue.so")], check=True, capture_output=True)
                source = root / "main.S"
                source.write_text(".text\n.globl _start\n.type _start,@function\n_start:\n"
                                  "call value@plt\nli a7,93\necall\n")
                binary = root / "main"
                subprocess.run([*flags, "-no-pie", "-Wl,--no-relax", str(source),
                                f"-L{root}", "-lvalue", "-o", str(binary)],
                               check=True, capture_output=True)
                output = root / "main.gtirb"
                subprocess.run(["ddisasm", str(binary), "--ir", str(output), "-j", "1",
                                "--debug-dir", str(root / "debug"), *self.disassembly_options],
                               check=True, capture_output=True)
                module = gtirb.IR.load_protobuf(output).modules[0]
                attrs = gtirb.SymbolicExpression.Attribute
                forwarding = module.aux_data["symbolForwarding"].data
                self.assertTrue(any(symbol.name == "value" for symbol in forwarding.values()))
                pairs = 0
                for interval in next(s for s in module.sections if s.name == ".plt").byte_intervals:
                    for expression in interval.symbolic_expressions.values():
                        if not {attrs.LO, attrs.PCREL}.issubset(expression.attributes):
                            continue
                        pairs += 1
                        self.assertIsInstance(expression, gtirb.SymAddrConst)
                        self.assertEqual(expression.offset, 0)
                        anchor = expression.symbol.referent
                        self.assertIsInstance(anchor, gtirb.CodeBlock)
                        self.assertEqual(anchor.byte_interval.contents[anchor.offset] & 0x7f, 0x17)
                        self.assertNotIn(expression.symbol, forwarding)
                self.assertGreater(pairs, 0)

    @unittest.skipUnless(shutil.which("riscv64-linux-gnu-gcc"), "RISC-V compiler required")
    def test_nonadjacent_consumers_follow_reaching_definition(self):
        for bits in (32, 64):
            for compressed in (False, True):
                for operation in ("lbu a0", "sb t1", "addi a0"):
                    with self.subTest(bits=bits, compressed=compressed, operation=operation):
                        instruction = (f"{operation},t0,%pcrel_lo(_start)" if operation == "addi a0"
                                       else f"{operation},%pcrel_lo(_start)(t0)")
                        module = self._disassemble(bits, compressed, instruction)
                        high_block = next(module.symbols_named("_start")).referent
                        low_block = next(module.symbols_named("probe")).referent
                        high = high_block.byte_interval.symbolic_expressions.get(high_block.offset)
                        low = low_block.byte_interval.symbolic_expressions.get(low_block.offset)
                        self.assertIsInstance(high, gtirb.SymAddrConst)
                        self.assertIsInstance(low, gtirb.SymAddrConst)
                        self.assertEqual(high.symbol.name, "value")
                        self.assertEqual(low.symbol.referent.address, high_block.address)
                        attrs = gtirb.SymbolicExpression.Attribute
                        self.assertTrue({attrs.HI, attrs.PCREL}.issubset(high.attributes))
                        self.assertTrue({attrs.LO, attrs.PCREL}.issubset(low.attributes))

    def _disassemble(self, bits, compressed, instruction):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "pair.S"
            source.write_text(f"""
.option {'rvc' if compressed else 'norvc'}
.option norelax
.text
.globl _start, probe
.type _start,@function
_start:
    auipc t0,%pcrel_hi(value)
    j probe
decoy:
    auipc t0,%pcrel_hi(other)
    addi t0,t0,%pcrel_lo(decoy)
    j done
probe:
    {instruction}
    li a7,93
    ecall
done:
    li a0,99
    li a7,93
    ecall
.size _start,.-_start
.data
value: .byte 7
other: .byte 99
""")
            binary = root / "pair"
            subprocess.run([
                "riscv64-linux-gnu-gcc", f"-march=rv{bits}imac",
                f"-mabi={'ilp32' if bits == 32 else 'lp64'}", "-nostdlib", "-static",
                "-no-pie", "-Wl,--no-relax,--build-id=none", str(source), "-o", str(binary),
            ], check=True, capture_output=True)
            output = root / "pair.gtirb"
            subprocess.run([
                "ddisasm", str(binary), "--ir", str(output), "-j", "1",
                "--debug-dir", str(root / "debug"), *self.disassembly_options,
            ], check=True, capture_output=True)
            return gtirb.IR.load_protobuf(output).modules[0]


if __name__ == "__main__":
    unittest.main()
