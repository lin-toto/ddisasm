"""Absolute OBJECT values must not defeat overlapping code candidates."""

from contextlib import contextmanager
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import tempfile
import unittest

import gtirb


@unittest.skipUnless(shutil.which("riscv64-linux-gnu-gcc") and shutil.which("readelf"),
                     "RV64 compiler and ELF inspector required")
class AbsoluteObjectOverlapTest(unittest.TestCase):
    @contextmanager
    def fixture_directory(self, label):
        retained = os.environ.get("DDISASM_TEST_ARTIFACT_DIR")
        if retained:
            root = Path(retained) / label
            root.mkdir(parents=True, exist_ok=False)
            yield root
        else:
            with tempfile.TemporaryDirectory() as directory:
                yield Path(directory)

    def run_checked(self, root, label, command, timeout):
        (root / f"{label}.command.json").write_text(json.dumps(command, indent=2) + "\n")
        result = subprocess.run(command, capture_output=True, text=True, timeout=timeout)
        (root / f"{label}.stdout").write_text(result.stdout)
        (root / f"{label}.stderr").write_text(result.stderr)
        result.check_returncode()
        return result

    def lift_collision(self, root, absolute, object_size):
        # Same bytes/value/type/size in both controls. Only st_shndx differs.
        # The value is halfway through a four-byte AUIPC, as in Brotli common.
        value = "0x10002" if absolute else "_start+2"
        source, binary = root / "input.S", root / "input"
        source.write_text(f""".file "collision.S"
        .option norvc
        .option norelax
        .text
        .globl _start
        .type _start,@function
        _start:
            auipc t0,%pcrel_hi(target)
            addi t0,t0,%pcrel_lo(_start)
            ld a0,0(t0)
            li a7,93
            ecall
        .size _start,.-_start
        .globl collision_object
        .set collision_object,{value}
        .type collision_object,@object
        .size collision_object,{object_size}
        .section .rodata,"a",@progbits
        .globl target
        .type target,@object
        target: .quad 7
        .size target,8
        .section .note.GNU-stack,"",@progbits
        """)
        self.run_checked(root, "compile", [
            "riscv64-linux-gnu-gcc", "-march=rv64gc", "-mabi=lp64d",
            "-nostdlib", "-static", "-no-pie", "-Wl,--no-relax,--build-id=none",
            "-Wl,--section-start=.text=0x10000",
            "-Wl,--section-start=.rodata=0x20000", str(source), "-o", str(binary),
        ], 30)
        symbols = self.run_checked(root, "elf-symbols", ["readelf", "-sW", str(binary)], 10).stdout
        self.assertRegex(symbols, re.compile(
            r"^\s*\d+:\s+0000000000000000\s+0\s+FILE\s+LOCAL\s+DEFAULT\s+ABS\s+collision\.S$",
            re.MULTILINE))
        ndx = "ABS" if absolute else r"\d+"
        self.assertRegex(symbols, rf"0000000000010002\s+{object_size}\s+OBJECT"
                                  rf"\s+GLOBAL\s+DEFAULT\s+{ndx}\s+collision_object")
        output = root / "lift.gtirb"
        self.run_checked(root, "lift", [
            os.environ.get("DDISASM", "ddisasm"), str(binary), "--ir", str(output),
            "-j", "1", "--with-souffle-relations",
        ], 120)
        module = gtirb.IR.load_protobuf(output).modules[0]
        collision = next(module.symbols_named("collision_object"))
        info = module.aux_data["elfSymbolInfo"].data[collision]
        self.assertEqual(info[:4], (object_size, "OBJECT", "GLOBAL", "DEFAULT"))
        if absolute:
            self.assertEqual(info[4], 0xfff1)
        else:
            text_indices = re.findall(
                r"^\s*\d+:\s+0000000000010000\s+0\s+SECTION\s+LOCAL\s+DEFAULT\s+(\d+)\s+\.text$",
                symbols, re.MULTILINE)
            self.assertEqual(len(text_indices), 1)
            self.assertEqual(info[4], int(text_indices[0]))
        _, symbol_data = module.aux_data["souffleFacts"].data["disassembly.symbol"]
        symbol_rows = [line.split("\t") for line in symbol_data.splitlines()
                       if line.split("\t")[-1] == "collision_object"]
        self.assertTrue(symbol_rows)
        self.assertTrue(all(int(row[5], 0) == info[4] for row in symbol_rows))
        # Retain a relation-level discriminator, not just the final block type.
        _, invalid_data = module.aux_data["souffleOutputs"].data["disassembly.invalid"]
        invalid = {(int(address, 0), reason) for address, reason in
                   (line.split("\t") for line in invalid_data.splitlines())}
        return module, collision, invalid

    def test_absolute_object_inside_code_stays_code(self):
        for object_size in (0, 4):
            with self.subTest(object_size=object_size), self.fixture_directory(f"abs-size-{object_size}") as root:
                module, collision, invalid = self.lift_collision(root, True, object_size)
                self.assertEqual(collision.value, 0x10002)
                self.assertIsNone(collision.referent)
                self.assertFalse(collision.at_end)
                self.assertNotIn((0x10000, "overlaps object"), invalid)
                start = next(module.symbols_named("_start")).referent
                self.assertIsInstance(start, gtirb.CodeBlock)
                for address in (0x10000, 0x10004):
                    self.assertTrue(any(block.address <= address
                                        and address + 4 <= block.address + block.size
                                        for block in module.code_blocks))
                interval = start.byte_interval
                low = interval.symbolic_expressions[0x10004 - interval.address]
                self.assertIsInstance(low, gtirb.SymAddrConst)
                attrs = gtirb.SymbolicExpression.Attribute
                self.assertTrue({attrs.PCREL, attrs.LO}.issubset(low.attributes))
                self.assertEqual(low.offset, 0)
                self.assertIsInstance(low.symbol.referent, gtirb.CodeBlock)
                self.assertEqual(low.symbol.referent.address, 0x10000)

    def test_section_backed_object_inside_text_still_defeats_code(self):
        for object_size in (0, 4):
            with self.subTest(object_size=object_size), self.fixture_directory(f"section-size-{object_size}") as root:
                module, _, invalid = self.lift_collision(root, False, object_size)
                self.assertIn((0x10000, "overlaps object"), invalid)
                self.assertFalse(any(block.address < 0x10004
                                     and 0x10000 < block.address + block.size
                                     for block in module.code_blocks))
                for address in range(0x10000, 0x10004):
                    self.assertTrue(any(block.address <= address < block.address + block.size
                                        for block in module.data_blocks))


if __name__ == "__main__":
    unittest.main()
