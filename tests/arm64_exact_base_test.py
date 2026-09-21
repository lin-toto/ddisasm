import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

import gtirb
from disassemble_reassemble_check import asm_print, disassemble


@unittest.skipUnless(
    shutil.which("aarch64-linux-gnu-gcc") and shutil.which("qemu-aarch64"),
    "AArch64 compiler and QEMU required",
)
class Arm64ExactBaseTest(unittest.TestCase):
    def test_exact_and_page_bases_survive_relayout(self):
        consumers = {
            "add": "add x0, x8, #64\nldrb w0, [x0]",
            "add_shift": "add x0, x8, #1, lsl #12\nldrb w0, [x0]",
            "load": "ldrb w0, [x8, #64]",
            "store": "strb w1, [x8, #64]\nadr x9, target\nldrb w0, [x9]",
        }
        flows = {
            "direct": ("", "x8"),
            "copy": ("mov x9, x8", "x9"),
            "spill": (
                "sub sp, sp, #16\nstr x8, [sp]\nldr x9, [sp]\nadd sp, sp, #16",
                "x9",
            ),
        }
        cases = [
            (kind, flow, setup, consumer.replace("x8", register))
            for kind, consumer in consumers.items()
            for flow, (setup, register) in flows.items()
        ]
        compiler = ["aarch64-linux-gnu-gcc", "-nostdlib", "-no-pie"]
        for operation in ("adr", "adrp"):
            for kind, flow, setup, consumer in cases:
                with self.subTest(operation=operation, consumer=kind, flow=flow):
                    initial = 0 if kind == "store" else 37
                    distance = 4096 if kind == "add_shift" else 64
                    source = f"""
                        .text
                        .globl _start
                        .type _start, %function
                        _start:
                            mov w1, #37
                            {operation} x8, base
                            {setup}
                        consumer:
                            {consumer}
                            cmp w0, w1
                            cset w0, ne
                            mov x8, #93
                            svc #0
                        .size _start, .-_start
                        .section .values, "aw", %progbits
                        .balign 8
                        .type base, %object
                        base: .zero {distance}
                        .size base, .-base
                        .type target, %object
                        target: .byte {initial}
                        .size target, .-target
                        .zero 255
                        .section .note.GNU-stack, "", %progbits
                    """
                    with tempfile.TemporaryDirectory() as directory:
                        root = Path(directory)
                        original = root / "original"
                        assembly = root / "input.S"
                        assembly.write_text(source)
                        subprocess.run(
                            compiler + [str(assembly), "-o", str(original),
                                        "-Wl,--section-start=.values=0x480000"],
                            check=True, capture_output=True,
                        )
                        subprocess.run(
                            ["qemu-aarch64", str(original)],
                            check=True, capture_output=True, timeout=10,
                        )
                        result = disassemble(original)
                        printed = root / "printed.S"
                        self.assertEqual(
                            asm_print(result.ir_path, printed).returncode, 0
                        )
                        asm = printed.read_text()
                        for address in (0x480000, 0x480100, 0x490108):
                            for nops in (0, 5):
                                with self.subTest(address=hex(address), nops=nops):
                                    moved = asm.replace(
                                        "_start:",
                                        f".rept {nops}\nnop\n.endr\n_start:",
                                    )
                                    self.assertNotEqual(moved, asm)
                                    # A literal offset must not pass merely
                                    # because base and target moved together.
                                    gap = (4096 if kind == "add_shift" else 16) if nops else 0
                                    expanded = moved.replace(
                                        "target:", f".zero {gap}\ntarget:"
                                    )
                                    self.assertNotEqual(expanded, moved)
                                    printed.write_text(expanded)
                                    rebuilt = root / "rebuilt"
                                    subprocess.run(
                                        compiler + [str(printed), "-o", str(rebuilt),
                                                    f"-Wl,--section-start=.values={address:#x}"],
                                        check=True, capture_output=True,
                                    )
                                    ran = subprocess.run(
                                        ["qemu-aarch64", str(rebuilt)],
                                        capture_output=True, timeout=10,
                                    )
                                    self.assertEqual(ran.returncode, 0, ran.stderr)

                        module = result.ir().modules[0]
                        block = next(module.symbols_named("_start")).referent
                        symbol = next(module.symbols_named("consumer"))
                        address = symbol.value
                        if address is None:
                            address = symbol.referent.address
                            if symbol.at_end:
                                address += symbol.referent.size
                        expression = block.byte_interval.symbolic_expressions[
                            address - block.byte_interval.address
                        ]
                        if operation == "adr":
                            self.assertIsInstance(expression, gtirb.SymAddrAddr)
                            self.assertNotIn(
                                gtirb.SymbolicExpression.Attribute.LO12,
                                expression.attributes,
                            )
                        else:
                            self.assertIsInstance(expression, gtirb.SymAddrConst)
                            self.assertIn(
                                gtirb.SymbolicExpression.Attribute.LO12,
                                expression.attributes,
                            )


if __name__ == "__main__":
    unittest.main()
