"""A debug-section offset must never become a runtime code address."""
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

import gtirb
from gtirb_functions import Function
from gtirb_rewriting import Patch, RewritingContext, patch_constraints


@unittest.skipUnless(shutil.which("gcc") and shutil.which("gtirb-pprinter"),
                     "requires x64 ELF compiler and printer")
class NonallocatedSymbolTest(unittest.TestCase):
    def test_debug_offset_overlapping_call_is_not_a_code_label(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source, original = root / "input.S", root / "original"
            source.write_text("""
                .text
                .globl _start
                .type _start,@function
            _start:
                call callee
                xorl %edi,%edi
                movl $60,%eax
                syscall
                .size _start,.-_start
                .type callee,@function
            callee:
                ret
                .size callee,.-callee
                .data
                .globl allocated_value
                .type allocated_value,@object
            allocated_value: .quad 123
                .size allocated_value,8
                .globl absolute_value
                .set absolute_value,0x654321
                .section .debug_collision,"",@progbits
                .zero 0x20003
                .local debug_overlap
            debug_overlap: .byte 0
                .section .note.GNU-stack,"",@progbits
            """)
            cc = ["gcc", "-nostdlib", "-static", "-no-pie"]
            subprocess.run(cc + [str(source), "-Wl,--section-start=.text=0x20000",
                                  "-Wl,--emit-relocs", "-o", str(original)],
                           check=True, capture_output=True)
            sections = subprocess.check_output(["readelf", "-WS", str(original)], text=True)
            symbols = subprocess.check_output(["readelf", "-Ws", str(original)], text=True)
            debug_section = next(line for line in sections.splitlines() if ".debug_collision " in line)
            # Readelf puts the section flags after its fixed-width entry size;
            # this synthetic section is PROGBITS with no ALLOC flag.
            self.assertRegex(debug_section, r"PROGBITS\s+0+\s+[0-9a-f]+\s+[0-9a-f]+\s+00\s+0\s+0\s+1")
            self.assertRegex(symbols, r"0000000000020003\s+0\s+NOTYPE\s+LOCAL\s+DEFAULT\s+\d+\s+debug_overlap")
            self.assertRegex(symbols, r"0000000000654321\s+0\s+NOTYPE\s+GLOBAL\s+DEFAULT\s+ABS\s+absolute_value")
            subprocess.run([str(original)], check=True, timeout=10)
            lifted = root / "lifted.gtirb"
            subprocess.run(["ddisasm", str(original), "--ir", str(lifted), "-j", "1"],
                           check=True, capture_output=True)
            ir = gtirb.IR.load_protobuf(lifted)
            module = ir.modules[0]
            debug = next(module.symbols_named("debug_overlap"))
            self.assertIsNone(debug.value)
            self.assertIsNone(debug.referent)
            self.assertEqual(next(module.symbols_named("absolute_value")).value, 0x654321)
            self.assertIsNotNone(next(module.symbols_named("allocated_value")).referent)
            self.assertFalse(any(symbol.value == 0x20003 for symbol in module.symbols))

            @patch_constraints()
            def nop(_context):
                return "nop"

            context = RewritingContext(module, Function.build_functions(module))
            for block in tuple(module.code_blocks):
                if block.size:
                    context.insert_at(block, 0, Patch.from_function(nop))
            context.apply()
            moved, assembly, rewritten = root / "moved.gtirb", root / "moved.S", root / "rewritten"
            ir.save_protobuf(moved)
            subprocess.run(["gtirb-pprinter", "--ir", str(moved), "--asm", str(assembly),
                            "--policy", "complete", "--shared", "no"], check=True, capture_output=True)
            subprocess.run(cc + [str(assembly), "-Wl,--section-start=.text=0x500000",
                                  "-o", str(rewritten)], check=True, capture_output=True)
            subprocess.run([str(rewritten)], check=True, timeout=10)


if __name__ == "__main__":
    unittest.main()
