"""Retained relocations must not merge same-named locals from different objects."""
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

import gtirb


@unittest.skipUnless(shutil.which("gcc") and shutil.which("gtirb-pprinter"),
                     "requires x64 ELF compiler and printer")
class RetainedLocalRelocationsTest(unittest.TestCase):
    def test_distinct_local_targets_and_addends_after_relayout(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            objects = []
            for index, value in enumerate((11, 31)):
                source = root / ("part%d.S" % index)
                source.write_text(f"""
                    .text
                    .globl get_{index}
                    .type get_{index},@function
                get_{index}:
                    # Explicit relocations keep the local symbol's identity;
                    # ordinary gas fixups may fold it into the section symbol.
                    .byte 0x8b,0x05
                .Ldisp:
                    .long 0
                    .reloc .Ldisp,R_X86_64_PC32,local_value
                    ret
                    .size get_{index},.-get_{index}
                    .data
                    .local local_value
                    .type local_value,@object
                local_value:
                    .long 0,{value}
                    .size local_value,.-local_value
                    .globl pointer_{index}
                    .type pointer_{index},@object
                pointer_{index}:
                    .quad 0
                    .reloc pointer_{index},R_X86_64_64,local_value+4
                    .size pointer_{index},.-pointer_{index}
                    .section .note.GNU-stack,"",@progbits
                """)
                obj = source.with_suffix(".o")
                subprocess.run(["gcc", "-c", str(source), "-o", str(obj)],
                               check=True, capture_output=True)
                objects.append(obj)
            entry = root / "entry.S"
            entry.write_text("""
                .text
                .globl _start
                .type _start,@function
            _start:
                call get_0
                cmpl $11,%eax
                jne bad
                call get_1
                cmpl $31,%eax
                jne bad
                movq pointer_0(%rip),%rax
                cmpl $11,(%rax)
                jne bad
                movq pointer_1(%rip),%rax
                cmpl $31,(%rax)
                jne bad
                xorl %edi,%edi
                jmp done
            bad:
                movl $1,%edi
            done:
                movl $60,%eax
                syscall
                .size _start,.-_start
                .section .note.GNU-stack,"",@progbits
            """)
            cc = ["gcc", "-nostdlib", "-no-pie", "-Wl,--build-id=none"]
            original = root / "original"
            subprocess.run(cc + [str(entry), *map(str, objects), "-Wl,--emit-relocs",
                                 "-o", str(original)], check=True, capture_output=True)
            relocations = subprocess.check_output(["readelf", "-Wr", str(original)], text=True)
            self.assertGreaterEqual(relocations.count("local_value"), 4)
            subprocess.run([str(original)], check=True)
            path = root / "ir.gtirb"
            subprocess.run(["ddisasm", str(original), "--ir", str(path), "-j", "1"],
                           check=True, capture_output=True)
            module = gtirb.IR.load_protobuf(path).modules[0]
            targets = []
            for index in range(2):
                pointer = next(module.symbols_named("pointer_%d" % index)).referent
                expression = pointer.byte_interval.symbolic_expressions[pointer.offset]
                self.assertIsInstance(expression, gtirb.SymAddrConst)
                self.assertEqual(expression.offset, 4)
                targets.append(expression.symbol.referent.address)
            assembly = root / "output.S"
            subprocess.run(["gtirb-pprinter", "--ir", str(path), "--asm", str(assembly),
                            "--policy", "complete", "--shared", "no"],
                           check=True, capture_output=True)
            rewritten = root / "rewritten"
            subprocess.run(cc + [str(assembly), "-Wl,--section-start=.text=0x500000",
                                 "-Wl,--section-start=.data=0x700000", "-o", str(rewritten)],
                           check=True, capture_output=True)
            subprocess.run([str(rewritten)], check=True, timeout=10)
            self.assertNotEqual(*targets)


if __name__ == "__main__":
    unittest.main()
