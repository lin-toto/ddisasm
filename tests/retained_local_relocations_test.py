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
    def test_retained_section_calls_and_bss_after_relayout(self):
        for pie in (False, True):
            with self.subTest(pie=pie), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                source = root / "input.c"
                source.write_text("""
                    #include <stdio.h>
                    static int local_counter;
                    static const char padding[4096] __attribute__((used)) = "padding";
                    __attribute__((noinline, noclone)) static void local_callee(void) {
                        ++local_counter;
                    }
                    int main(void) {
                        local_callee();
                        local_callee();
                        printf("counter=%d\\n", local_counter);
                        return local_counter != 2;
                    }
                """)
                cc = ["gcc", "-O2", "-fPIE" if pie else "-fno-pie",
                      "-pie" if pie else "-no-pie",
                      "-Wl,--build-id=none"]
                original = root / "original"
                subprocess.run(cc + [str(source), "-Wl,--emit-relocs",
                                     "-o", str(original)], check=True, capture_output=True)
                relocations = subprocess.check_output(["readelf", "-Wr", str(original)], text=True)
                self.assertRegex(relocations, r"R_X86_64_PC32\s+[0-9a-f]+\s+\.text \+")
                self.assertRegex(relocations, r"R_X86_64_PC32\s+[0-9a-f]+\s+\.bss \+")
                expected = subprocess.check_output([str(original)], timeout=10)
                path, assembly = root / "ir.gtirb", root / "output.S"
                subprocess.run(["ddisasm", str(original), "--ir", str(path), "-j", "1"],
                               check=True, capture_output=True)
                subprocess.run(["gtirb-pprinter", "--ir", str(path), "--asm", str(assembly),
                                "--policy", "complete", "--shared", "no"],
                               check=True, capture_output=True)
                rewritten = root / "rewritten"
                subprocess.run(["gcc", "-nostartfiles", "-no-pie", str(assembly),
                                "-Wl,--section-start=.text=0x500000",
                                "-Wl,--section-start=.bss=0x700000", "-o", str(rewritten)],
                               check=True, capture_output=True)
                self.assertEqual(subprocess.check_output([str(rewritten)], timeout=10), expected)

    def test_nonrelaxable_gotpcrel_cmov_after_relayout(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "input.S"
            source.write_text("""
                .text
                .globl _start
                .type _start,@function
            _start:
                xorl %eax,%eax
                testl %eax,%eax
                cmoveq target@GOTPCREL(%rip),%rax
                xorl %edi,%edi
                cmpq $37,(%rax)
                setne %dil
                movl $60,%eax
                syscall
                .size _start,.-_start
                .data
                .globl target
                .hidden target
                .type target,@object
            target:
                .quad 37
                .size target,.-target
                .section .note.GNU-stack,"",@progbits
            """)
            cc = ["gcc", "-nostdlib", "-no-pie", "-Wl,--build-id=none"]
            original = root / "original"
            subprocess.run(cc + [str(source), "-Wl,--emit-relocs", "-o", str(original)],
                           check=True, capture_output=True)
            relocations = subprocess.check_output(["readelf", "-Wr", str(original)], text=True)
            self.assertIn(" R_X86_64_GOTPCREL ", relocations)
            subprocess.run([str(original)], check=True)
            path = root / "ir.gtirb"
            subprocess.run(["ddisasm", str(original), "--ir", str(path), "-j", "1"],
                           check=True, capture_output=True)
            assembly = root / "output.S"
            subprocess.run(["gtirb-pprinter", "--ir", str(path), "--asm", str(assembly),
                            "--policy", "complete", "--shared", "no"],
                           check=True, capture_output=True)
            rewritten = root / "rewritten"
            subprocess.run(cc + [str(assembly), "-Wl,--section-start=.text=0x500000",
                                 "-Wl,--section-start=.data=0x700000", "-o", str(rewritten)],
                           check=True, capture_output=True)
            subprocess.run([str(rewritten)], check=True, timeout=10)

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
