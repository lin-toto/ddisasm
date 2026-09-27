"""Retained relocations must not merge same-named locals from different objects."""
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
class RetainedLocalRelocationsTest(unittest.TestCase):
    def test_runtime_text_relocation_keeps_external_call_unresolved(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source, original = root / "input.S", root / "original.so"
            source.write_text("""
                .text
                .globl entry
                .type entry,@function
            entry:
                movabs $external_target,%rax
                call external_target@PLT
                ret
                .size entry,.-entry
                .section .note.GNU-stack,"",@progbits
            """)
            subprocess.run(["gcc", "-shared", "-nostdlib", str(source),
                            "-Wl,--emit-relocs,-z,notext", "-o", str(original)],
                           check=True, capture_output=True)
            dynamic = subprocess.check_output(["readelf", "-d", str(original)], text=True)
            self.assertIn("TEXTREL", dynamic)
            lifted = root / "lifted.gtirb"
            subprocess.run(["ddisasm", str(original), "--ir", str(lifted), "-j", "1"],
                           check=True, capture_output=True)
            module = gtirb.IR.load_protobuf(lifted).modules[0]
            entry = next(module.symbols_named("entry")).referent
            calls = [edge for edge in entry.outgoing_edges if edge.label.type == gtirb.Edge.Type.Call]
            self.assertEqual(len(calls), 1)
            self.assertIsInstance(calls[0].target, gtirb.ProxyBlock)
            self.assertIn("external_target", [symbol.name for symbol in calls[0].target.references])

    def test_retained_calls_preserve_arguments_during_instrumentation(self):
        # Retained .symtab relocations must not hide the linked call target
        # from CFG/liveness analysis. Exercise both SECTION and named symbols,
        # then let a consumer use/spill RDI according to the exported live set.
        for pie in (False, True):
            with self.subTest(pie=pie), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                source, original = root / "input.S", root / "original"
                source.write_text("""
                    .text
                    .globl _start
                    .type _start,@function
                _start:
                    movl $37,%edi
                section_call:
                    call .text.callee+16
                    cmpl $37,%eax
                    jne bad
                    movl $41,%edi
                named_call:
                    call named_callee
                    cmpl $41,%eax
                    jne bad
                    jmp .text.tail+16
                bad:
                    movl $1,%edi
                    movl $60,%eax
                    syscall
                    .size _start,.-_start
                    .section .text.callee,"ax",@progbits
                    .rept 16
                    nop
                    .endr
                    .globl named_callee
                    .hidden named_callee
                    .type named_callee,@function
                named_callee:
                    movl %edi,%eax
                    ret
                    .size named_callee,.-named_callee
                    .section .text.tail,"ax",@progbits
                    .rept 16
                    nop
                    .endr
                    .type tail,@function
                tail:
                    xorl %edi,%edi
                    movl $60,%eax
                    syscall
                    .size tail,.-tail
                    .section .note.GNU-stack,"",@progbits
                """)
                compiler = ["gcc", "-nostdlib", "-pie" if pie else "-no-pie"]
                subprocess.run(compiler + [str(source), "-Wl,--emit-relocs",
                                           "-o", str(original)], check=True, capture_output=True)
                subprocess.run([str(original)], check=True, timeout=10)
                lifted = root / "lifted.gtirb"
                subprocess.run(["ddisasm", str(original), "--ir", str(lifted), "-j", "1"],
                               check=True, capture_output=True)
                ir = gtirb.IR.load_protobuf(lifted)
                module = ir.modules[0]
                live = module.aux_data["liveRegisterSets"].data
                rdi = 1 << module.aux_data["liveRegisterNames"].data.index("rdi")
                context = RewritingContext(module, Function.build_functions(module))

                @patch_constraints()
                def nop(_context):
                    return "nop"

                for block in tuple(module.code_blocks):
                    if block.size:
                        context.insert_at(block, 0, Patch.from_function(nop))
                call_evidence = []
                for name in ("section_call", "named_call"):
                    address = next(module.symbols_named(name)).referent.address
                    block = next(b for b in module.code_blocks
                                 if b.address <= address < b.address + b.size)
                    offset = address - block.address
                    is_live = bool(live[gtirb.Offset(block, offset)] & rdi)
                    calls = [e for e in block.outgoing_edges
                             if e.label.type == gtirb.Edge.Type.Call]
                    call_evidence.append((name, is_live, len(calls)))
                    # A simple instrumentation consumer: dead registers may
                    # be scratch; live ones must survive the patch.
                    assembly = "movl $0,%edi"
                    if is_live:
                        assembly = "pushq %rdi\n" + assembly + "\npopq %rdi"
                    context.insert_at(block, offset, Patch.from_function(
                        patch_constraints()(lambda _context, asm=assembly: asm)))
                context.apply()
                moved, printed, rewritten = root / "moved.gtirb", root / "moved.S", root / "rewritten"
                ir.save_protobuf(moved)
                subprocess.run(["gtirb-pprinter", "--ir", str(moved), "--asm", str(printed),
                                "--policy", "complete", "--shared", "no",
                                "--skip-section", ".interp", ".dynamic"],
                               check=True, capture_output=True)
                subprocess.run(["gcc", "-nostdlib", "-no-pie", str(printed),
                                "-Wl,--section-start=.text=0x500000", "-o", str(rewritten)],
                               check=True, capture_output=True)
                result = subprocess.run([str(rewritten)], capture_output=True, timeout=10)
                self.assertEqual(result.returncode, 0, (call_evidence, result.stderr))
                self.assertEqual(call_evidence, [("section_call", True, 1), ("named_call", True, 1)])

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
