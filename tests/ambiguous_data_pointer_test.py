"""Unproven absolute data pointers must not silently rewrite integer tables."""
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

import gtirb


SOURCE = r"""
    .text
    .globl _start
    .type _start,@function
_start:
    movq pointer(%rip), %rax
    cmpq $37, (%rax)
    jne bad
    movl $0x50, %ecx
    shll $16, %ecx
    cmpq %rcx, numbers(%rip)
    jne bad
    cmpq %rcx, numbers+8(%rip)
    jne bad
    cmpq %rcx, numbers+16(%rip)
    jne bad
    xorl %edi, %edi
    jmp done
bad:
    movl $1, %edi
done:
    movl $60, %eax
    syscall
    .size _start,.-_start

    .section .rodata
    .globl target
    .hidden target
    .type target,@object
target:
    .quad 37
    .size target,.-target

    .data
    .globl pointer
    .hidden pointer
    .type pointer,@object
pointer:
    .quad target
    .size pointer,.-pointer
    .globl numbers
    .hidden numbers
    .type numbers,@object
numbers:
    .quad 0x500000, 0x500000, 0x500000
    .size numbers,.-numbers
    .section .note.GNU-stack,"",@progbits
"""


@unittest.skipUnless(shutil.which("gcc") and shutil.which("objcopy"),
                     "x64 ELF tools required")
class AmbiguousDataPointerTest(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name)

    def build(self, flags=(), source=SOURCE):
        assembly = self.root / "input.S"
        assembly.write_text(source)
        binary = self.root / "input"
        subprocess.run(["gcc", "-nostdlib", "-no-pie", "-Wl,--build-id=none",
                        "-Wl,--section-start=.rodata=0x500000", *flags,
                        str(assembly), "-o", str(binary)],
                       check=True, capture_output=True)
        return binary

    def lift(self, binary, *options):
        ir = self.root / "output.gtirb"
        result = subprocess.run(["ddisasm", str(binary), "--ir", str(ir),
                                 "-j", "1", *options],
                                capture_output=True, text=True, timeout=60)
        return result, ir

    def data_expressions(self, module, name, size):
        block = next(module.symbols_named(name)).referent
        return {offset - block.offset: expression
                for offset, expression in block.byte_interval.symbolic_expressions.items()
                if block.offset <= offset < block.offset + size}

    def test_refuses_named_integer_pointer_ambiguity(self):
        binary = self.build()
        subprocess.run([str(binary)], check=True)
        for options in ((), ("--ignore-errors",)):
            with self.subTest(options=options):
                result, ir = self.lift(binary, *options)
                self.assertNotEqual(result.returncode, 0, result.stderr)
                self.assertIn("Refusing ambiguous data pointers", result.stderr)
                self.assertIn("numbers:", result.stderr)
                self.assertIn("--emit-relocs", result.stderr)
                self.assertFalse(ir.exists() and ir.stat().st_size)

    def test_override_warns_and_retains_legacy_guesses(self):
        result, ir = self.lift(self.build(), "--allow-ambiguous-data-pointers")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("WARNING: Allowing ambiguous data pointers", result.stderr)
        self.assertIn("numbers:", result.stderr)
        module = gtirb.IR.load_protobuf(ir).modules[0]
        self.assertEqual(set(self.data_expressions(module, "numbers", 24)), {0, 8, 16})

    def test_retained_relocations_preserve_scalars_after_relayout(self):
        binary = self.build(("-Wl,--emit-relocs",))
        subprocess.run([str(binary)], check=True)
        result, ir = self.lift(binary)
        self.assertEqual(result.returncode, 0, result.stderr)
        module = gtirb.IR.load_protobuf(ir).modules[0]
        self.assertEqual(self.data_expressions(module, "numbers", 24), {})
        self.assertEqual(set(self.data_expressions(module, "pointer", 8)), {0})
        output = self.root / "output.S"
        subprocess.run(["gtirb-pprinter", "--ir", str(ir), "--asm", str(output),
                        "--policy", "complete", "--shared", "no"],
                       check=True, capture_output=True)
        rebuilt = self.root / "rebuilt"
        # Deliberately do not retain the original .rodata address. A real
        # pointer must move, whereas the adjacent scalar words must not.
        subprocess.run(["gcc", "-nostdlib", "-no-pie", str(output),
                        "-o", str(rebuilt)], check=True, capture_output=True)
        symbols = subprocess.check_output(["nm", str(rebuilt)], text=True)
        target = next(line for line in symbols.splitlines() if line.endswith(" target"))
        self.assertNotEqual(int(target.split()[0], 16), 0x500000)
        subprocess.run([str(rebuilt)], check=True, timeout=10)

    def test_partial_static_tables_do_not_cover_other_sections(self):
        binary = self.build(("-Wl,--emit-relocs",))
        subprocess.run(["objcopy", "--remove-section=.rela.data", str(binary)], check=True)
        result, _ = self.lift(binary)
        self.assertNotEqual(result.returncode, 0, result.stderr)
        self.assertIn("numbers:", result.stderr)

    def test_pie_and_shared_data_need_their_own_relocations(self):
        for kind in ("-pie", "-shared"):
            with self.subTest(kind=kind):
                result, ir = self.lift(self.build((kind,)))
                self.assertEqual(result.returncode, 0, result.stderr)
                module = gtirb.IR.load_protobuf(ir).modules[0]
                self.assertEqual(self.data_expressions(module, "numbers", 24), {})
                self.assertEqual(set(self.data_expressions(module, "pointer", 8)), {0})

    def test_abi_function_pointer_section_needs_no_static_table(self):
        source = r"""
            .text
            .globl _start
            .type _start,@function
        _start:
            xorl %edi,%edi
            movl $60,%eax
            syscall
            .size _start,.-_start
            .type init,@function
        init:
            ret
            .size init,.-init
            .section .init_array,"aw",@init_array
            .quad init
            .section .note.GNU-stack,"",@progbits
        """
        result, _ = self.lift(self.build(source=source))
        self.assertEqual(result.returncode, 0, result.stderr)


if __name__ == "__main__":
    unittest.main()
