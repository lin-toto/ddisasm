"""Retained PC32 relocations must not turn relative switch entries absolute."""
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

import gtirb
from gtirb_capstone.instructions import GtirbInstructionDecoder
from gtirb_functions import Function
from gtirb_rewriting import Patch, RewritingContext, patch_constraints


@unittest.skipUnless(shutil.which("gcc") and shutil.which("gtirb-pprinter"),
                     "requires x64 ELF compiler and printer")
class RetainedRelativeTablesTest(unittest.TestCase):
    def test_relative_table_survives_nop_insertion(self):
        for pie in (False, True):
            for named in (False, True):
                with self.subTest(pie=pie, named=named), tempfile.TemporaryDirectory() as directory:
                    root = Path(directory)
                    source, original = root / "input.S", root / "original"
                    calls = "\n".join(
                        f"mov ${index},%edi\ncall dispatch\ncmp ${37+index},%eax\njne bad"
                        for index in range(4))
                    cases = "\n".join(
                        (f".globl case{index}\n.hidden case{index}\n" if named else "")
                        + f"case{index}:\nmov ${37+index},%eax\nret\n"
                        for index in range(4))
                    entries = "\n".join(f".long case{index}-relative_table" for index in range(4))
                    source.write_text(f"""
                        .text
                        .globl _start
                        .type _start,@function
                    _start:
                        {calls}
                        xor %edi,%edi
                        jmp done
                    bad:
                        mov $1,%edi
                    done:
                        mov $60,%eax
                        syscall
                        .size _start,.-_start
                        .type dispatch,@function
                    dispatch:
                        cmp $3,%edi
                        ja bad
                        lea relative_table(%rip),%rdx
                        movslq (%rdx,%rdi,4),%rax
                        add %rdx,%rax
                        jmp *%rax
                        {cases}
                        .size dispatch,.-dispatch
                        .section .rodata
                        .balign 4
                        .type relative_table,@object
                    relative_table:
                        {entries}
                        .size relative_table,.-relative_table
                        .section .note.GNU-stack,"",@progbits
                    """)
                    subprocess.run(["gcc", "-nostdlib", "-pie" if pie else "-no-pie",
                                    str(source), "-Wl,--emit-relocs", "-o", str(original)],
                                   check=True, capture_output=True)
                    subprocess.run([str(original)], check=True, timeout=10)
                    lifted = root / "lifted.gtirb"
                    subprocess.run(["ddisasm", str(original), "--ir", str(lifted), "-j", "1"],
                                   check=True, capture_output=True)
                    ir = gtirb.IR.load_protobuf(lifted)
                    module = ir.modules[0]
                    table = next(module.symbols_named("relative_table")).referent
                    kinds = [type(table.byte_interval.symbolic_expressions[table.offset + 4 * index]).__name__
                             for index in range(4)]
                    context = RewritingContext(module, Function.build_functions(module))
                    decoder = GtirbInstructionDecoder(module.isa)

                    @patch_constraints()
                    def nop(_context):
                        return "nop"

                    for block in tuple(module.code_blocks):
                        for instruction in decoder.get_instructions(block):
                            context.insert_at(block, instruction.address - block.address, Patch.from_function(nop))
                    context.apply()
                    moved, printed, rewritten = root / "moved.gtirb", root / "moved.S", root / "rewritten"
                    ir.save_protobuf(moved)
                    subprocess.run(["gtirb-pprinter", "--ir", str(moved), "--asm", str(printed),
                                    "--policy", "complete", "--shared", "no",
                                    "--skip-section", ".interp", ".dynamic"],
                                   check=True, capture_output=True)
                    subprocess.run(["gcc", "-nostdlib", "-no-pie", str(printed),
                                    "-Wl,--section-start=.text=0x500000",
                                    "-Wl,--section-start=.rodata=0x700000", "-o", str(rewritten)],
                                   check=True, capture_output=True)
                    actual = subprocess.run([str(rewritten)], capture_output=True, timeout=10)
                    self.assertEqual(actual.returncode, 0, (kinds, actual.stderr))
                    self.assertEqual(kinds, ["SymAddrAddr"] * 4)


if __name__ == "__main__":
    unittest.main()
