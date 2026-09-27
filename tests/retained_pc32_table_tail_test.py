"""A retained RIP-relative reference must not truncate an adjacent jump table."""
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

import gtirb
from gtirb_capstone.instructions import GtirbInstructionDecoder
from gtirb_functions import Function
from gtirb_rewriting import Patch, RewritingContext, patch_constraints


@unittest.skipUnless(all(shutil.which(tool) for tool in ('gcc', 'ddisasm', 'gtirb-pprinter')),
                     'requires x64 compiler, lifter and printer')
class RetainedPc32TableTailTest(unittest.TestCase):
    def test_all_six_arms_with_adjacent_named_object_after_movement(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            calls = '\n'.join(f'''
                mov ${index},%edi
                call dispatch
                cmp ${65+index},%eax
                jne bad
                mov %al,output(%rip)
                mov $1,%eax
                mov $1,%edi
                lea output(%rip),%rsi
                mov $1,%edx
                syscall
            ''' for index in range(6))
            cases = '\n'.join(f'case{index}:\nmov ${65+index},%eax\nret'
                              for index in range(6))
            entries = '\n'.join(f'.long case{index}-relative_table' for index in range(6))
            source = root / 'input.S'
            source.write_text(f'''
                .text
                .globl _start
                .type _start,@function
            _start:
                # This named PC32 relocation has addend -4. Its S+A points
                # into the sixth table word; its effective address does not.
                movzwl table_suffix(%rip),%eax
                cmp $0x1234,%eax
                jne bad
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
                cmp $5,%edi
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
                .globl table_suffix
                .hidden table_suffix
                .type table_suffix,@object
            table_suffix:
                .short 0x1234
                .size table_suffix,.-table_suffix
                .data
            output: .byte 0
                .section .note.GNU-stack,"",@progbits
            ''')
            original = root / 'original'
            subprocess.run(['gcc', '-nostdlib', '-pie', source, '-Wl,--emit-relocs',
                            '-o', original], check=True, capture_output=True)
            baseline = subprocess.run([original], check=True, capture_output=True, timeout=10)
            self.assertEqual(baseline.stdout, b'ABCDEF')
            lifted = root / 'lifted.gtirb'
            subprocess.run(['ddisasm', original, '--ir', lifted, '-j', '1'],
                           check=True, capture_output=True)
            ir = gtirb.IR.load_protobuf(lifted)
            module = ir.modules[0]
            table = next(module.symbols_named('relative_table')).referent
            kinds = [type(table.byte_interval.symbolic_expressions[table.offset + 4 * index]).__name__
                     for index in range(6)]
            context = RewritingContext(module, Function.build_functions(module))
            decoder = GtirbInstructionDecoder(module.isa)

            @patch_constraints()
            def nop(_):
                return 'nop'

            for block in tuple(module.code_blocks):
                for instruction in decoder.get_instructions(block):
                    context.insert_at(block, instruction.address - block.address, Patch.from_function(nop))
            context.apply()
            moved, assembly = root / 'moved.gtirb', root / 'moved.S'
            ir.save_protobuf(moved)
            subprocess.run(['gtirb-pprinter', '--ir', moved, '--asm', assembly,
                            '--policy', 'complete', '--shared', 'no',
                            '--skip-section', '.interp', '.dynamic'], check=True, capture_output=True)
            for pie in (False, True):
                with self.subTest(pie=pie):
                    target = root / ('moved-pie' if pie else 'moved-exec')
                    layout = [] if pie else ['-Wl,--section-start=.text=0x500000',
                                             '-Wl,--section-start=.rodata=0x700000']
                    linked = subprocess.run(['gcc', '-nostdlib', '-pie' if pie else '-no-pie',
                                             assembly, *layout, '-o', target], capture_output=True)
                    self.assertEqual(linked.returncode, 0, (kinds, linked.stderr))
                    self.assertEqual(int.from_bytes(target.read_bytes()[16:18], 'little'),
                                     3 if pie else 2)
                    actual = subprocess.run([target], capture_output=True, timeout=10)
                    self.assertEqual((actual.returncode, actual.stdout, actual.stderr),
                                     (0, baseline.stdout, baseline.stderr), kinds)
            self.assertEqual(kinds, ['SymAddrAddr'] * 6)


if __name__ == '__main__':
    unittest.main()
