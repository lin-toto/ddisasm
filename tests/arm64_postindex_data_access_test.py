"""Native post-index increments must not become memory-access displacements."""

from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

import gtirb
from gtirb_functions import Function
from gtirb_rewriting import Patch, RewritingContext, patch_constraints


# Name, instruction, effective displacement, base increment, post-index.
CASES = (
    ('byte_load_post', 'ldrb w0, [x9], #1', 0, 1, True),
    ('byte_store_post', 'strb w2, [x9], #-1', 0, -1, True),
    ('q_load_post', 'ldr q0, [x9], #16', 0, 16, True),
    ('q_store_post', 'str q0, [x9], #-16', 0, -16, True),
    ('byte_load_pre', 'ldrb w0, [x9, #1]!', 1, 1, False),
    ('byte_store_pre', 'strb w2, [x9, #-1]!', -1, -1, False),
    ('q_load_pre', 'ldr q0, [x9, #16]!', 16, 16, False),
    ('q_store_pre', 'str q0, [x9, #-16]!', -16, -16, False),
    ('structure_load', 'ld1 {v1.2d-v4.2d}, [x9], #64', 0, 64, True),
    ('structure_store', 'st1 {v1.2d-v4.2d}, [x9], #64', 0, 64, True),
)


@unittest.skipUnless(all(shutil.which(tool) for tool in (
    'aarch64-linux-gnu-gcc', 'qemu-aarch64', 'ddisasm', 'gtirb-pprinter')),
    'AArch64 compiler, QEMU, and frontend tools required')
class Arm64PostindexDataAccessTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        temporary = tempfile.TemporaryDirectory()
        cls.addClassCleanup(temporary.cleanup)
        cls.root = root = Path(temporary.name)
        cls.compiler = ['aarch64-linux-gnu-gcc', '-nostdlib', '-static', '-no-pie']
        source = ['.text', '.globl _start', '.type _start,%function',
                  '_start:', 'mov w2,#37']
        for label, instruction, _, _, _ in CASES:
            source += ['adr x9, buffer+64', '.globl ' + label,
                       label + ':', instruction]
        # Expose the actual resulting memory, rather than checking exit alone.
        source += [
            'mov x0,#1', 'adr x1,buffer', 'mov x2,#256', 'mov x8,#64', 'svc #0',
            'mov x0,#0', 'mov x8,#93', 'svc #0', '.size _start,.-_start',
            '.data', '.balign 16', '.globl buffer', '.type buffer,%object',
            'buffer:', '.rept 32', '.byte 1,2,3,4,5,6,7,8', '.endr',
            '.size buffer,.-buffer', '.section .note.GNU-stack,"",%progbits',
        ]
        (root / 'input.S').write_text('\n'.join(source) + '\n')
        cls.run_command(cls.compiler + ['-Wl,--emit-relocs', root / 'input.S',
                                         '-o', root / 'original'])
        cls.run_command(['ddisasm', root / 'original', '--ir', root / 'lifted.gtirb',
                         '--debug-dir', root / 'debug', '-j', '1'])

    @staticmethod
    def run_command(argv):
        return subprocess.run(argv, check=True, capture_output=True, timeout=60)

    def relation(self, name):
        path = self.root / 'debug/disassembly' / name
        return [line.split('\t') for line in path.read_text().splitlines()]

    def test_effective_addresses_and_base_updates(self):
        module = gtirb.IR.load_protobuf(self.root / 'lifted.gtirb').modules[0]
        access = self.relation('data_access.csv')
        updates = self.relation('arch.reg_arithmetic_operation.csv')
        writeback = {int(row[0], 0) for row in self.relation('instruction_writeback.facts')}
        postindex = {int(row[0], 0) for row in self.relation('instruction_post_index.facts')}
        for label, _, displacement, increment, is_post in CASES:
            with self.subTest(label=label):
                address = next(module.symbols_named(label)).referent.address
                accesses = [row for row in access if int(row[0], 0) == address and row[3] == 'X9']
                self.assertIn(address, writeback)
                self.assertEqual(address in postindex, is_post)
                self.assertEqual({int(row[6]) for row in accesses}, {displacement})
                if label.startswith('q_load'):
                    self.assertEqual({int(row[7]) for row in accesses}, {16})
                if not label.startswith('structure_'):
                    arithmetic = [row[1:] for row in updates if int(row[0], 0) == address]
                    self.assertIn(['X9', 'X9', '1', str(increment)], arithmetic)

    def test_nop_movement_preserves_memory_effects(self):
        root = self.root
        ir = gtirb.IR.load_protobuf(root / 'lifted.gtirb')
        module = ir.modules[0]

        @patch_constraints()
        def nop(_):
            return 'nop'

        context = RewritingContext(module, Function.build_functions(module))
        for block in tuple(module.code_blocks):
            if block.size:
                context.insert_at(block, 0, Patch.from_function(nop))
        context.apply()
        ir.save_protobuf(root / 'moved.gtirb')
        self.run_command(['gtirb-pprinter', '--ir', root / 'moved.gtirb',
                          '--asm', root / 'moved.S', '--policy', 'complete', '--shared', 'no'])
        self.run_command(self.compiler + [root / 'moved.S',
            '-Wl,--section-start=.text=0x500000', '-Wl,--section-start=.data=0x580000',
            '-o', root / 'moved'])
        original = self.run_command(['qemu-aarch64', root / 'original'])
        rewritten = self.run_command(['qemu-aarch64', root / 'moved'])
        self.assertEqual(len(original.stdout), 256)
        self.assertEqual((rewritten.stdout, rewritten.stderr),
                         (original.stdout, original.stderr))


if __name__ == '__main__':
    unittest.main()
