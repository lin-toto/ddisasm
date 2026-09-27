"""Checkpoint liveness must distinguish preserved lanes and ABI boundaries."""
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

import gtirb
from disassemble_reassemble_check import disassemble


@unittest.skipUnless(shutil.which('gcc'), 'x64 compiler required')
class X64VectorLivenessTest(unittest.TestCase):
    def test_pieces_zeroing_partial_writes_and_call_boundaries(self):
        bodies = {
            'legacy_zero': 'pxor %xmm8,%xmm8; vmovdqu %ymm8,(%rdi); ret',
            'vex_zero': 'vpxor %xmm8,%xmm8,%xmm8; vmovdqu %ymm8,(%rdi); ret',
            'partial': 'movss %xmm2,%xmm8; movaps %xmm8,(%rdi); ret',
            'full_low': 'movaps %xmm2,%xmm8; movaps %xmm8,(%rdi); ret',
            'memory_scalar': 'movss (%rdi),%xmm8; movaps %xmm8,(%rdi); ret',
            'merge_mask': 'vpxord %zmm20,%zmm20,%zmm20{%k3}; vmovdqu64 %zmm20,(%rdi); ret',
            'zero_mask': 'vpxord %zmm20,%zmm20,%zmm20{%k3}{z}; vmovdqu64 %zmm20,(%rdi); ret',
            'mask': 'kmovq %k7,(%rdi); ret',
            'zero_k': 'kxorw %k7,%k7,%k7; kmovq %k7,(%rdi); ret',
            'zero_all': 'vzeroall; vmovdqu %ymm12,(%rdi); ret',
            'all_pieces': 'vmovdqu64 %zmm31,(%rdi); ret',
            'caller': 'call callee; movaps %xmm12,(%rdi); ret',
            'callee': 'movaps %xmm15,(%rdi); ret',
            'tail': 'jmp callee',
            'unknown': 'jmp *%rax',
            'returns': 'ret',
        }
        asm = '.text\n.globl _start\n.type _start,@function\n_start:\n'
        asm += ''.join(f'call {name}\n' for name in bodies)
        asm += 'mov $60,%eax; xor %edi,%edi; syscall\n.size _start,.-_start\n'
        for name, body in bodies.items():
            asm += f'.globl {name}\n.type {name},@function\n{name}:\n{body}\n.size {name},.-{name}\n'
        asm += '.section .note.GNU-stack,"",@progbits\n'
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root/'input.S').write_text(asm)
            subprocess.run(['gcc', '-nostdlib', '-no-pie', '-Wl,--emit-relocs',
                            str(root/'input.S'), '-o', str(root/'input')], check=True)
            module = disassemble(root/'input').ir().modules[0]
            names = module.aux_data['liveRegisterNames'].data
            self.assertEqual(len(names), 120)
            lo = module.aux_data['liveRegisterSets'].data
            hi = module.aux_data['liveRegisterSetsHigh'].data
            self.assertEqual(set(lo), set(hi))
            def live(name):
                symbol = next(module.symbols_named(name))
                off = gtirb.Offset(symbol.referent, 0)
                mask = lo[off] | (hi[off] << 64)
                return {n for i,n in enumerate(names) if i >= 16 and mask & (1 << i)}
            self.assertNotIn('xmm8', live('legacy_zero'))
            self.assertIn('ymm8h', live('legacy_zero'))
            self.assertNotIn('ymm8h', live('vex_zero'))
            self.assertNotIn('xmm8', live('vex_zero'))
            self.assertIn('xmm8', live('partial'))
            self.assertNotIn('xmm8', live('full_low'))
            self.assertNotIn('xmm8', live('memory_scalar'))
            pieces = {'xmm20','ymm20h','zmm20h'}
            self.assertTrue(pieces <= live('merge_mask'))
            self.assertFalse(pieces & live('zero_mask'))
            self.assertIn('k3', live('zero_mask'))
            self.assertIn('k7', live('mask'))
            self.assertNotIn('k7', live('zero_k'))
            self.assertEqual(live('zero_all'), set())
            self.assertTrue({'xmm31','ymm31h','zmm31h'} <= live('all_pieces'))
            self.assertEqual(live('caller'), {f'xmm{i}' for i in range(8)})
            self.assertEqual(live('tail'), {f'xmm{i}' for i in range(8)})
            self.assertEqual(live('returns'), {'xmm0','xmm1'})
            self.assertNotIn('xmm12', live('callee'))
            self.assertEqual(len(live('unknown')), 104)
