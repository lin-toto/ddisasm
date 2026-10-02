"""Checkpoint liveness must distinguish preserved lanes and ABI boundaries."""
import ctypes.util
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
            'unknown_call': 'call *%rax; movaps %xmm12,(%rdi); ret',
            'returns': 'ret',
        }
        asm = '.text\n.globl _start\n.type _start,@function\n_start:\n'
        # Keep the independent instruction probes in separate call contexts.
        # Calling them in sequence would legitimately make a later probe's
        # inputs live through every earlier leaf after interprocedural analysis.
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
            self.assertEqual(live('caller'), {'xmm0', 'xmm1', 'xmm12', 'xmm15'})
            self.assertEqual(live('tail'), {'xmm0', 'xmm1', 'xmm12', 'xmm15'})
            self.assertEqual(live('returns'), {'xmm0','xmm1'})
            self.assertIn('xmm12', live('callee'))
            self.assertEqual(len(live('unknown')), 104)
            self.assertEqual(live('unknown_call'), {f'xmm{i}' for i in range(8)})

    @staticmethod
    def _vector_liveness(asm, link_flags=()):
        """Lift a probe program; return a function giving the vector registers live at a label."""
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root/'input.S').write_text(asm)
            subprocess.run(['gcc', '-nostdlib', '-no-pie', str(root/'input.S'), *link_flags,
                            '-o', str(root/'input')], check=True)
            module = disassemble(root/'input').ir().modules[0]
        names = module.aux_data['liveRegisterNames'].data
        lo = module.aux_data['liveRegisterSets'].data
        hi = module.aux_data['liveRegisterSetsHigh'].data

        def live(name):
            symbol = next(module.symbols_named(name))
            off = gtirb.Offset(symbol.referent, 0)
            mask = lo[off] | (hi[off] << 64)
            return {n for i, n in enumerate(names) if i >= 16 and mask & (1 << i)}
        return live

    @unittest.skipUnless(ctypes.util.find_library('m'), 'a shared libm is required')
    def test_external_tail_jumps_keep_vector_arguments(self):
        # A tail jump through a PLT stub or a GOT entry passes vector
        # arguments. Each probe overwrites xmm0 just before the jump, so
        # xmm0-7 are live there only because of it. The sets are exact: an
        # unresolved jump would keep all 104 pieces live, and a jump the CFG
        # follows into a local body would keep only what is live there (at an
        # ifunc resolver's ret, the return registers xmm0-1).
        # - cos is also loaded from the GOT, so jmp cos@PLT uses a .plt.got
        #   stub; sin is reached only through a lazy PLT stub.
        # - vector_ifunc is an ifunc defined here, so jmp vector_ifunc uses an
        #   IRELATIVE stub, which the CFG follows into the resolver.
        # No --emit-relocs, for two reasons: as in a -fno-plt build, only the
        # dynamic GOT relocation then names cos, and a retained PLT32
        # relocation would make the cos and sin probes exact without the
        # stub rules.
        asm = """.text
        .globl _start
        .type _start,@function
        _start:
          mov $60,%eax
          xor %edi,%edi
          syscall
        .size _start,.-_start
        .globl got_tail
        .type got_tail,@function
        got_tail:
          movsd (%rdi),%xmm0
        .globl got_tail_jump
        got_tail_jump:
          jmp *cos@GOTPCREL(%rip)
        .size got_tail,.-got_tail
        .globl got_reg_tail
        .type got_reg_tail,@function
        got_reg_tail:
          movsd (%rdi),%xmm0
          mov cos@GOTPCREL(%rip),%rax
        .globl got_reg_tail_jump
        got_reg_tail_jump:
          jmp *%rax
        .size got_reg_tail,.-got_reg_tail
        .globl plt_tail
        .type plt_tail,@function
        plt_tail:
          movsd (%rdi),%xmm0
        .globl plt_tail_jump
        plt_tail_jump:
          jmp cos@PLT
        .size plt_tail,.-plt_tail
        .globl lazy_plt_tail
        .type lazy_plt_tail,@function
        lazy_plt_tail:
          movsd (%rdi),%xmm0
        .globl lazy_plt_tail_jump
        lazy_plt_tail_jump:
          jmp sin@PLT
        .size lazy_plt_tail,.-lazy_plt_tail
        .type vector_impl,@function
        vector_impl:
          ret
        .size vector_impl,.-vector_impl
        .globl vector_ifunc
        .type vector_ifunc,@gnu_indirect_function
        vector_ifunc:
          lea vector_impl(%rip),%rax
          ret
        .size vector_ifunc,.-vector_ifunc
        .globl ifunc_tail
        .type ifunc_tail,@function
        ifunc_tail:
          movsd (%rdi),%xmm0
        .globl ifunc_tail_jump
        ifunc_tail_jump:
          jmp vector_ifunc
        .size ifunc_tail,.-ifunc_tail
        .section .note.GNU-stack,"",@progbits
        """
        live = self._vector_liveness(asm, ['-lm'])
        arguments = {f'xmm{i}' for i in range(8)}
        for name in ('got_tail_jump', 'got_reg_tail_jump', 'plt_tail_jump',
                     'lazy_plt_tail_jump', 'ifunc_tail_jump'):
            with self.subTest(jump=name):
                self.assertEqual(live(name), arguments)

    def test_state_saves_read_vector_state(self):
        # FXSAVE and the XSAVE family store vector state no operand names. Each
        # probe overwrites its registers right after the save. XRSTOR records
        # no write (its components depend on the mask), so a later read keeps
        # the register live across it.
        saves = {'fxsave': 'fxsave', 'fxsave64': 'fxsave64', 'xsave': 'xsave',
                 'xsaveopt': 'xsaveopt', 'xsavec64': 'xsavec64'}
        asm = """.text
        .globl _start
        .type _start,@function
        _start:
          mov $60,%eax
          xor %edi,%edi
          syscall
        .size _start,.-_start
        """
        for name, mnemonic in saves.items():
            asm += f"""
        .globl {name}_probe
        .type {name}_probe,@function
        {name}_probe:
          {mnemonic} (%rdi)
          pxor %xmm8,%xmm8
          movaps %xmm8,(%rsi)
          vpxord %zmm20,%zmm20,%zmm20
          vmovdqu64 %zmm20,(%rsi)
          kxorw %k5,%k5,%k5
          kmovq %k5,(%rsi)
          ret
        .size {name}_probe,.-{name}_probe
        """
        asm += """
        .globl xrstor_probe
        .type xrstor_probe,@function
        xrstor_probe:
          xrstor (%rdi)
          movaps %xmm8,(%rsi)
          ret
        .size xrstor_probe,.-xrstor_probe
        .section .note.GNU-stack,"",@progbits
        """
        live = self._vector_liveness(asm, ['-Wl,--emit-relocs'])
        for name in saves:
            with self.subTest(save=name):
                self.assertIn('xmm8', live(name + '_probe'))
                if name.startswith('xsave'):
                    self.assertTrue({'xmm20', 'ymm20h', 'zmm20h', 'k5'} <= live(name + '_probe'))
                else:
                    # FXSAVE stores no upper halves, no xmm16-31 and no k registers.
                    self.assertFalse({'xmm20', 'ymm20h', 'zmm20h', 'k5'} & live(name + '_probe'))
        self.assertIn('xmm8', live('xrstor_probe'))

    def test_ipa_register_allocation_through_local_calls(self):
        # The critical part of GCC -O2 -fipa-ra ipara5/ipara6: high vectors
        # remain live at a branch before a leaf call. A transitive tail callee
        # overwrites xmm10 only; xmm8/9 must survive both calls and rollback.
        asm = '''.text
        .globl _start
        .type _start,@function
        _start:
          mov $60,%eax
          xor %edi,%edi
          syscall
        .size _start,.-_start
        .globl ipara6
        .type ipara6,@function
        ipara6:
          movsd 64(%rdi),%xmm8
          movsd 72(%rdi),%xmm9
          cmp $3,%rsi
        .globl checkpoint_site
        checkpoint_site:
          jle 1f
          add $7,%rsi
        1:
          call leaf
          addsd %xmm8,%xmm0
          addsd %xmm9,%xmm0
          addsd %xmm10,%xmm0
          ret
        .size ipara6,.-ipara6
        .type leaf,@function
        leaf:
          lea 1(%rsi,%rsi,2),%rax
          jmp leaf_tail
        .size leaf,.-leaf
        .type leaf_tail,@function
        leaf_tail:
          pxor %xmm10,%xmm10
          ret
        .size leaf_tail,.-leaf_tail
        .section .note.GNU-stack,"",@progbits
        '''
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root/'input.S').write_text(asm)
            subprocess.run(['gcc', '-nostdlib', '-no-pie', '-Wl,--emit-relocs',
                            str(root/'input.S'), '-o', str(root/'input')], check=True)
            module = disassemble(root/'input').ir().modules[0]
            site = next(module.symbols_named('checkpoint_site')).referent
            offset = gtirb.Offset(site, 0)
            mask = (module.aux_data['liveRegisterSets'].data[offset] |
                    (module.aux_data['liveRegisterSetsHigh'].data[offset] << 64))
            names = module.aux_data['liveRegisterNames'].data
            live = {n for i, n in enumerate(names) if mask & (1 << i)}
            self.assertTrue({'xmm8', 'xmm9'} <= live)
            self.assertNotIn('xmm10', live)
