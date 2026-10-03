"""A direct call passes on the condition flags its callee reads first."""
import ctypes.util
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

import gtirb
from gtirb_capstone.instructions import GtirbInstructionDecoder
from disassemble_reassemble_check import disassemble

START = """.text
        .globl _start
        .type _start,@function
        _start:
          mov $60,%eax
          xor %edi,%edi
          syscall
        .size _start,.-_start
        """

# Like OpenSSL's __rsaz_512_mulx: no flag write before the first ADC.
CARRY_HELPER = """
        .type carry_helper,@function
        carry_helper:
          mov $7,%r8
          mov %rdx,%rax
          adc %rax,%r8
          ret
        .size carry_helper,.-carry_helper
        .section .note.GNU-stack,"",@progbits
        """


def caller(name, call, after=""):
    """rsaz_512_mul's pattern: CMP leaves CF = 0, and JE reaches the call through flag-free moves."""
    return f"""
        .globl {name}
        .type {name},@function
        {name}:
          cmp $0x80100,%r11d
          je 1f
          ret
        1:
          mov $5,%rdx
          mov %rdx,%rbp
          {call}
          {after}
          ret
        .size {name},.-{name}
        """


@unittest.skipUnless(shutil.which('gcc'), 'x64 compiler required')
class X64FlagLivenessTest(unittest.TestCase):
    @staticmethod
    def _flag_liveness(asm, link_flags=()):
        """Lift a probe program; return it and a function giving [(mnemonic, rflags live)] for a function."""
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root/'input.S').write_text(asm)
            subprocess.run(['gcc', '-nostdlib', '-no-pie', str(root/'input.S'), *link_flags,
                            '-o', str(root/'input')], check=True)
            module = disassemble(root/'input').ir().modules[0]
        bit = 1 << module.aux_data['liveRegisterNames'].data.index('rflags')
        masks = module.aux_data['liveRegisterSets'].data
        decoder = GtirbInstructionDecoder(module.isa)
        live = {}
        for block in module.code_blocks:
            for insn in decoder.get_instructions(block):
                offset = gtirb.Offset(block, insn.address - block.address)
                live[insn.address] = (insn.mnemonic, bool(masks[offset] & bit))
        sizes = module.aux_data['elfSymbolInfo'].data

        def function(name):
            symbol = next(module.symbols_named(name))
            start = symbol.referent.address
            return [live[a] for a in sorted(live) if start <= a < start + sizes[symbol][0]]
        return module, function

    def test_direct_calls_pass_on_what_the_callee_reads(self):
        # A call kills the flags for its return site, but not for its callee:
        # the caller's CF is live from the JE target through the call. A callee
        # that writes every flag before reading one still has none live at the
        # call, even though the return site reads CF.
        asm = START + caller('carry_caller', 'call carry_helper')
        asm += """
        .globl set_caller
        .type set_caller,@function
        set_caller:
          mov $5,%rdx
          stc
          call carry_helper
          ret
        .size set_caller,.-set_caller
        .type tail_entry,@function
        tail_entry:
          jmp carry_helper
        .size tail_entry,.-tail_entry
        .type nested_entry,@function
        nested_entry:
          call carry_helper
          ret
        .size nested_entry,.-nested_entry
        .type writer_helper,@function
        writer_helper:
          add %rdx,%rax
          adc %rdx,%r8
          ret
        .size writer_helper,.-writer_helper
        """
        asm += caller('tail_caller', 'call tail_entry')
        asm += caller('nested_caller', 'call nested_entry')
        asm += caller('writer_caller', 'call writer_helper', 'adc $0,%rax')
        asm += CARRY_HELPER
        _, function = self._flag_liveness(asm)
        F, T = False, True
        window = [('cmp', F), ('je', T), ('ret', F), ('mov', T), ('mov', T), ('call', T), ('ret', F)]
        for name in ('carry_caller', 'tail_caller', 'nested_caller'):
            with self.subTest(function=name):
                self.assertEqual(function(name), window)
        expected = {
            'carry_helper': [('mov', T), ('mov', T), ('adc', T), ('ret', F)],
            # STC writes CF, the only flag the callee reads.
            'set_caller': [('mov', F), ('stc', F), ('call', T), ('ret', F)],
            'tail_entry': [('jmp', T)],
            'nested_entry': [('call', T), ('ret', F)],
            'writer_helper': [('add', F), ('adc', T), ('ret', F)],
            'writer_caller': [('cmp', F), ('je', T), ('ret', F), ('mov', F), ('mov', F),
                              ('call', F), ('adc', T), ('ret', F)],
        }
        for name, states in expected.items():
            with self.subTest(function=name):
                self.assertEqual(function(name), states)

    @unittest.skipUnless(ctypes.util.find_library('m'), 'a shared libm is required')
    def test_indirect_and_plt_calls_pass_no_flags(self):
        # The ABI assumption stays for an unresolved indirect call, an
        # indirect call that the CFG resolves to a callee reading CF, and a
        # call through a lazy PLT stub, whose jump keeps every flag live.
        # No --emit-relocs: the call to sin then targets the stub's block.
        asm = START + caller('indirect_caller', 'call *%r11')
        asm += caller('resolved_caller', 'lea carry_helper(%rip),%rax; call *%rax')
        asm += caller('plt_caller', 'call sin@PLT')
        asm += CARRY_HELPER
        module, function = self._flag_liveness(asm, ['-lm'])
        F, T = False, True
        dead = [('cmp', F), ('je', T), ('ret', F), ('mov', F), ('mov', F), ('call', F), ('ret', F)]
        for name in ('indirect_caller', 'plt_caller'):
            with self.subTest(function=name):
                self.assertEqual(function(name), dead)
        with self.subTest(function='resolved_caller'):
            self.assertEqual(function('resolved_caller'), dead[:5] + [('lea', F)] + dead[5:])
        self.assertEqual(function('carry_helper'), [('mov', T), ('mov', T), ('adc', T), ('ret', F)])
        # The probes above reach the cases they are meant to: a resolved
        # indirect call edge into carry_helper, and a direct call into a PLT stub.
        helper = next(module.symbols_named('carry_helper')).referent
        calls = [e for e in module.ir.cfg if e.label is not None and e.label.type == gtirb.EdgeType.Call]
        self.assertTrue(any(e.target is helper and not e.label.direct for e in calls))
        self.assertTrue(any(e.label.direct and isinstance(e.target, gtirb.CodeBlock) and
                            e.target.section.name.startswith('.plt') for e in calls))


if __name__ == '__main__':
    unittest.main()
