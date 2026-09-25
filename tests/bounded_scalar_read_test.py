"""A bounded memory read describes scalar fields, not a register value load."""
from pathlib import Path
import subprocess
import tempfile
import unittest

import gtirb
from gtirb_capstone.instructions import GtirbInstructionDecoder
import snippets


class BoundedScalarReadTests(unittest.TestCase):
    def check_read(self, operation, expect_scalar):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source, binary = root / 'read.S', root / 'read'
            source.write_text('''
.text
.globl main
.type main,@function
main:
    leaq scalar_table(%rip), %rax
    andl $63, %edi
    ''' + operation + '''
    movq 384(%rax), %r10
    movl %esi, %eax
    ret
.size main,.-main
.section .rodata
.p2align 3
.type scalar_table,@object
scalar_table:
    .zero 128
    .long 0x500028, 0
    .zero 384-(.-scalar_table)
    .quad 0x500028
    .zero 512-(.-scalar_table)
.size scalar_table,.-scalar_table
.data
.p2align 3
.type destination,@object
destination:
    .zero 64
.size destination,.-destination
.section .note.GNU-stack,"",@progbits
''')
            subprocess.run(['gcc', '-no-pie', '-Wl,-Tdata=0x500000',
                            str(source), '-o', str(binary)],
                           check=True, capture_output=True)
            module = snippets.disassemble_to_gtirb(str(binary))
        table = next(module.symbols_named('scalar_table')).referent.address
        main = next(module.symbols_named('main')).referent
        access = list(GtirbInstructionDecoder(module.isa).get_instructions(main))[2].address
        expressions = {interval.address + offset: expression for interval in module.byte_intervals
                       for offset, expression in interval.symbolic_expressions.items()}
        ranges = list(snippets.parse_souffle_output(module, 'bounded_subpointer_width_access'))
        witness = any(row[0] <= table + 128 and table + 136 <= row[1] and row[-1] == access
                      for row in ranges)
        if witness != expect_scalar:
            evidence = {'access': hex(access), 'table': hex(table), 'ranges': ranges,
                        'bounds': [row for row in snippets.parse_souffle_output(module, 'last_value_reg_limit')
                                   if row[1] == access],
                        'values': [row for row in snippets.parse_souffle_output(module, 'value_reg_at_operand')
                                   if row[0] == access]}
            self.fail('bounded field-width evidence differs: ' + repr(evidence))
        if expect_scalar:
            self.assertFalse(table + 128 in expressions, 'two uint32 fields became one guessed pointer')
        # A real pointer-width access outside the masked subarray must survive.
        self.assertIsInstance(expressions[table + 384], gtirb.SymAddrConst)
        loads = list(snippets.parse_souffle_output(module, 'arch.memory_access'))
        if not operation.startswith('movl'):
            self.assertFalse(any(row[0] == 'LOAD' and row[1] == access for row in loads),
                             'arithmetic/read evidence must not broaden arch.load')

    def test_move_memory_read(self):
        self.check_read('movl (%rax,%rdi,4), %esi', True)

    def test_xor_memory_read(self):
        self.check_read('xorl (%rax,%rdi,4), %esi', True)

    def test_add_memory_read(self):
        self.check_read('addl (%rax,%rdi,4), %esi', True)

    def test_compare_memory_read(self):
        self.check_read('cmpl (%rax,%rdi,4), %esi', True)

    def test_lea_is_not_a_memory_read(self):
        self.check_read('leaq (%rax,%rdi,4), %rsi', False)


if __name__ == '__main__':
    unittest.main()
