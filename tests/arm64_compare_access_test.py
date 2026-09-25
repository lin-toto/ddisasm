"""Flag-only aliases read their GPR operands without redefining them."""
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

import gtirb


@unittest.skipUnless(shutil.which('aarch64-linux-gnu-gcc'), 'AArch64 compiler required')
class Arm64CompareAccessTest(unittest.TestCase):
    def test_compare_and_test_alias_accesses(self):
        cases = (
            ('cmp64', 'cmp x0,x1', {'X0', 'X1'}),
            ('cmp32', 'cmp w0,w1', {'X0', 'X1'}),
            ('cmpimm', 'cmp x0,#1', {'X0'}),
            ('cmn64', 'cmn x0,x1', {'X0', 'X1'}),
            ('cmn32', 'cmn w0,w1', {'X0', 'X1'}),
            ('tst64', 'tst x0,x1', {'X0', 'X1'}),
            ('tst32', 'tst w0,w1', {'X0', 'X1'}),
            ('tstimm', 'tst x0,#1', {'X0'}),
            ('ccmp64', 'ccmp x0,x1,#0,eq', {'X0', 'X1'}),
            ('ccmp32', 'ccmp w0,w1,#0,eq', {'X0', 'X1'}),
            ('ccmpimm', 'ccmp x0,#1,#0,eq', {'X0'}),
            ('ccmn64', 'ccmn x0,x1,#0,eq', {'X0', 'X1'}),
            ('ccmn32', 'ccmn w0,w1,#0,eq', {'X0', 'X1'}),
        )
        source = '.text\n.globl _start\n.type _start,@function\n_start:\n'
        source += ''.join('bl check_' + name + '\n' for name, _, _ in cases)
        source += 'bl check_adds\nmov x8,#93\nmov x0,#0\nsvc #0\n.size _start,.-_start\n'
        for name, instruction, _ in cases:
            source += f'''
                .type check_{name},@function
                check_{name}: {instruction}
                    add x2,x0,#1
                    ret
                .size check_{name},.-check_{name}
            '''
        source += '''
            .type check_adds,@function
            check_adds: adds x0,x0,x1
                ret
            .size check_adds,.-check_adds
            .section .note.GNU-stack,"",@progbits
        '''
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            assembly, binary, ir = root / 'input.S', root / 'input', root / 'input.gtirb'
            assembly.write_text(source)
            subprocess.run(['aarch64-linux-gnu-gcc', '-nostdlib', '-static', '-no-pie',
                            str(assembly), '-o', str(binary)], check=True, capture_output=True)
            subprocess.run(['ddisasm', str(binary), '--ir', str(ir), '-j', '1',
                            '--debug-dir', str(root / 'facts')], check=True, capture_output=True)
            module = gtirb.IR.load_protobuf(ir).modules[0]
            relations = root / 'facts/disassembly'

            def registers(relation, address):
                return {fields[1] for line in (relations / (relation + '.csv')).read_text().splitlines()
                        if (fields := line.split('\t')) and int(fields[0], 0) == address}

            for name, _, expected_reads in cases:
                with self.subTest(alias=name):
                    address = next(module.symbols_named('check_' + name)).referent.address
                    self.assertTrue(expected_reads <= registers('reg_def_use.used', address))
                    writes = registers('reg_def_use.def', address)
                    self.assertFalse(expected_reads & writes)
                    self.assertIn('NZCV', writes)
            # Real arithmetic destinations must still terminate reaching defs.
            address = next(module.symbols_named('check_adds')).referent.address
            self.assertTrue({'X0', 'NZCV'} <= registers('reg_def_use.def', address))


if __name__ == '__main__':
    unittest.main()
