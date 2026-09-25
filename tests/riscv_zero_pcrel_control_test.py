"""Zero-offset JR/JALR aliases must retain both PC-relative relocation halves."""
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

import gtirb


@unittest.skipUnless(shutil.which('riscv64-linux-gnu-gcc') and shutil.which('qemu-riscv64'),
                     'RISC-V compiler and emulator required')
class RiscvZeroPcrelControlTest(unittest.TestCase):
    def check_transfer(self, operation, compressed, call):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / 'input.S'
            source.write_text('''
                .option norelax
                .option norvc
                .text
                .globl _start
                .type _start,@function
            _start:
                auipc t1,%pcrel_hi(target)
                .option {encoding}
                {operation} t1
                .option norvc
                li a7,93
                ecall
                .size _start,.-_start
                .section .target,"ax",@progbits
                .globl target
                .type target,@function
            target:
                li a0,7
                {finish}
                .size target,.-target
                .section .note.GNU-stack,"",@progbits
            '''.format(encoding='rvc' if compressed else 'norvc', operation=operation,
                       finish='ret' if call else 'li a7,93\n ecall'))
            original, lifted = root / 'original', root / 'lifted.gtirb'
            compiler = ['riscv64-linux-gnu-gcc', '-nostdlib', '-static', '-no-pie',
                        '-Wl,--no-relax,--build-id=none']
            subprocess.run(compiler + [str(source), '-o', str(original),
                '-Wl,--section-start=.text=0x400000', '-Wl,--section-start=.target=0x380000'],
                check=True, capture_output=True)
            self.assertEqual(subprocess.run(['qemu-riscv64', str(original)],
                             capture_output=True).returncode, 7)
            subprocess.run(['ddisasm', str(original), '--ir', str(lifted), '-j', '1'],
                           check=True, capture_output=True)
            module = gtirb.IR.load_protobuf(lifted).modules[0]
            start = next(module.symbols_named('_start')).referent
            target = next(module.symbols_named('target')).referent
            expressions = start.byte_interval.symbolic_expressions
            high = expressions.get(start.offset)
            low = expressions.get(start.offset + 4)
            attrs = gtirb.SymbolicExpression.Attribute
            self.assertIsInstance(high, gtirb.SymAddrConst)
            self.assertTrue({attrs.PCREL, attrs.HI}.issubset(high.attributes), high)
            self.assertEqual(high.symbol.referent.address + high.offset, target.address)
            self.assertIsInstance(low, gtirb.SymAddrConst)
            self.assertTrue({attrs.PCREL, attrs.LO}.issubset(low.attributes), low)
            self.assertEqual(low.symbol.referent.address + low.offset, start.address)
            self.assertTrue(any(edge.target == target and edge.label.direct and
                edge.label.type == (gtirb.Edge.Type.Call if call else gtirb.Edge.Type.Branch)
                for edge in module.ir.cfg))
            assembly = root / 'printed.S'
            subprocess.run(['gtirb-pprinter', '--ir', str(lifted), '--asm', str(assembly),
                            '--policy', 'complete'], check=True, capture_output=True)
            for address in (0x681ffc, 0x680040):
                with self.subTest(target_address=hex(address)):
                    rebuilt = root / 'rebuilt'
                    link = subprocess.run(compiler + [str(assembly), '-o', str(rebuilt),
                        '-Wl,--section-start=.text=0x500000',
                        '-Wl,--section-start=.target=%#x' % address], capture_output=True)
                    self.assertEqual(link.returncode, 0, link.stderr.decode(errors='replace'))
                    run = subprocess.run(['qemu-riscv64', str(rebuilt)], capture_output=True)
                    self.assertEqual((run.returncode, run.stdout, run.stderr), (7, b'', b''))

    def test_uncompressed_jump(self):
        self.check_transfer('jr', compressed=False, call=False)

    def test_compressed_jump(self):
        self.check_transfer('c.jr', compressed=True, call=False)

    def test_compressed_call(self):
        self.check_transfer('c.jalr', compressed=True, call=True)

    def test_uncompressed_call_control(self):
        self.check_transfer('jalr', compressed=False, call=True)


if __name__ == '__main__':
    unittest.main()
