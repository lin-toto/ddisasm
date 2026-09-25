"""AArch64 literal-load immediates are addresses in DYN as well as EXEC."""
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

import gtirb


@unittest.skipUnless(shutil.which('aarch64-linux-gnu-gcc') and shutil.which('qemu-aarch64'),
                     'AArch64 compiler and emulator required')
class Arm64LiteralLoadTest(unittest.TestCase):
    def check(self, shared):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / 'literal.S'
            source.write_text('''
                .text
                .globl _start, load64, load32, load_signed, load_double, load_vector
                .type _start,%function
            _start:
            load64: ldr x0,pool64
            load32: ldr w1,pool32
            load_signed: ldrsw x2,pool_signed
            load_double: ldr d0,pool64
            load_vector: ldr q1,pool_vector
                add x0,x0,x1
                add x0,x0,x2
                sub x0,x0,#42
                mov x8,#93
                svc #0
                .size _start,.-_start
                .section .rodata
                .p2align 4
                .type pool64,%object
            pool64: .quad 40
                .size pool64,8
                .type pool32,%object
            pool32: .word 4
                .size pool32,4
                .type pool_signed,%object
            pool_signed: .word -2
                .size pool_signed,4
                .type pool_vector,%object
            pool_vector: .quad 1,2
                .size pool_vector,16
                .section .note.GNU-stack,"",%progbits
            ''')
            original, irpath = root / 'original', root / 'output.gtirb'
            subprocess.run(['aarch64-linux-gnu-gcc', '-nostdlib',
                *(['-shared', '-Wl,-Bsymbolic'] if shared else ['-static', '-no-pie']),
                str(source), '-o', str(original)], check=True, capture_output=True)
            subprocess.run(['ddisasm', str(original), '--ir', str(irpath), '-j', '1'],
                           check=True, capture_output=True)
            module = gtirb.IR.load_protobuf(irpath).modules[0]
            for instruction, pool in [('load64', 'pool64'), ('load32', 'pool32'),
                    ('load_signed', 'pool_signed'), ('load_double', 'pool64'),
                    ('load_vector', 'pool_vector')]:
                with self.subTest(instruction=instruction):
                    block = next(module.symbols_named(instruction)).referent
                    address = next(module.symbols_named(pool)).referent.address
                    expr = block.byte_interval.symbolic_expressions.get(block.offset)
                    self.assertIsInstance(expr, gtirb.SymAddrConst)
                    self.assertEqual(expr.symbol.referent.address + expr.offset, address)
            assembly, rebuilt = root / 'out.S', root / 'rebuilt'
            subprocess.run(['gtirb-pprinter', '--ir', str(irpath), '--asm', str(assembly),
                '--shared', 'no', '--policy', 'complete'], check=True, capture_output=True)
            subprocess.run(['aarch64-linux-gnu-gcc', '-nostdlib', '-static', '-no-pie',
                str(assembly), '-o', str(rebuilt)], check=True, capture_output=True)
            run = subprocess.run(['qemu-aarch64', str(rebuilt)], capture_output=True)
            self.assertEqual((run.returncode, run.stdout, run.stderr), (0, b'', b''))

    def test_shared_literals(self):
        self.check(shared=True)

    def test_executable_literals(self):
        self.check(shared=False)


if __name__ == '__main__':
    unittest.main()
