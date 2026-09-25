"""Local GOT references must preserve addresses and never name ISA markers."""
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

import gtirb
from elftools.elf.elffile import ELFFile


@unittest.skipUnless(all(shutil.which(t) for t in ('riscv64-linux-gnu-gcc',
    'riscv64-linux-gnu-objcopy', 'qemu-riscv64')), 'RISC-V toolchain required')
class RiscvLocalGotIdentityTest(unittest.TestCase):
    def check(self, shared, duplicate):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            objects = []
            for index in range(2):
                callback = 'callback' if duplicate else 'callback_%d' % index
                source = root / ('part%d.S' % index)
                source.write_text('''
                    .option pic
                    .option norelax
                    .option norvc
                    .text
                    .globl get_{i}
                    .type get_{i},@function
                get_{i}:
                    la a0,{callback}
                    ret
                    .size get_{i},.-get_{i}
                    .type {callback},@function
                    .local {callback}
                    .local $xrv64i2p1_m2p0_a2p1_f2p2_d2p2_c2p0
                $xrv64i2p1_m2p0_a2p1_f2p2_d2p2_c2p0:
                callback_anchor_{i}:
                {callback}:
                    li a0,{value}
                    ret
                    .size {callback},.-{callback}
                    .section .note.GNU-stack,"",@progbits
                '''.format(i=index, callback=callback, value=11 + index))
                obj = source.with_suffix('.o')
                subprocess.run(['riscv64-linux-gnu-gcc', '-c', str(source), '-o', str(obj)],
                               check=True, capture_output=True)
                objects.append(str(obj))
            start = root / 'start.S'
            start.write_text('''
                .text
                .globl _start
                .type _start,@function
            _start:
                call get_0
                jalr a0
                li t0,11
                bne a0,t0,fail
                call get_1
                jalr a0
                li t0,12
                bne a0,t0,fail
                li a0,0
                j done
            fail:
                li a0,1
            done:
                li a7,93
                ecall
                .size _start,.-_start
                .section .note.GNU-stack,"",@progbits
            ''')
            original, irpath = root / 'original', root / 'output.gtirb'
            flags = ['-shared'] if shared else ['-static', '-no-pie', str(start)]
            subprocess.run(['riscv64-linux-gnu-gcc', '-nostdlib', '-Wl,--no-relax',
                *flags, *objects, '-o', str(original)], check=True, capture_output=True)
            with original.open('rb') as stream:
                elf = ELFFile(stream)
                table = elf.get_section_by_name('.symtab')
                expected = [table.get_symbol_by_name('callback_anchor_%d' % i)[0]['st_value']
                            for i in range(2)]
            subprocess.run(['riscv64-linux-gnu-objcopy', '--strip-symbol=callback_anchor_0',
                '--strip-symbol=callback_anchor_1', str(original)], check=True, capture_output=True)
            subprocess.run(['ddisasm', str(original), '--ir', str(irpath), '-j', '1'],
                           check=True, capture_output=True)
            module = gtirb.IR.load_protobuf(irpath).modules[0]
            for index, address in enumerate(expected):
                block = next(module.symbols_named('get_%d' % index)).referent
                expr = block.byte_interval.symbolic_expressions[block.offset]
                self.assertIsInstance(expr, gtirb.SymAddrConst)
                self.assertIn(gtirb.SymbolicExpression.Attribute.GOT, expr.attributes)
                self.assertFalse(expr.symbol.name.startswith('$'), expr.symbol.name)
                self.assertEqual(expr.symbol.referent.address + expr.offset, address)
            assembly, rebuilt = root / 'out.S', root / 'rebuilt'
            subprocess.run(['gtirb-pprinter', '--ir', str(irpath), '--asm', str(assembly),
                '--policy', 'complete', '--shared', 'no'], check=True, capture_output=True)
            link = subprocess.run(['riscv64-linux-gnu-gcc', '-nostdlib', '-static', '-no-pie',
                '-Wl,--no-relax', str(assembly), *([str(start)] if shared else []),
                '-o', str(rebuilt)], capture_output=True)
            self.assertEqual(link.returncode, 0, link.stderr.decode(errors='replace'))
            run = subprocess.run(['qemu-riscv64', str(rebuilt)], capture_output=True)
            self.assertEqual((run.returncode, run.stdout, run.stderr), (0, b'', b''))

    def test_shared_local_mapping_alias(self):
        self.check(shared=True, duplicate=False)

    def test_shared_duplicate_local_targets(self):
        self.check(shared=True, duplicate=True)

    def test_static_duplicate_local_targets(self):
        self.check(shared=False, duplicate=True)


if __name__ == '__main__':
    unittest.main()
