"""Split addresses must retain their section side after unrelated data moves."""
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

import gtirb


class SplitBoundaryAliasesTest(unittest.TestCase):
    def check_boundary(self, arch, body, high_names, low_names=(), second_section='.second'):
        compiler = arch + '-linux-gnu-gcc'
        emulator = 'qemu-' + arch
        if not shutil.which(compiler) or not shutil.which(emulator):
            self.skipTest('cross compiler and emulator required')
        source = body + '''
            .section .first,"aw",@progbits
            .balign 8
            range_begin: .quad 5, 12
            range_end:
            .section .second,"aw",@progbits
            other_begin: .quad 41
            .section .note.GNU-stack,"",@progbits
        '''
        source = source.replace('.second', second_section)
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            assembly, original = root / 'input.S', root / 'original'
            assembly.write_text(source)
            cc = [compiler, '-nostdlib', '-static', '-no-pie',
                  '-Wl,--build-id=none,--no-relax']
            if arch == 'riscv64':
                cc += ['-march=rv64imac', '-mabi=lp64']
            initial = ['-Wl,--section-start=.text=0x400000',
                       '-Wl,--section-start=.first=0x480ff0',
                       f'-Wl,--section-start={second_section}=0x481000']
            subprocess.run(cc + [str(assembly), '-o', str(original)] + initial,
                           check=True, capture_output=True)
            self.assertEqual(subprocess.run([emulator, str(original)],
                capture_output=True, timeout=10).returncode, 0)
            ir = root / 'input.gtirb'
            subprocess.run(['ddisasm', str(original), '--ir', str(ir), '-j', '1'],
                           check=True, capture_output=True)
            module = gtirb.IR.load_protobuf(ir).modules[0]
            first = next(s for s in module.sections if s.name == '.first')
            second = next(s for s in module.sections if s.name == second_section)
            self.assertEqual(first.address + first.size, second.address)

            def expression(name):
                symbol = next(module.symbols_named(name))
                block = symbol.referent
                return block.byte_interval.symbolic_expressions[block.offset]

            for name in high_names:
                with self.subTest(expression=name):
                    expr = expression(name)
                    self.assertIsInstance(expr, gtirb.SymAddrConst)
                    self.assertIs(expr.symbol.referent.section, first)
                    self.assertTrue(expr.symbol.at_end)
                    self.assertEqual(expr.offset, 0)
            for name in low_names:
                with self.subTest(expression=name):
                    expr = expression(name)
                    self.assertIs(expr.symbol.referent,
                                  next(module.symbols_named('end_high')).referent)
            # The same original numeric value can legitimately name the next
            # section in another address construction. Do not retarget all uses.
            if second_section != '.got':
                self.assertIs(expression('other_address').symbol.referent.section, second)
                self.assertFalse(expression('other_address').symbol.at_end)
            if arch == 'aarch64':
                loop = next(module.symbols_named('loop')).referent
                self.assertNotIn(loop.offset, loop.byte_interval.symbolic_expressions,
                                 'pre-index -8 is a numeric cursor increment, not a GOT offset')
            printed = root / 'printed.S'
            subprocess.run(['gtirb-pprinter', '--ir', str(ir), '--asm', str(printed),
                            '--policy', 'complete'], check=True, capture_output=True)
            for first_address, second_address in ((0x500000, 0x620000),
                                                   (0x510ff0, 0x630078)):
                with self.subTest(first_address=first_address):
                    rebuilt = root / 'rebuilt'
                    linked = subprocess.run(cc + [str(printed), '-o', str(rebuilt),
                        '-Wl,--section-start=.text=0x400000',
                        f'-Wl,--section-start=.first={first_address:#x}',
                        f'-Wl,--section-start={second_section}={second_address:#x}'],
                        capture_output=True)
                    self.assertEqual(linked.returncode, 0, linked.stderr.decode())
                    result = subprocess.run([emulator, str(rebuilt)],
                                            capture_output=True, timeout=10)
                    self.assertEqual(result.returncode, 0, result.stderr)

    def test_arm64_compare_does_not_destroy_the_completed_pointer(self):
        self.check_arm64('.second')

    def test_arm64_got_adjacency_keeps_preindex_displacement_numeric(self):
        self.check_arm64('.got')

    def check_arm64(self, second_section):
        # The ordinary data-section variant checks the opposite-side reference.
        # The GOT variant only tests an adjacent array cursor; reconstructing a
        # synthetic static GOT-address function is a different printer contract.
        other = '' if second_section == '.got' else '''
            .type other_address,@function
            other_address:
                adrp x0, other_begin
                add x0, x0, :lo12:other_begin
                ret
            .size other_address,.-other_address
        '''
        self.check_boundary('aarch64', '''
            .text
            .globl _start
            .type _start,@function
            _start:
            end_high: adrp x0, range_end
                adrp x20, range_begin
            end_low: add x0, x0, :lo12:range_end
                add x1, x20, :lo12:range_begin
                cmp x0, x1
                b.eq fail
                mov x19, x0
                mov x2, #0
            loop:
                ldr x3, [x19,#-8]!
                add x2, x2, x3
                cmp x19, x1
                b.ne loop
                cmp x2, #17
                cset w0, ne
                b done
            fail: mov w0, #1
            done: mov x8, #93
                svc #0
            .size _start,.-_start
        ''' + other, ('end_high', 'end_low'), second_section=second_section)

    def test_riscv_shared_high_absolute_boundary(self):
        self.check_riscv(False)

    def test_riscv_shared_high_pcrel_boundary(self):
        self.check_riscv(True)

    def check_riscv(self, pcrel):
        high = 'auipc' if pcrel else 'lui'
        end_hi = '%pcrel_hi(range_end)' if pcrel else '%hi(range_end)'
        end_lo = '%pcrel_lo(end_high)' if pcrel else '%lo(range_end)'
        self.check_boundary('riscv64', f'''
            .option norvc
            .option norelax
            .text
            .globl _start
            .type _start,@function
            _start:
            end_high: {high} s0, {end_hi}
                lui s1, %hi(range_begin)
            end_compare: addi a5, s0, {end_lo}
                addi s1, s1, %lo(range_begin)
                beq a5, s1, fail
            end_cursor: addi s0, s0, {end_lo}
                li a0, 0
            loop:
                ld a5, -8(s0)
                addi s0, s0, -8
                add a0, a0, a5
                bne s0, s1, loop
                addi a0, a0, -17
                snez a0, a0
                j done
            fail: li a0, 1
            done: li a7, 93
                ecall
            .size _start,.-_start
            .type other_address,@function
            other_address:
                lui a0, %hi(other_begin)
                addi a0, a0, %lo(other_begin)
                ret
            .size other_address,.-other_address
        ''', ('end_high',) if pcrel else ('end_high', 'end_compare', 'end_cursor'),
            ('end_compare', 'end_cursor') if pcrel else ())


if __name__ == '__main__':
    unittest.main()
