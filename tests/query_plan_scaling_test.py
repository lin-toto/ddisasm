"""Connected joins must retain all evidence in the presence of unrelated uses."""
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

import gtirb
import snippets


class QueryPlanScalingTest(unittest.TestCase):
    def lift(self, source, compiler, extra=()):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            assembly, binary, ir = root / "input.S", root / "input", root / "input.gtirb"
            assembly.write_text(source + '\n.section .note.GNU-stack,"",@progbits\n')
            subprocess.run([compiler, "-nostdlib", "-static", "-no-pie",
                            "-Wl,--build-id=none", *extra, str(assembly), "-o", str(binary)],
                           check=True, capture_output=True)
            subprocess.run(["ddisasm", str(binary), "--ir", str(ir), "-j", "1",
                            "--with-souffle-relations"], check=True, timeout=180,
                           capture_output=True)
            return gtirb.IR.load_protobuf(ir).modules[0]

    @staticmethod
    def address(module, name):
        return next(module.symbols_named(name)).referent.address

    @unittest.skipUnless(shutil.which("gcc"), "x64 compiler required")
    def test_x64_overlapping_metadata_entry_bounds(self):
        module = self.lift('''
            .text
            .globl _start
            _start: xor %edi,%edi; mov $60,%eax; syscall
            .globl outer
            .type outer,@function
            outer:
                lea pool(%rip),%r11
                jmp inner
            .globl inner
            .type inner,@function
            inner: mov 0(%r11),%rax; ret
            .size inner,.-inner
            .size outer,.-outer
            .globl outside
            .type outside,@function
            outside: mov 8(%r11),%rax; ret
            .size outside,.-outside
            .p2align 3
            .type pool,@object
            pool: .quad 1,2
            .size pool,.-pool
        ''', "gcc")
        pairs = set(snippets.parse_souffle_output(module, "metadata_function_entry_between"))
        definition = self.address(module, "outer")
        self.assertIn((definition, self.address(module, "inner")), pairs)
        self.assertNotIn((definition, self.address(module, "outside")), pairs)

    @unittest.skipUnless(shutil.which("gcc"), "x64 compiler required")
    def test_x64_function_local_fixed_reads(self):
        count = int(os.environ.get("DDISASM_QUERY_SCALE", "128"))
        source = ['.text\n.globl _start\n_start: xor %edi,%edi; mov $60,%eax; syscall']
        for i in range(count):
            copied = i % 2 == 1
            base = "%r11" if copied else "%r10"
            source.append(f'''
                .p2align 4
                .globl def_{i}
                .type def_{i},@function
                def_{i}:
                .cfi_startproc
                    lea pool_{i}(%rip),%r10
                    {'mov %r10,%r11' if copied else 'nop'}
                    test %edi,%edi
                    je read_{i}_0
                    nop
                read_{i}_0: mov 0({base}),%rax
                read_{i}_1: mov 8({base}),%rdx
                    ret
                .cfi_endproc
                .size def_{i},.-def_{i}
                .p2align 3
                .type pool_{i},@object
                pool_{i}: .quad 1,2
                .size pool_{i},.-pool_{i}
            ''')
        module = self.lift('\n'.join(source), "gcc")
        definitions = {self.address(module, f"def_{i}") for i in range(count)}
        expected = {
            (self.address(module, f"def_{i}"), self.address(module, f"pool_{i}"),
             self.address(module, f"read_{i}_{j}"), self.address(module, f"pool_{i}") + 8 * j, 8)
            for i in range(count) for j in range(2)
        }
        actual = {row for row in snippets.parse_souffle_output(
            module, "metadata_function_reachable_fixed_data_use") if row[0] in definitions}
        self.assertEqual(actual, expected)

    @unittest.skipUnless(shutil.which("riscv64-linux-gnu-gcc"), "RV64 compiler required")
    def test_riscv_connected_relative_tables(self):
        count = int(os.environ.get("DDISASM_QUERY_SCALE", "128"))
        source = ['''
            .option norvc
            .option norelax
            .text
            .globl _start
            _start: li a0,0; call dispatch_0; li a7,93; ecall
        ''']
        for i in range(count):
            load = ".option rvc\nc.lw a2,0(a0)\n.option norvc" if i % 2 else "lw a2,0(a0)"
            source.append(f'''
                .text
                .p2align 2
                .globl dispatch_{i}
                .type dispatch_{i},@function
                dispatch_{i}:
                    li t0,1
                    bgtu a0,t0,default_{i}
                base_{i}: auipc a1,%pcrel_hi(table_{i})
                    addi a1,a1,%pcrel_lo(base_{i})
                    slli a0,a0,2
                    add a0,a0,a1
                load_{i}: {load}
                    add a2,a2,a1
                jump_{i}: jr a2
                case_{i}_0: li a0,1; ret
                case_{i}_1: li a0,2; ret
                default_{i}: li a0,3; ret
                .size dispatch_{i},.-dispatch_{i}

                .type decoy_{i},@function
                decoy_{i}:
                decoy_base_{i}: auipc t0,%pcrel_hi(table_{i})
                    addi t0,t0,%pcrel_lo(decoy_base_{i})
                    slli t1,a0,2
                    ret
                .size decoy_{i},.-decoy_{i}

                .section .rodata
                .p2align 2
                .type table_{i},@object
                table_{i}: .word case_{i}_0-table_{i},case_{i}_1-table_{i}
                .size table_{i},.-table_{i}
            ''')
        module = self.lift('\n'.join(source), "riscv64-linux-gnu-gcc",
                           ("-march=rv64imac", "-mabi=lp64", "-Wl,--no-relax"))
        expected = {
            (self.address(module, f"jump_{i}"), self.address(module, f"table_{i}"),
             self.address(module, f"load_{i}")) for i in range(count)
        }
        actual = {row[:3] for row in snippets.parse_souffle_output(
            module, "riscv_relative_jump_table_access")}
        self.assertEqual(actual, expected)
        for i in range(count):
            table = next(module.symbols_named(f"table_{i}")).referent
            for j in range(2):
                expression = table.byte_interval.symbolic_expressions[table.offset + 4 * j]
                self.assertIsInstance(expression, gtirb.SymAddrAddr)
                self.assertEqual(expression.symbol1.referent.address,
                                 self.address(module, f"case_{i}_{j}"))
                self.assertEqual(expression.symbol2.referent.address, table.address)


if __name__ == "__main__":
    unittest.main()
