"""A guarded relative dispatch must symbolize every in-range table entry.

JumpTableOracleTests uses only Python's standard library. Integration tests
assemble fixtures and invoke DDisasm but never execute the resulting binaries.
"""

import csv
import io
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest


def rows(text, width):
    result = [tuple(row) for row in csv.reader(io.StringIO(text), delimiter="\t")
              if row]
    if any(len(row) != width for row in result):
        raise ValueError("unexpected relation column count")
    return result


def check_table_relations(bounds, entries, table, targets):
    """Use inclusive last-entry addresses, matching jump_table_max's API."""
    actual_bounds = {(int(start, 0), int(end, 0)) for start, end in bounds
                     if int(start, 0) == table}
    expected_bounds = {(table, table + 4 * (len(targets) - 1))}
    if actual_bounds != expected_bounds:
        raise AssertionError((actual_bounds, expected_bounds))
    actual_entries = {
        tuple(int(field, 0) for field in row)
        for row in entries if int(row[1], 0) == table
    }
    expected_entries = {
        (table + 4 * i, table, 4, table, target, 1, 0)
        for i, target in enumerate(targets)
    }
    if actual_entries != expected_entries:
        raise AssertionError((actual_entries, expected_entries))


def symbol_addresses(binary):
    output = subprocess.run(["readelf", "-sW", str(binary)], check=True,
                            capture_output=True, text=True, timeout=15).stdout
    result = {}
    for line in output.splitlines():
        fields = line.split()
        if len(fields) >= 8 and fields[0].endswith(":") and fields[0][:-1].isdigit():
            result[fields[7]] = int(fields[1], 16)
    return result


class JumpTableOracleTests(unittest.TestCase):
    def table_entries(self, count):
        return [tuple(str(field) for field in
                      (0x20000 + 4 * i, 0x20000, 4, 0x20000,
                       0x10080 + 12 * i, 1, 0)) for i in range(count)]

    def test_seven_entries_with_inclusive_max(self):
        check_table_relations([("0x20000", "0x20018")], self.table_entries(7),
                              0x20000, [0x10080 + 12 * i for i in range(7)])

    def test_historical_four_entry_truncation_is_rejected(self):
        with self.assertRaises(AssertionError):
            check_table_relations([("0x20000", "0x20018")],
                                  self.table_entries(4), 0x20000,
                                  [0x10080 + 12 * i for i in range(7)])

    def test_off_by_one_bound_is_rejected(self):
        with self.assertRaises(AssertionError):
            check_table_relations([("0x20000", "0x20014")],
                                  self.table_entries(7), 0x20000,
                                  [0x10080 + 12 * i for i in range(7)])

    def test_unbounded_output_is_rejected(self):
        with self.assertRaises(AssertionError):
            check_table_relations([], self.table_entries(7), 0x20000,
                                  [0x10080 + 12 * i for i in range(7)])

    def test_relation_reader_rejects_missing_columns(self):
        with self.assertRaises(ValueError):
            rows("0x20000\n", 2)


@unittest.skipUnless(shutil.which("riscv64-linux-gnu-gcc")
                     and shutil.which("readelf"),
                     "RISC-V compiler and readelf required")
class RiscvJumpTableBoundsTest(unittest.TestCase):
    def test_guard_bound_reaches_every_entry(self):
        for bits in (32, 64):
            for in_place in (True, False):
                for guard in ("bltu", "bgeu"):
                    with self.subTest(bits=bits, in_place=in_place, guard=guard):
                        self.check_fixture(bits, in_place, guard, False)

    def test_redefined_index_does_not_reuse_guard(self):
        for bits in (32, 64):
            with self.subTest(bits=bits):
                self.check_fixture(bits, False, "bltu", True)

    def check_fixture(self, bits, in_place, guard, redefine):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            scaled = "a0" if in_place else "a1"
            constant, operands = ((6, "t0,a0") if guard == "bltu"
                                  else (7, "a0,t0"))
            cases = "\n".join(f"case{i}:\n    li a0,{i}\n    li a7,93\n    ecall"
                              for i in range(7))
            entries = "\n".join(f"    .long case{i}-switch_table"
                                for i in range(7))
            source = root / "switch.S"
            source.write_text(f"""
.option norvc
.option norelax
.text
.globl _start, switch_table, default, stray
.globl {','.join(f'case{i}' for i in range(7))}
.type _start,@function
_start:
.Lstray:
    auipc t4,%pcrel_hi(stray)
    {'ld' if bits == 64 else 'lw'} t4,%pcrel_lo(.Lstray)(t4)
    li t0,{constant}
    {guard} {operands},default
.Lbase:
    auipc t1,%pcrel_hi(switch_table)
    addi t1,t1,%pcrel_lo(.Lbase)
    {'li a0,20' if redefine else ''}
    slli {scaled},a0,2
    add t2,{scaled},t1
    lw t3,0(t2)
    add t3,t3,t1
    jalr zero,0(t3)
default:
    li a0,99
    li a7,93
    ecall
{cases}
.size _start,.-_start
.section .rodata,"a",@progbits
.p2align 2
/* No OBJECT extent is declared: the guard must establish the table bound. */
switch_table:
{entries}
.section .data,"aw",@progbits
.p2align {3 if bits == 64 else 2}
.type stray,@object
stray:
    {'.quad' if bits == 64 else '.long'} switch_table+16
.size stray,.-stray
.section .note.GNU-stack,"",@progbits
""")
            binary = root / "switch"
            subprocess.run([
                "riscv64-linux-gnu-gcc", f"-march=rv{bits}imac",
                f"-mabi={'ilp32' if bits == 32 else 'lp64'}", "-nostdlib",
                "-static", "-no-pie", "-Wl,--no-relax,--build-id=none",
                str(source), "-o", str(binary),
            ], check=True, capture_output=True, timeout=30)
            debug = root / "debug"
            subprocess.run([
                os.environ.get("DDISASM", "ddisasm"), str(binary),
                "--ir", str(root / "switch.gtirb"), "-j", "1",
                "--allow-ambiguous-data-pointers", "--debug-dir", str(debug),
            ], check=True, capture_output=True, timeout=120)
            addresses = symbol_addresses(binary)
            relations = debug / "disassembly"
            bounds = rows((relations / "jump_table_max.csv").read_text(), 2)
            table = addresses["switch_table"]
            if redefine:
                self.assertFalse(any(int(start, 0) == table for start, _ in bounds))
                return
            data_limits = rows((relations / "data_limit.csv").read_text(), 1)
            self.assertIn(table + 16, {int(row[0], 0) for row in data_limits},
                          "fixture did not create the interior table cutoff")
            entries = rows((relations / "relative_jump_table_entry.csv").read_text(), 7)
            check_table_relations(bounds, entries, table,
                                  [addresses[f"case{i}"] for i in range(7)])
            import gtirb

            module = gtirb.IR.load_protobuf(root / "switch.gtirb").modules[0]
            for index in range(7):
                address = table + 4 * index
                intervals = [interval for interval in module.byte_intervals
                             if interval.address is not None
                             and interval.address <= address
                             < interval.address + interval.size]
                self.assertEqual(len(intervals), 1)
                interval = intervals[0]
                expression = interval.symbolic_expressions.get(address - interval.address)
                self.assertIsInstance(expression, gtirb.SymAddrAddr)
                self.assertEqual(expression.scale, 1)
                self.assertEqual(expression.offset, 0)
                self.assertEqual(expression.symbol1.referent.address
                                 + (expression.symbol1.referent.size
                                    if expression.symbol1.at_end else 0),
                                 addresses[f"case{index}"])
                self.assertEqual(expression.symbol2.referent.address
                                 + (expression.symbol2.referent.size
                                    if expression.symbol2.at_end else 0), table)


if __name__ == "__main__":
    unittest.main()
