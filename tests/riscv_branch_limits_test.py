"""Ordered RISC-V branch operands must give one consistent bound per edge.

BranchOracleTests uses only Python's standard library. RiscvBranchLimitsTest
assembles fixtures and invokes DDisasm; it needs a built frontend and never
executes a fixture. Run that class separately after the frontend build.
"""

import csv
import io
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest


# Expected A0 bounds for K = 6. Each pair is (taken, fallthrough).
# An entry is (limit type, value); equality does not yield a MIN/MAX bound.
BRANCH_CASES = (
    ("blt", "L", False, ("MAX", 5), ("MIN", 6)),
    ("blt", "L", True, ("MIN", 7), ("MAX", 6)),
    ("bge", "GE", False, ("MIN", 6), ("MAX", 5)),
    ("bge", "GE", True, ("MAX", 6), ("MIN", 7)),
    ("bltu", "B", False, ("MAX", 5), ("MIN", 6)),
    ("bltu", "B", True, ("MIN", 7), ("MAX", 6)),
    ("bgeu", "AE", False, ("MIN", 6), ("MAX", 5)),
    ("bgeu", "AE", True, ("MAX", 6), ("MIN", 7)),
    ("beq", "E", False, None, None),
    ("beq", "E", True, None, None),
    ("bne", "NE", False, None, None),
    ("bne", "NE", True, None, None),
)


def relation_rows(text, width):
    """Read a debug relation, rejecting incomplete evidence."""
    rows = [tuple(row) for row in csv.reader(io.StringIO(text), delimiter="\t")
            if row]
    if any(len(row) != width for row in rows):
        raise ValueError("unexpected relation column count")
    return rows


def check_branch_rows(comparisons, limits, addresses, cc, constant_on_left,
                      taken_bound, fallthrough_bound, constant_reg="T0",
                      value_reg="A0"):
    """Compare actual relation tuples to an independent per-edge oracle."""
    probe, taken, fallthrough = addresses
    lhs, rhs = ((constant_reg, value_reg) if constant_on_left
                else (value_reg, constant_reg))
    actual_comparisons = {
        (int(row[0], 0), int(row[1], 0), *row[2:])
        for row in comparisons if int(row[1], 0) == probe
    }
    expected_comparisons = {(probe, probe, cc, rhs, lhs)}
    if actual_comparisons != expected_comparisons:
        raise AssertionError((actual_comparisons, expected_comparisons))
    actual_limits = {
        (int(row[1], 0), row[4], int(row[3], 0))
        for row in limits if int(row[0], 0) == probe and row[2] == value_reg
    }
    expected_limits = {
        (edge, bound[0], bound[1])
        for edge, bound in ((taken, taken_bound), (fallthrough, fallthrough_bound))
        if bound is not None
    }
    if actual_limits != expected_limits:
        raise AssertionError((actual_limits, expected_limits))


def read_symbol_addresses(binary):
    result = subprocess.run(["readelf", "-sW", str(binary)], check=True,
                            capture_output=True, text=True, timeout=15)
    symbols = {}
    for line in result.stdout.splitlines():
        fields = line.split()
        if len(fields) >= 8 and fields[0].endswith(":") and fields[0][:-1].isdigit():
            symbols[fields[7]] = int(fields[1], 16)
    return symbols


class BranchOracleTests(unittest.TestCase):
    def test_known_correct_constant_on_left_limits(self):
        check_branch_rows(
            [("0x10004", "0x10004", "B", "A0", "T0")],
            [("0x10004", "0x10014", "A0", "7", "MIN"),
             ("0x10004", "0x10008", "A0", "6", "MAX")],
            (0x10004, 0x10014, 0x10008), "B", True,
            ("MIN", 7), ("MAX", 6))

    def test_unordered_duplicate_is_rejected(self):
        with self.assertRaises(AssertionError):
            check_branch_rows(
                [("4", "4", "B", "A0", "T0"),
                 ("4", "4", "B", "T0", "A0")], [],
                (4, 20, 8), "B", True, ("MIN", 7), ("MAX", 6))

    def test_old_off_by_one_is_rejected(self):
        with self.assertRaises(AssertionError):
            check_branch_rows(
                [("4", "4", "B", "A0", "T0")],
                [("4", "20", "A0", "6", "MIN"),
                 ("4", "8", "A0", "5", "MAX")],
                (4, 20, 8), "B", True, ("MIN", 7), ("MAX", 6))

    def test_relation_reader_rejects_missing_columns(self):
        with self.assertRaises(ValueError):
            relation_rows("4\t4\tB\tA0\n", 5)
        self.assertEqual(relation_rows("", 5), [])


@unittest.skipUnless(shutil.which("riscv64-linux-gnu-gcc")
                     and shutil.which("readelf"),
                     "RISC-V compiler and readelf required")
class RiscvBranchLimitsTest(unittest.TestCase):
    def test_both_operand_orders_and_both_register_widths(self):
        for bits in (32, 64):
            for mnemonic, cc, const_left, taken, fallthrough in BRANCH_CASES:
                with self.subTest(bits=bits, mnemonic=mnemonic,
                                  constant_on_left=const_left):
                    self.check_fixture(bits, mnemonic, cc, const_left,
                                       taken, fallthrough)

    def check_fixture(self, bits, mnemonic, cc, const_left, taken, fallthrough):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "branch.S"
            lhs, rhs = ("t0", "a0") if const_left else ("a0", "t0")
            source.write_text(f"""
.option norvc
.option norelax
.text
.globl _start, fallthrough, taken
.type _start,@function
_start:
    li t0,6
.Lprobe:
    {mnemonic} {lhs},{rhs},taken
fallthrough:
    li a7,93
    ecall
taken:
    li a7,93
    ecall
.size _start,.-_start
.section .note.GNU-stack,"",@progbits
""")
            binary = root / "branch"
            subprocess.run([
                "riscv64-linux-gnu-gcc", f"-march=rv{bits}imac",
                f"-mabi={'ilp32' if bits == 32 else 'lp64'}", "-nostdlib",
                "-static", "-no-pie", "-Wl,--no-relax,--build-id=none",
                str(source), "-o", str(binary),
            ], check=True, capture_output=True, timeout=30)
            debug = root / "debug"
            subprocess.run([
                os.environ.get("DDISASM", "ddisasm"), str(binary),
                "--ir", str(root / "branch.gtirb"), "-j", "1",
                "--debug-dir", str(debug),
            ], check=True, capture_output=True, timeout=120)
            addresses = read_symbol_addresses(binary)
            # A global probe symbol would split the constant definition and
            # branch into separate blocks, outside this rule's same-block scope.
            # With norvc, the preceding li t0,6 is one four-byte instruction.
            addresses["probe"] = addresses["_start"] + 4
            relations = debug / "disassembly"
            comparisons = relation_rows(
                (relations / "compare_and_jump_register.csv").read_text(), 5)
            limits = relation_rows(
                (relations / "value_reg_limit.csv").read_text(), 5)
            check_branch_rows(comparisons, limits,
                              tuple(addresses[key] for key in
                                    ("probe", "taken", "fallthrough")),
                              cc, const_left, taken, fallthrough)


if __name__ == "__main__":
    unittest.main()
