"""Binary-only alignment fill, real traps, and provisional/final exports."""

import json
import math
import os
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

import gtirb


FIXTURE = (Path(__file__).resolve().parents[1] / "examples" /
           "riscv_asm_examples" / "ex_trailing_zero_alignment" / "main.S")

@unittest.skipUnless(all(shutil.which(tool) for tool in
                         ("riscv64-linux-gnu-gcc", "riscv64-linux-gnu-strip", "ddisasm")),
                     "RISC-V compiler, strip and DDisasm required")
class RiscvTrailingAlignmentTest(unittest.TestCase):
    def setUp(self):
        self.budgets = {"compile": 30, "strip": 30, "lift": 120,
                        **json.loads(os.environ.get("DDISASM_PADDING_TEST_TIMEOUTS", "{}"))}
        for phase in ("compile", "strip", "lift"):
            value = self.budgets[phase]
            self.assertIsInstance(value, (float, int))
            self.assertNotIsInstance(value, bool)
            self.assertTrue(math.isfinite(value) and value > 0)
        for tool in ("riscv64-linux-gnu-gcc", "riscv64-linux-gnu-strip", "ddisasm"):
            self.assertIsNotNone(shutil.which(tool), tool)

    def _run(self, argv, kind):
        timeout = float(self.budgets[kind])
        self.assertTrue(math.isfinite(timeout) and timeout > 0)
        return subprocess.run(argv, check=True, capture_output=True,
                              timeout=timeout)

    def _rows(self, debug, relation):
        source = debug / "disassembly" / (relation + ".csv")
        self.assertTrue(source.is_file(), source)
        return [line.split("\t") for line in source.read_text().splitlines()
                if line.strip()]

    def _lift(self, binary, destination):
        debug = destination.with_suffix(".debug")
        self._run(["ddisasm", str(binary), "--ir", str(destination),
                   "--debug-dir", str(debug), "-j", "1"], "lift")
        return gtirb.IR.load_protobuf(destination).modules[0], debug

    def _check_gap(self, module, debug, begin, end, expected):
        size = end - begin
        candidates = {(int(row[0], 0), int(row[1], 0)) for row in
                      self._rows(debug, "riscv_trailing_alignment_padding")}
        self.assertEqual((begin, size) in candidates, expected)

        # Provisional code is retained for the absence-of-reference proof.
        provisional = {int(row[0], 0) for row in
                       self._rows(debug, "refined_block")}
        final = {int(row[0], 0) for row in
                 self._rows(debug, "final_refined_block")}
        self.assertIn(begin, provisional)
        self.assertEqual(begin in final, not expected)

        interval = next(interval for section in module.sections
                        for interval in section.byte_intervals
                        if interval.address is not None and
                        interval.address <= begin and end <= interval.address + interval.size)
        self.assertEqual(interval.contents[begin-interval.address:end-interval.address],
                         b"\0" * size)
        overlapping_code = [block for block in module.code_blocks
                            if block.address is not None and
                            block.address < end and begin < block.address + block.size]
        if not expected:
            self.assertTrue(overlapping_code)
            return

        self.assertEqual(overlapping_code, [])
        self.assertTrue(any(block.address is not None and
                            block.address <= begin and end <= block.address + block.size
                            for block in module.data_blocks))
        pads = {(offset.element_id.address + offset.displacement, count)
                for offset, count in module.aux_data["padding"].data.items()}
        self.assertIn((begin, size), pads)
        for edge in module.ir.cfg:
            for endpoint in (edge.source, edge.target):
                if isinstance(endpoint, gtirb.CodeBlock):
                    self.assertFalse(begin <= endpoint.address < end)
        for blocks in module.aux_data["functionBlocks"].data.values():
            self.assertFalse(any(begin <= block.address < end for block in blocks))
        self.assertTrue(any(any(block.address == end for block in entries)
                            for entries in module.aux_data["functionEntries"].data.values()))

    def _check_preceding_endproc(self, module, begin):
        # A removed padding block must not take main's endproc with it or move
        # it onto the following function. Inspect the actual serialized CFI.
        self.assertTrue(any(isinstance(offset.element_id, gtirb.CodeBlock) and
                            offset.element_id.address < begin and
                            offset.element_id.address + offset.displacement == begin and
                            any(directive[0] == ".cfi_endproc" for directive in directives)
                            for offset, directives in
                            module.aux_data["cfiDirectives"].data.items()))

    def _case(self, bits, case, expected_original, expected_stripped,
              no_unwind=False):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            binary = root / "original"
            compiler = ["riscv64-linux-gnu-gcc", f"-march=rv{bits}imac",
                        "-mabi=ilp32" if bits == 32 else "-mabi=lp64",
                        "-nostdlib", "-static", "-no-pie",
                        "-Wl,--no-relax,--build-id=none,-e,_start",
                        "-Wl,--section-start=.text=0x400000",
                        f"-DCASE={case}", f"-DNO_UNWIND={int(no_unwind)}"]
            if case == 12:
                compiler.append("-Wl,--emit-relocs")
            self._run([*compiler, str(FIXTURE), "-o", str(binary)], "compile")
            original, debug = self._lift(binary, root / "original.gtirb")
            next_symbol = next(original.symbols_named("after_gap"))
            end = (next_symbol.value if next_symbol.referent is None else
                   next_symbol.referent.address +
                   (next_symbol.referent.size if next_symbol.at_end else 0))
            size = 6 if case in (6, 15) else 4 if case == 7 else 2
            begin = end - size
            if case != 6:
                self._check_gap(original, debug, begin, end, expected_original)
                if expected_original and not no_unwind:
                    self._check_preceding_endproc(original, begin)
            else:
                # Mixed zero/nop/zero fill may be split by existing nop rules;
                # it must never be accepted as one new zero-alignment gap.
                rows = self._rows(debug, "riscv_trailing_alignment_padding")
                self.assertFalse(any(int(row[0], 0) == begin for row in rows))

            stripped = root / "stripped"
            shutil.copyfile(binary, stripped)
            self._run(["riscv64-linux-gnu-strip", "--strip-all", str(stripped)], "strip")
            stripped_module, stripped_debug = self._lift(
                stripped, root / "stripped.gtirb")
            # Assertions carry addresses observed before stripping as audit
            # expectations. They are never supplied to DDisasm as decisions.
            self.assertFalse(any(stripped_module.symbols_named("after_gap")))
            if case != 6:
                self._check_gap(stripped_module, stripped_debug, begin, end,
                                expected_stripped)
                if expected_stripped and not no_unwind:
                    self._check_preceding_endproc(stripped_module, begin)
            else:
                rows = self._rows(stripped_debug, "riscv_trailing_alignment_padding")
                self.assertFalse(any(int(row[0], 0) == begin for row in rows))

    def test_raw_entry_and_zero_gap_without_unwind_or_symbols(self):
        for bits in (32, 64):
            with self.subTest(bits=bits):
                self._case(bits, 0, True, True, no_unwind=True)

    def test_binary_positive_evidence_keeps_real_traps(self):
        # incoming branch, fallthrough, no independent next function,
        # misalignment, a local unresolved call, input pointer, resolved JR,
        # and conflicting unwind coverage all survive strip --strip-all.
        for case in (1, 2, 5, 7, 8, 10, 11, 13):
            with self.subTest(case=case):
                self._case(64, case, False, False)

    def test_removed_static_label_or_size_does_not_decide_padding(self):
        # Static labels/sizes neither supply positive starts nor directly veto
        # padding. The binary entry and runtime unwind stay the same.
        for case in (3, 4):
            with self.subTest(case=case):
                self._case(64, case, True, True)

    def test_real_zero_trap_entry_refuses_with_or_without_static_span(self):
        # The original has a hard retained expression span. The stripped form
        # retains a real zero/C.UNIMP entry; binary ambiguity must refuse both.
        self._case(64, 12, False, False)

    def test_unrelated_unresolved_branch_is_retained_without_veto(self):
        self._case(64, 9, True, True)

    def test_mixed_fill_is_refused_and_larger_zero_gap_is_preserved(self):
        self._case(64, 6, False, False)
        for bits in (32, 64):
            with self.subTest(bits=bits):
                self._case(bits, 15, True, True)


if __name__ == "__main__":
    unittest.main()
