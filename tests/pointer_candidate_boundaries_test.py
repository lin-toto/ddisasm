import collections
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

from disassemble_reassemble_check import disassemble
from snippets import parse_souffle_output


@unittest.skipUnless(shutil.which("gcc"), "GCC required")
class PointerCandidateBoundariesTest(unittest.TestCase):
    def test_nearest_candidates_respect_original_boundaries(self):
        for boundary_kind in ("none", "symbol", "object_end"):
            with self.subTest(boundary=boundary_kind):
                records = []
                for index in range(64):
                    if index == 24 and boundary_kind == "symbol":
                        records.append(".globl middle\nmiddle:")
                    if index == 16 and boundary_kind == "object_end":
                        records.append(
                            ".type nested, @object\nnested:\n.size nested, 320"
                        )
                    records.append(f".quad targets+{8 * (index + 1)}\n.zero 32")
                source = """
                    .text
                    .globl _start
                    .type _start, @function
                    _start:
                        xor %edi, %edi
                        mov $60, %eax
                        syscall
                    .size _start, .-_start
                    .data
                    .balign 8
                    .type records, @object
                    records:
                    {records}
                    .size records, .-records
                    .type targets, @object
                    targets:
                        .zero 1024
                    .size targets, .-targets
                    .section .note.GNU-stack, "", @progbits
                """.format(records="\n".join(records))
                with tempfile.TemporaryDirectory() as directory:
                    root = Path(directory)
                    assembly = root / "input.S"
                    binary = root / "input"
                    assembly.write_text(source)
                    subprocess.run(
                        ["gcc", "-nostdlib", "-no-pie", str(assembly),
                         "-o", str(binary)],
                        check=True,
                    )
                    module = disassemble(
                        binary, extra_args=["--with-souffle-relations"]
                    ).ir().modules[0]

                boundaries = set()
                for address, size, kind, *_ in parse_souffle_output(
                    module, "defined_symbol"
                ):
                    boundaries.add(address)
                    if kind == "OBJECT" and size:
                        boundaries.add(address + size)

                groups = collections.defaultdict(set)
                for address, *group in parse_souffle_output(
                    module, "interior_object_pointer"
                ):
                    groups[tuple(group)].add(address)
                self.assertGreaterEqual(max(map(len, groups.values())), 32)
                expected = set()
                for group, addresses in groups.items():
                    ordered = sorted(addresses)
                    for start, end in zip(ordered, ordered[1:]):
                        if not any(start < b <= end for b in boundaries):
                            expected.add((start, end, *group))
                self.assertEqual(
                    set(parse_souffle_output(
                        module, "next_interior_object_pointer"
                    )),
                    expected,
                )


if __name__ == "__main__":
    unittest.main()
