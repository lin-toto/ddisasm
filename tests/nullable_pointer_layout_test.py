import unittest

import bss_pointer_array_test as fixture


class NullablePointerLayoutTest(unittest.TestCase):
    lift = fixture.BssPointerArrayTest.lift
    assert_pointer = fixture.BssPointerArrayTest.assert_pointer

    def assert_no_pointers(self, module, offsets):
        start = next(module.symbols_named("records")).referent.address
        for interval in module.byte_intervals:
            for offset in offsets:
                self.assertFalse(
                    list(interval.symbolic_expressions_at(start + offset))
                )

    @staticmethod
    def records(hole="0", boundary=""):
        fields = []
        values = ("storage+40", "storage+48", "storage+56", hole, "storage+64")
        for index, value in enumerate(values):
            if index == 4:
                fields.append(boundary)
            fields.append(f".quad {value}")
            # Each 48-byte record has another, interleaved pointer column.
            fields.append(".quad name_string")
            if index != 4:
                fields.append(".zero 32")
        return "\n".join(fields)

    def test_interleaved_column_extends_through_null(self):
        module = self.lift(self.records())
        for index, target in ((0, 40), (1, 48), (2, 56), (4, 64)):
            self.assert_pointer(module, 32 + index * 48, target)

    def test_scalar_or_source_boundary_stops_column(self):
        for fields in (
            self.records(hole="7"),
            self.records(boundary=".globl last\nlast:"),
        ):
            with self.subTest(fields=fields):
                module = self.lift(fields)
                self.assert_no_pointers(module, (224,))

    def test_sparse_complete_nullable_pointer_object(self):
        fields = (
            ".quad storage+40\n.zero 16\n.quad name_string\n.zero 8\n"
            ".quad storage+64\n.zero 16\n.quad name_string"
        )
        module = self.lift(fields)
        self.assert_pointer(module, 32, 40)
        self.assert_pointer(module, 72, 64)

    def test_scalar_invalidates_complete_pointer_layout(self):
        fields = (
            ".quad storage+40\n.quad 7\n.zero 8\n.quad name_string\n.zero 8\n"
            ".quad storage+64\n.zero 16\n.quad name_string"
        )
        module = self.lift(fields)
        self.assert_no_pointers(module, (32, 72))

    def test_sparse_object_requires_anchors_and_no_internal_boundary(self):
        two_anchors = (
            ".quad storage+40\n.zero 16\n.quad name_string\n.zero 8\n"
            ".quad storage+64\n.zero 24"
        )
        boundary = (
            ".quad storage+40\n.zero 16\n.quad name_string\n.zero 8\n"
            ".globl tail\ntail:\n.quad storage+64\n.zero 16\n.quad name_string"
        )
        for fields in (two_anchors, boundary):
            with self.subTest(fields=fields):
                module = self.lift(fields)
                self.assert_no_pointers(module, (32, 72))

    def test_unaligned_unanchored_targets_do_not_establish_layout(self):
        columns = self.records()
        for offset in (40, 48, 56, 64):
            columns = columns.replace(
                f"storage+{offset}", f"storage+{offset + 1}"
            )
        sparse = (
            ".quad storage+41\n.zero 16\n.quad name_string\n.zero 8\n"
            ".quad storage+65\n.zero 16\n.quad name_string"
        )
        for fields, offsets in ((columns, (32, 224)), (sparse, (32, 72))):
            with self.subTest(fields=fields):
                module = self.lift(fields)
                self.assert_no_pointers(module, offsets)

    def test_nullable_layout_other_architectures(self):
        for arch in ("aarch64", "riscv64"):
            with self.subTest(arch=arch):
                module = self.lift(self.records(), arch=arch)
                self.assert_pointer(module, 224, 64)
                module = self.lift(
                    ".quad storage+40\n.zero 16\n.quad name_string\n.zero 8\n"
                    ".quad storage+64\n.zero 16\n.quad name_string",
                    arch=arch,
                )
                self.assert_pointer(module, 32, 40)
                self.assert_pointer(module, 72, 64)


if __name__ == "__main__":
    unittest.main()
