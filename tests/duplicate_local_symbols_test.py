"""Keep distinct local definitions distinct after expression construction."""

import contextlib
import os
from pathlib import Path
import platform
import subprocess
import tempfile
import unittest

import gtirb
from disassemble_reassemble_check import disassemble


def symbol_address(symbol):
    if symbol.referent is not None:
        return symbol.referent.address + (symbol.referent.size if symbol.at_end else 0)
    return symbol.value


@unittest.skipUnless(platform.system() == "Linux" and platform.machine() == "x86_64",
                     "Linux x86-64 assembler and native execution required")
class DuplicateLocalSymbolsTest(unittest.TestCase):
    @contextlib.contextmanager
    def fixture_directory(self):
        # Optional retained artifacts make red/green runs independently auditable.
        parent = os.environ.get("DDISASM_TEST_ARTIFACTS")
        if parent:
            root = Path(parent) / self._testMethodName
            root.mkdir(parents=True, exist_ok=False)
            yield root
        else:
            with tempfile.TemporaryDirectory() as directory:
                yield Path(directory)

    def check_round_trip(self, names, strip_names=(), reverse=False, relative=False):
        with self.fixture_directory() as root:
            objects = []
            for index, name in enumerate(names):
                source = root / ("component_%d.S" % index)
                source.write_text("""
                    .text
                    .local {name}
                    .type {name}, @function
                    .globl target_alias_{index}
                target_alias_{index}:
                {name}:
                    .cfi_startproc
                    cmpb $0, .Ldone(%rip)
                    jne .Lreturn
                    mov $1, %eax
                    mov $1, %edi
                    lea .Lmessage(%rip), %rsi
                    mov $1, %edx
                    syscall
                .Lreturn:
                    ret
                    .cfi_endproc
                    .size {name}, .-{name}
                    .globl call_{index}
                    .type call_{index}, @function
                call_{index}:
                    .cfi_startproc
                    call {name}
                    ret
                    .cfi_endproc
                    .size call_{index}, .-call_{index}
                    .section .fini_array, "aw", @fini_array
                    .p2align 3
                    .globl pointer_{index}
                    .type pointer_{index}, @object
                pointer_{index}:
                    .quad {name}
                    .size pointer_{index}, 8
                    .section .rodata
                .Lmessage:
                    .byte {letter}
                    .bss
                .Ldone:
                    .zero 1
                    .section .note.GNU-stack, "", @progbits
                """.format(name=name, index=index, letter=ord("A") + index))
                obj = source.with_suffix(".o")
                subprocess.run(["gcc", "-c", str(source), "-o", str(obj)],
                               check=True, capture_output=True)
                objects.append(obj)
            entry = root / "entry.S"
            calls = ["call call_%d" % index for index in range(len(names))]
            if relative:
                calls += ["mov $%d, %%edi\ncall dispatch" % index for index in range(len(names))]
            else:
                calls += ["call *pointer_%d(%%rip)" % index for index in range(len(names))]
            dispatch = """
                .globl dispatch
                .type dispatch, @function
            dispatch:
                .cfi_startproc
                cmp $1, %edi
                ja .Linvalid
                lea relative_table(%rip), %rdx
                movslq (%rdx,%rdi,4), %rax
                add %rdx, %rax
                jmp *%rax
            .Linvalid:
                ret
                .cfi_endproc
                .size dispatch, .-dispatch
                .section .rodata
                .p2align 2
                .globl relative_table
                .type relative_table, @object
            relative_table:
                .long target_alias_0-relative_table
                .long target_alias_1-relative_table
                .size relative_table, .-relative_table
            """ if relative else ""
            entry.write_text("""
                .text
                .globl _start
                .type _start, @function
            _start:
                {calls}
                mov $60, %eax
                xor %edi, %edi
                syscall
                .size _start, .-_start
                {dispatch}
                .section .note.GNU-stack, "", @progbits
            """.format(calls="\n".join(calls), dispatch=dispatch))
            original = root / "original"
            compiler = ["gcc", "-nostdlib", "-no-pie", "-Wl,--build-id=none"]
            if reverse:
                objects.reverse()
            subprocess.run(compiler + [str(entry)] + [str(obj) for obj in objects]
                           + ["-o", str(original)], check=True, capture_output=True)
            # Cross-object table assembly needs exported targets, but they must
            # not provide unique alternate names that hide the local-name bug.
            for name in tuple(strip_names) + tuple("target_alias_%d" % index for index in range(len(names))):
                subprocess.run(["objcopy", "--strip-symbol=" + name, str(original)],
                               check=True, capture_output=True)
            expected = bytes(range(ord("A"), ord("A") + len(names))) * 2
            before = subprocess.run([str(original)], capture_output=True, timeout=10)
            self.assertEqual((before.returncode, before.stdout, before.stderr),
                             (0, expected, b""))
            result = disassemble(original)
            module = result.ir().modules[0]
            failures = []
            for index in range(len(names)):
                pointer = next(module.symbols_named("pointer_%d" % index)).referent
                interval, offset = pointer.byte_interval, pointer.offset
                target = int.from_bytes(interval.contents[offset:offset + 8], "little")
                expr = interval.symbolic_expressions[offset]
                self.assertIsInstance(expr, gtirb.SymAddrConst)
                if symbol_address(expr.symbol) + expr.offset != target:
                    failures.append(("data", index, target, symbol_address(expr.symbol) + expr.offset))
                wrapper = next(module.symbols_named("call_%d" % index)).referent
                expr = wrapper.byte_interval.symbolic_expressions[wrapper.offset + 1]
                self.assertIsInstance(expr, gtirb.SymAddrConst)
                if symbol_address(expr.symbol) + expr.offset != target:
                    failures.append(("call", index, target, symbol_address(expr.symbol) + expr.offset))
                for function, entries in module.aux_data["functionEntries"].data.items():
                    if any(block.address == target for block in entries):
                        symbol = module.aux_data["functionNames"].data[function]
                        if symbol_address(symbol) != target:
                            failures.append(("function name", index, target, symbol_address(symbol)))
            if relative:
                table = next(module.symbols_named("relative_table")).referent
                for index in range(len(names)):
                    offset = table.offset + index * 4
                    expr = table.byte_interval.symbolic_expressions[offset]
                    self.assertIsInstance(expr, gtirb.SymAddrAddr)
                    expected_value = ((symbol_address(expr.symbol1) - symbol_address(expr.symbol2))
                                      // expr.scale + expr.offset) % (1 << 32)
                    raw = int.from_bytes(table.byte_interval.contents[offset:offset + 4], "little")
                    if expected_value != raw:
                        failures.append(("relative data", index, raw, expected_value))
            printed = root / "printed.S"
            subprocess.run(["gtirb-pprinter", str(result.ir_path), "--asm", str(printed),
                            "--policy=complete"], check=True, capture_output=True)
            rebuilt = root / "rebuilt"
            subprocess.run(compiler + [str(printed), "-o", str(rebuilt)],
                           check=True, capture_output=True)
            after = subprocess.run([str(rebuilt)], capture_output=True, timeout=10)
            # Check behavior even when the earlier IR identity checks failed.
            self.assertEqual((after.returncode, after.stdout, after.stderr),
                             (0, expected, b""), "IR identity failures: %r" % failures)
            self.assertEqual(failures, [])

    def test_existing_duplicate_special_locals(self):
        self.check_round_trip(("__do_global_dtors_aux",) * 2)

    def test_existing_duplicate_special_locals_reverse_link_order(self):
        self.check_round_trip(("__do_global_dtors_aux",) * 2, reverse=True)

    def test_inferred_duplicate_special_locals(self):
        self.check_round_trip(("__do_global_dtors_aux",) * 2,
                              strip_names=("__do_global_dtors_aux",))

    def test_existing_and_inferred_same_name(self):
        self.check_round_trip(("__do_global_dtors_aux", "second_finalizer"),
                              strip_names=("second_finalizer",))

    def test_generic_duplicate_local_control(self):
        self.check_round_trip(("local_callback",) * 2)

    def test_unique_special_local_control(self):
        self.check_round_trip(("__do_global_dtors_aux",))

    def test_duplicate_targets_in_relative_jump_table(self):
        self.check_round_trip(("__do_global_dtors_aux",) * 2, relative=True)
