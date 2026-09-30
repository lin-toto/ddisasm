import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

import gtirb
from gtirb_capstone.instructions import GtirbInstructionDecoder
from disassemble_reassemble_check import disassemble


@unittest.skipUnless(shutil.which("gcc"), "x64 compiler required")
class X64LiveRegistersTest(unittest.TestCase):
    def test_memory_test_keeps_register_input_live(self):
        # TEST does not write either operand. Capstone 5 omits the register
        # source of the memory-first Intel form from its read-access facts.
        # It must remain live through the preceding store's instrumentation.
        cases = (("b", "%sil"), ("w", "%si"), ("l", "%esi"), ("q", "%rsi"))
        source = ".text\n.globl _start\n.type _start,@function\n_start:\n"
        source += "".join(f"call check_test_{suffix}\n" for suffix, _ in cases)
        source += "mov $60,%eax\nxor %edi,%edi\nsyscall\n.size _start,.-_start\n"
        for suffix, register in cases:
            source += f"""
            .globl check_test_{suffix}
            .type check_test_{suffix},@function
            check_test_{suffix}:
                movl $0,(%rdi)
                test{suffix} {register},(%rdi)
                sete %al
                mov $0,%esi
                ret
            .size check_test_{suffix},.-check_test_{suffix}
            """
        source += '.section .note.GNU-stack,"",@progbits\n'
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            assembly = root / "test.S"
            assembly.write_text(source)
            binary = root / "test"
            subprocess.run(["gcc", "-nostdlib", "-no-pie", str(assembly), "-o", str(binary)], check=True)
            module = disassemble(binary).ir().modules[0]
            live = module.aux_data["liveRegisterSets"].data
            bit = 1 << module.aux_data["liveRegisterNames"].data.index("rsi")
            decoder = GtirbInstructionDecoder(gtirb.Module.ISA.X64)
            for suffix, _ in cases:
                block = next(module.symbols_named("check_test_" + suffix)).referent
                for instruction in list(decoder.get_instructions(block))[:2]:
                    with self.subTest(width=suffix, instruction=instruction.mnemonic):
                        self.assertTrue(live[gtirb.Offset(block, instruction.address - block.address)] & bit)

    def test_arithmetic_flags_kills_and_preserved_inputs(self):
        # Expected liveness immediately before the writer, with SETO reading
        # only OF after it. Flags are tracked one by one: the writer kills the
        # flags only if it replaces OF and reads no flag. ADC/SBB replace all
        # arithmetic outputs but still consume the incoming carry flag.
        cases = (
            ("add", "add %rbx, %rax", False),
            ("sub", "sub %rbx, %rax", False),
            ("cmp", "cmp %rbx, %rax", False),
            ("neg", "neg %rax", False),
            ("add_byte", "add %bl, %al", False),
            ("add_word", "add %bx, %ax", False),
            ("lock_add", "lock add %rbx, (%rax)", False),
            ("adc", "adc %rbx, %rax", True),
            ("sbb", "sbb %rbx, %rax", True),
            ("inc", "inc %rax", False),
            ("dec", "dec %rax", False),
            ("clc", "clc", True),
            ("stc", "stc", True),
            ("cmc", "cmc", True),
            ("sahf", "sahf", True),
            ("cld", "cld", True),
            ("std", "std", True),
            ("variable_shift", "shl %cl, %rax", True),
            ("zero_shift", "shl $0, %rax", True),
            ("masked_shift", "shl $64, %rax", True),
            ("wide_shift", "shr $32, %rax", False),
            ("rotate", "rol $1, %rax", False),
            ("whole_rotate", "rol $16, %ax", True),
            ("adcx", "adcx %rbx, %rax", True),
            ("adox", "adox %rbx, %rax", True),
            ("and", "and %rbx, %rax", False),
            ("or", "or %rbx, %rax", False),
            ("xor", "xor %rbx, %rax", False),
            ("test", "test %rbx, %rax", False),
            ("lahf", "lahf", True),
        )
        source = ".text\n.globl _start\n.type _start, @function\n_start:\n"
        source += "".join(f"call check_{name}\n" for name, _, _ in cases)
        source += "mov $60, %eax\nxor %edi, %edi\nsyscall\n.size _start, .-_start\n"
        for name, operation, _ in cases:
            source += f"""
            .globl check_{name}
            .type check_{name}, @function
            check_{name}:
                mov %rbx, %rax
                {operation}
                seto %dl
                ret
            .size check_{name}, .-check_{name}
            """
        source += '.section .note.GNU-stack, "", @progbits\n'
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            assembly = root / "input.S"
            binary = root / "input"
            assembly.write_text(source)
            subprocess.run(["gcc", "-nostdlib", "-no-pie", str(assembly),
                            "-o", str(binary)], check=True)
            module = disassemble(binary).ir().modules[0]
            # Consumers use the flags bit as it is only under this rule.
            self.assertEqual(module.aux_data["liveRegisterFlagRule"].data, "call-boundary")
            flag_bit = 1 << module.aux_data["liveRegisterNames"].data.index("rflags")
            live = module.aux_data["liveRegisterSets"].data
            decoder = GtirbInstructionDecoder(gtirb.Module.ISA.X64)
            for name, _, expected in cases:
                with self.subTest(name=name):
                    block = next(module.symbols_named(f"check_{name}")).referent
                    self.assertIsInstance(block, gtirb.CodeBlock)
                    instructions = list(decoder.get_instructions(block))
                    self.assertEqual(len(instructions), 4)
                    for instruction in instructions[:2]:
                        offset = gtirb.Offset(block, instruction.address - block.address)
                        self.assertEqual(bool(live[offset] & flag_bit), expected)
                    offset = gtirb.Offset(block, instructions[2].address - block.address)
                    self.assertTrue(live[offset] & flag_bit)

    def test_carry_stays_live_across_inc_and_dec(self):
        source = """
        .text
        .globl _start
        .type _start, @function
        _start:
            call check_carry
            mov $60, %eax
            xor %edi, %edi
            syscall
        .size _start, .-_start
        .globl check_carry
        .type check_carry, @function
        check_carry:
            mov %rbx, %rax
            inc %rbx
            dec %rcx
            adc %rdx, %rax
            ret
        .size check_carry, .-check_carry
        .section .note.GNU-stack, "", @progbits
        """
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            assembly = root / "input.S"
            binary = root / "input"
            assembly.write_text(source)
            subprocess.run(["gcc", "-nostdlib", "-no-pie", str(assembly),
                            "-o", str(binary)], check=True)
            module = disassemble(binary).ir().modules[0]
            block = next(module.symbols_named("check_carry")).referent
            self.assertIsInstance(block, gtirb.CodeBlock)
            flag_bit = 1 << module.aux_data["liveRegisterNames"].data.index("rflags")
            live = module.aux_data["liveRegisterSets"].data
            for displacement in (0, 3, 6, 9):
                with self.subTest(displacement=displacement):
                    self.assertTrue(live[gtirb.Offset(block, displacement)] & flag_bit)


if __name__ == "__main__":
    unittest.main()
