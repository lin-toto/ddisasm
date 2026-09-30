import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

import gtirb

# Condition flags die at every call, even where other registers stay live.
FLAGS = {"gcc": ("rflags",), "aarch64-linux-gnu-gcc": ("nzcv",), "riscv64-linux-gnu-gcc": ()}


class ImplicitLiveRegistersTest(unittest.TestCase):
    disassembly_options = ()

    def check_mask(self, compiler, body, expected, *, absent=(), link_options=()):
        if shutil.which(compiler) is None:
            self.skipTest(f"{compiler} required")
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "input.S"
            source.write_text(".text\n.globl _start\n.globl probe\n_start:\n" + body)
            binary = root / "input"
            subprocess.run([compiler, "-nostdlib", "-no-pie", str(source),
                            "-o", str(binary)] + list(link_options),
                           check=True, capture_output=True)
            ir = root / "output.gtirb"
            subprocess.run(["ddisasm", str(binary), "--ir", str(ir), "-j", "1",
                            "--debug-dir", str(root / "debug")]
                           + list(self.disassembly_options), check=True)
            module = gtirb.IR.load_protobuf(ir).modules[0]
            symbol = next(module.symbols_named("probe"))
            address = symbol.value
            if address is None:
                address = symbol.referent.address
                if symbol.at_end:
                    address += symbol.referent.size
            high = module.aux_data.get("liveRegisterSetsHigh")
            masks = [mask | ((high.data[offset] if high is not None else 0) << 64)
                     for offset, mask in module.aux_data["liveRegisterSets"].data.items()
                     if offset.element_id.address + offset.displacement == address]
            self.assertTrue(masks, "probe instruction has no live-register metadata")
            names = module.aux_data["liveRegisterNames"].data
            required = (1 << len(names)) - 1 if expected is None else sum(
                1 << names.index(name) for name in expected)
            for name in absent:
                required &= ~(1 << names.index(name))
            for mask in masks:
                self.assertEqual(mask & required, required)
                for name in absent:
                    self.assertFalse(mask & (1 << names.index(name)), name)

    def test_x64_system_call(self):
        self.check_mask("gcc", "mov $60,%eax\nxor %edi,%edi\nprobe: syscall\n", None)

    def test_aarch64_system_call(self):
        self.check_mask("aarch64-linux-gnu-gcc",
                        "mov x8,#93\nmov x0,#0\nprobe: svc #0\n", None)

    def test_riscv64_system_call(self):
        self.check_mask("riscv64-linux-gnu-gcc",
                        "li a7,93\nli a0,0\nprobe: ecall\n", None)

    def test_x64_adx(self):
        for operation in ("adox", "adcx"):
            with self.subTest(operation=operation):
                self.check_mask("gcc", f"probe: {operation} %rdx,%rax\nret\n",
                                ("rax", "rdx", "rflags"))

    # Private helpers may consume or return registers outside the public ABI.
    # Check both directions across calls and a chain containing a tail call.
    def test_internal_calls_and_returns(self):
        cases = (
            ("gcc", "r10", "call helper", "jmp done", "jmp leaf", "ret",
             "mov %r10,%rax", ".type helper,@function", ".type leaf,@function"),
            ("aarch64-linux-gnu-gcc", "x15", "bl helper", "b done", "b leaf", "ret",
             "mov x0,x15", ".type helper,%function", ".type leaf,%function"),
            ("riscv64-linux-gnu-gcc", "t3", "call helper", "j done", "j leaf", "ret",
             "mv a0,t3", ".type helper,@function", ".type leaf,@function"),
        )
        for compiler, reg, call, stop, tail, ret, use, helper_type, leaf_type in cases:
            for kind in ("argument", "return", "tail-return"):
                with self.subTest(compiler=compiler, kind=kind):
                    if kind == "argument":
                        body = f"probe: {call}\ndone: {stop}\n{helper_type}\nhelper: {use}\n{ret}\n"
                    else:
                        body = f"{call}\n{use}\ndone: {stop}\n{helper_type}\nhelper:\n"
                        if kind == "tail-return":
                            body += f"{tail}\n{leaf_type}\nleaf:\n"
                        body += f"probe: {ret}\n"
                    self.check_mask(compiler, body, (reg,))

    def test_unresolved_indirect_transfers(self):
        cases = (
            ("gcc", ("call *%r11", "jmp *%r11"), "ret"),
            ("aarch64-linux-gnu-gcc", ("blr x15", "br x15"), "ret"),
            ("riscv64-linux-gnu-gcc", ("jalr t3", "jr t3"), "ret"),
        )
        for compiler, transfers, ret in cases:
            for transfer in transfers:
                with self.subTest(compiler=compiler, transfer=transfer):
                    # Unknown x64 calls use the vector ABI but retain the
                    # conservative GPR policy. Unknown jumps have no ABI.
                    expected, absent = None, ()
                    if transfer == transfers[0]:
                        absent = FLAGS[compiler]
                    if compiler == "gcc" and transfer.startswith("call"):
                        expected = ("rax", "rbx", "rcx", "rdx", "rsi", "rdi", "rbp",
                                    "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15",
                                    *(f"xmm{i}" for i in range(8)))
                    self.check_mask(compiler, f"probe: {transfer}\n{ret}\n", expected,
                                    absent=absent)

    def test_conditional_tail_returns_preserve_private_caller_values(self):
        cases = (
            ("gcc", "call helper", "mov %r10,%rax", "jmp done", "je leaf", "r10"),
            ("aarch64-linux-gnu-gcc", "bl helper", "mov x0,x15", "b done", "b.eq leaf", "x15"),
            ("riscv64-linux-gnu-gcc", "call helper", "mv a0,t3", "j done", "beqz a0,leaf", "t3"),
        )
        for compiler, call, use, stop, tail, register in cases:
            with self.subTest(compiler=compiler):
                self.check_mask(compiler,
                    f"{call}\n{use}\ndone: {stop}\n.type helper,STT_FUNC\nhelper: {tail}\nret\n"
                    ".type leaf,STT_FUNC\nleaf:\nprobe: ret\n", (register,))

    def test_return_reachability_does_not_depend_on_function_attribution(self):
        cases = (
            ("gcc", "call helper", "mov %r10,%rax", "jmp done", "r10"),
            ("aarch64-linux-gnu-gcc", "bl helper", "mov x0,x15", "b done", "x15"),
            ("riscv64-linux-gnu-gcc", "call helper", "mv a0,t3", "j done", "t3"),
        )
        for compiler, call, use, stop, register in cases:
            with self.subTest(compiler=compiler):
                self.check_mask(compiler,
                    f"{call}\n{use}\ndone: {stop}\n.type helper,STT_FUNC\nhelper: nop\n"
                    ".size helper,.-helper\n.globl alternate\n.type alternate,STT_FUNC\n"
                    "alternate:\nprobe: ret\n", (register,))

    def test_aarch64_read_modify_write_destinations(self):
        for width in ("x", "w"):
            for operation in (f"movk {width}15,#0x1234,lsl #16",
                              f"bfi {width}15,{width}2,#3,#5",
                              f"bfxil {width}15,{width}2,#3,#5"):
                with self.subTest(operation=operation):
                    expected = ("x15",) if operation.startswith("movk") else ("x15", "x2")
                    self.check_mask("aarch64-linux-gnu-gcc",
                        f"probe: {operation}\nmov x15,#0\nmov x2,#0\nret\n", expected)

    def test_weak_alias_at_strong_target_remains_replaceable(self):
        cases = (
            ("gcc", "call helper", "jmp done"),
            ("aarch64-linux-gnu-gcc", "bl helper", "b done"),
            ("riscv64-linux-gnu-gcc", "call helper", "j done"),
        )
        for compiler, call, stop in cases:
            with self.subTest(compiler=compiler):
                self.check_mask(compiler, f"probe: {call}\ndone: {stop}\n"
                    ".globl helper\n.type helper,STT_FUNC\nhelper: ret\n"
                    ".weak weak_alias\n.set weak_alias,helper\n", None,
                    absent=FLAGS[compiler])

    def test_external_plt_calls_use_public_abi(self):
        cases = (
            ("gcc", "call puts@PLT", "jmp done", ("rdi", "rsi"), "r10"),
            ("aarch64-linux-gnu-gcc", "bl puts", "b done", ("x0", "x1"), "x15"),
            ("riscv64-linux-gnu-gcc", "call puts@plt", "j done", ("a0", "a1"), "t3"),
        )
        for compiler, call, stop, arguments, dead in cases:
            with self.subTest(compiler=compiler):
                self.check_mask(compiler, f"probe: {call}\ndone: {stop}\n", arguments,
                                absent=(dead,), link_options=("-lc",))

    def test_replaceable_weak_targets(self):
        cases = (
            ("gcc", "call helper", "jmp helper", "jmp done", "ret", "r10"),
            ("aarch64-linux-gnu-gcc", "bl helper", "b helper", "b done", "ret", "x15"),
            ("riscv64-linux-gnu-gcc", "call helper", "j helper", "j done", "ret", "t3"),
        )
        for compiler, call, tail, stop, ret, scratch in cases:
            for transfer in (call, tail):
                for weak in (False, True):
                    with self.subTest(compiler=compiler, transfer=transfer, weak=weak):
                        binding = ".weak helper\n" if weak else ""
                        body = (f"probe: {transfer}\ndone: {stop}\n{binding}"
                                f".type helper,STT_FUNC\nhelper: {ret}\n"
                                ".size helper,.-helper\n")
                        # A replacement also follows the ABI, which passes no flags.
                        self.check_mask(compiler, body, None if weak else (),
                                        absent=FLAGS[compiler] if weak else (scratch,))

    # Flags are dead across calls and returns in both directions, including a
    # chain containing a tail call. A branch into another function's blocks,
    # such as a .cold part, still uses the target's reads.
    def test_flags_die_at_calls_and_returns(self):
        cases = (
            ("gcc", "call helper", "jmp done", "jmp leaf", "ret", "seto %al",
             ".type helper,@function", ".type leaf,@function"),
            ("aarch64-linux-gnu-gcc", "bl helper", "b done", "b leaf", "ret", "cset x0,vs",
             ".type helper,%function", ".type leaf,%function"),
        )
        for compiler, call, stop, tail, ret, use, helper_type, leaf_type in cases:
            for kind in ("argument", "return", "tail-return", "branch"):
                with self.subTest(compiler=compiler, kind=kind):
                    expected, absent = (), FLAGS[compiler]
                    if kind == "argument":
                        body = f"probe: {call}\ndone: {stop}\n{helper_type}\nhelper: {use}\n{ret}\n"
                    elif kind == "branch":
                        body = f"probe: {tail}\n{leaf_type}\nleaf: {use}\n{ret}\n"
                        expected, absent = FLAGS[compiler], ()
                    else:
                        body = f"{call}\n{use}\ndone: {stop}\n{helper_type}\nhelper:\n"
                        if kind == "tail-return":
                            body += f"{tail}\n{leaf_type}\nleaf:\n"
                        body += f"probe: {ret}\n"
                    self.check_mask(compiler, body, expected, absent=absent)


if __name__ == "__main__":
    unittest.main()
