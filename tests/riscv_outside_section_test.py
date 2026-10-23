"""Biased PC-relative data bases require complete binary use proofs."""

import csv
import io
import json
import math
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

import gtirb


LINKER_SCRIPT = """
ENTRY(_start)
SECTIONS {
  .text 0x10000 : { *(.text) }
  .bss 0x20000 (NOLOAD) : { *(.bss) }
  /DISCARD/ : { *(.riscv.attributes) *(.comment) *(.note*) }
}
"""

PREFIX = "auipc s1,0x11\naddi s1,s1,-2048\n"
ACCESS = "ld a0,-2016(s1)\n"

# Every case checks the actual final IR and debug proof. No Python copy of the
# Datalog proof or original symbol lookup decides which instruction is tested.
CASES = {
    "adjacent": (PREFIX + ACCESS, True),
    "scheduled_different_destination": (
        "auipc s1,0x11\naddi t4,zero,7\naddi t0,s1,-2048\n"
        "ld a0,-2016(t0)\n", True),
    "read_before_write": (PREFIX + "ld s1,-2016(s1)\n", True),
    "affine_copy": (PREFIX + "mv t0,s1\naddi t0,t0,-32\n"
                    "ld a0,-1984(t0)\n", True),
    "masked_index": (PREFIX + "andi t0,a1,3\nslli t0,t0,3\n"
                     "add t1,s1,t0\nld a0,-2016(t1)\n", True),
    "bounded_join": (PREFIX + "beqz a1,one\nli t0,0\nj joined\n"
                     "one: li t0,1\njoined: slli t0,t0,3\n"
                     "add t1,s1,t0\nld a0,-2016(t1)\n", True),
    "exact_spill_overwritten": (PREFIX + "sd s1,0(sp)\nli s1,0\n"
                                "ld t0,0(sp)\nsd zero,0(sp)\n"
                                "ld a0,-2016(t0)\n", True),
    "cfg_reachable_extra_access": (PREFIX + "beqz a1,extra\n" + ACCESS +
                                   "j done\nextra: ld a0,-2008(s1)\n"
                                   "done: addi zero,zero,0\n", True),
    "unreachable_bad_access": (PREFIX + "j good\n"
                               "ld a0,0(s1)\n"
                               "good: " + ACCESS, True),
    "unbounded_index": (PREFIX + "add t0,s1,a1\nld a0,-2016(t0)\n", False),
    "one_unbounded_join": (PREFIX + "beqz a1,bounded\nmv t0,a2\nj use\n"
                           "bounded: li t0,0\nuse: add t1,s1,t0\n"
                           "ld a0,-2016(t1)\n", False),
    "width_crosses_section": (PREFIX + "ld a0,-1796(s1)\n", False),
    "mixed_inside_outside": (PREFIX + ACCESS + "ld a1,0(s1)\n", False),
    "numeric_use": (PREFIX + ACCESS + "xor t0,s1,a1\n", False),
    "returned_pointer": (PREFIX + ACCESS + "mv a0,s1\n", False),
    "pointer_escape": (PREFIX + ACCESS + "sd s1,0(a1)\n", False),
    "pointer_call_argument": (PREFIX + ACCESS + "mv a1,s1\ncall helper\n", False),
    "unknown_indirect": (PREFIX + ACCESS + "jalr zero,a1,0\n", False),
    "pointer_derivation_loop": (PREFIX + "again: addi s1,s1,8\n"
                                "ld a0,-2016(s1)\nbnez a1,again\n", False),
    "partial_spill_reload": (PREFIX + "sd s1,0(sp)\nli s1,0\n"
                             "lw t0,0(sp)\nsd zero,0(sp)\n"
                             "ld a0,-2016(t0)\n", False),
    "slot_live_at_call": (PREFIX + "sd s1,0(sp)\ncall helper\n"
                          "ld t0,0(sp)\nsd zero,0(sp)\n"
                          "ld a0,-2016(t0)\n", False),
    "boundary_anchor": (PREFIX + "ld a0,-2048(s1)\n", False),
    "direct_load_lower": ("auipc s1,0x11\nld a0,-2048(s1)\n", False),
    "direct_store_lower": ("auipc s1,0x11\nsd a0,-2048(s1)\n", False),
    "unmatched_hi_memory": ("auipc s1,0x10\nld a0,32(s1)\n"
                            "addi t0,s1,2047\nld a1,-2015(t0)\n", False),
    "unmatched_hi_copy": ("auipc s1,0x10\nmv t1,s1\n"
                          "addi t0,s1,2047\nld a0,-2015(t0)\n"
                          "ld a1,32(t1)\n", False),
    "conflicting_pointer_copy_join": (PREFIX + "beqz a1,other\nmv t0,s1\n"
                                      "j use\nother: mv t0,a2\n"
                                      "use: ld a0,-2016(t0)\n", False),
    "conflicting_stack_store_join": (PREFIX + "beqz a1,other\nsd s1,0(sp)\n"
                                    "j reload\nother: sd a2,0(sp)\n"
                                    "reload: li s1,0\nld t0,0(sp)\n"
                                    "sd zero,0(sp)\nld a0,-2016(t0)\n", False),
    "uninitialized_stack_slot_join": (PREFIX + "beqz a1,reload\nsd s1,0(sp)\n"
                                     "reload: li s1,0\nld t0,0(sp)\n"
                                     "sd zero,0(sp)\nld a0,-2016(t0)\n", False),
    "partial_write_stack_join": (PREFIX + "beqz a1,partial\nsd s1,0(sp)\n"
                                 "j reload\npartial: sw zero,0(sp)\n"
                                 "reload: li s1,0\nld t0,0(sp)\n"
                                 "sd zero,0(sp)\nld a0,-2016(t0)\n", False),
    "SP_change_stack_join": (PREFIX + "beqz a1,changed\nsd s1,0(sp)\n"
                             "j reload\nchanged: addi sp,sp,16\n"
                             "reload: li s1,0\nld t0,0(sp)\n"
                             "sd zero,0(sp)\nld a0,-2016(t0)\n", False),
    "caller_saved_pointer_read_after_call": (
        PREFIX + ACCESS + "mv t0,s1\nli s1,0\njal ra,helper\n"
        "ld a0,-2016(t0)\n", False),
    "caller_saved_pointer_redefined_after_call": (
        PREFIX + ACCESS + "mv t0,s1\nli s1,0\njal ra,helper\n"
        "li t0,0\n", True),
    "raw_HI_read_after_call": (
        "auipc t0,0x10\njal ra,helper\naddi s1,t0,2047\n"
        "ld a0,-2015(s1)\n", False),
    "conditional_noncode_successor": (
        PREFIX + ".set lost,0x10800\nbeq a1,zero,lost\n" + ACCESS, False),
    "completed_outside_argument_dead_at_call": (
        PREFIX + ACCESS + "mv a4,s1\nli s1,0\njal ra,helper\nli a4,0\n", True),
    "completed_outside_argument_read_after_call": (
        PREFIX + ACCESS + "mv a4,s1\nli s1,0\njal ra,helper\n"
        "ld a0,-2016(a4)\nli a4,0\n", False),
    "dead_argument_mixed_affine_definitions": (
        PREFIX + ACCESS + "beqz a1,inside\nmv a4,s1\nj joined\n"
        "inside: addi a4,s1,-2016\njoined: li s1,0\njal ra,helper\nli a4,0\n", False),
    "dead_argument_mixed_intervals_one_definition": (
        PREFIX + ACCESS + "beqz a1,inside\nli t0,0\nj joined\n"
        "inside: li t0,-2016\njoined: add a4,s1,t0\nli s1,0\n"
        "jal ra,helper\nli a4,0\n", False),
    "callee_saved_callback_value": (
        PREFIX + ACCESS + "mv s6,s1\nli s1,0\njalr ra,t1,0\n"
        "ld a0,-2016(s6)\n", True),
    "callee_saved_register_as_call_operand": (
        PREFIX + ACCESS + "mv s6,s1\nli s1,0\njalr ra,s6,0\n", False),
    "ECALL_redefines_previously_bounded_A0": (
        "li a0,0\necall\n" + PREFIX +
        "add t0,s1,a0\nld a1,-2016(t0)\n", False),
}


@unittest.skipUnless(all(shutil.which(tool) for tool in
                         ("riscv64-linux-gnu-gcc", "riscv64-linux-gnu-strip", "ddisasm")),
                     "RISC-V compiler, strip and DDisasm required")
class RiscvOutsideSectionTest(unittest.TestCase):
    def setUp(self):
        self.limits = {"compile": 30, "strip": 30, "lift": 120,
                       **json.loads(os.environ.get("DDISASM_OUTSIDE_SECTION_TEST_TIMEOUTS", "{}"))}
        for phase in ("compile", "strip", "lift"):
            value = self.limits[phase]
            self.assertIsInstance(value, (float, int))
            self.assertNotIsInstance(value, bool)
            self.assertTrue(math.isfinite(value) and value > 0)
        for tool in ("riscv64-linux-gnu-gcc", "riscv64-linux-gnu-strip", "ddisasm"):
            self.assertIsNotNone(shutil.which(tool), tool)

    def run_command(self, phase, argv):
        subprocess.run(argv, check=True, capture_output=True,
                       timeout=self.limits[phase])

    def lift(self, root, binary, form, extra_options=()):
        output = root / (form + ".gtirb")
        debug = root / (form + "-debug")
        self.run_command("lift", ["ddisasm", str(binary), "--ir", str(output),
                                  "--debug-dir", str(debug), "-j", "1",
                                  *extra_options])
        module = gtirb.IR.load_protobuf(output).modules[0]
        certificates = list(debug.rglob("riscv_outside_section_certificate.csv"))
        refusals = list(debug.rglob("riscv_outside_section_refusal.csv"))
        self.assertEqual(len(certificates), 1)
        self.assertEqual(len(refusals), 1)
        return module, certificates[0].read_text(), refusals[0].read_text()

    def check_ir(self, module, positive):
        hi = None
        high_pc = None
        high_word = None
        # Find the actual AUIPC bytes in executable CodeBlocks. Stripped
        # positives use ELF entry plus binary CFG, never original symbols.
        for block in module.code_blocks:
            raw = block.byte_interval.contents[block.offset:block.offset + block.size]
            for index in range(0, len(raw), 4):
                if int.from_bytes(raw[index:index + 4], "little") & 0xfff in (0x497, 0x297):
                    self.assertIsNone(high_pc)
                    high_pc = block.address + index
                    high_word = int.from_bytes(raw[index:index + 4], "little")
                    hi = block.byte_interval.symbolic_expressions.get(block.offset + index)
        self.assertIsNotNone(high_pc)
        if not positive:
            self.assertIsNone(hi)
            return None
        self.assertIsInstance(hi, gtirb.SymAddrConst)
        self.assertTrue({gtirb.SymbolicExpression.Attribute.HI,
                         gtirb.SymbolicExpression.Attribute.PCREL} <= hi.attributes)
        self.assertIsInstance(hi.symbol.referent, gtirb.DataBlock)
        self.assertFalse(hi.symbol.at_end)
        anchor = hi.symbol.referent.address
        self.assertGreater(anchor, 0x20000)
        self.assertLess(anchor, 0x20100)
        self.assertEqual(hi.symbol.referent.byte_interval.section.name, ".bss")
        lows = []
        lower_word = None
        for interval in module.byte_intervals:
            for offset, expression in interval.symbolic_expressions.items():
                if isinstance(expression, gtirb.SymAddrConst) and \
                        gtirb.SymbolicExpression.Attribute.LO in expression.attributes and \
                        expression.symbol.referent.address == high_pc:
                    self.assertEqual(expression.offset, 0)
                    self.assertFalse(expression.symbol.at_end)
                    self.assertIsInstance(expression.symbol.referent, gtirb.CodeBlock)
                    lows.append(interval.address + offset)
                    lower_word = int.from_bytes(interval.contents[offset:offset + 4], "little")
        self.assertEqual(len(lows), 1)
        self.assertEqual(lower_word & 0x707f, 0x13)  # physical ADDI
        self.assertEqual((lower_word >> 15) & 31, (high_word >> 7) & 31)
        high_immediate = high_word & 0xfffff000
        if high_immediate >= 1 << 31:
            high_immediate -= 1 << 32
        lower_immediate = lower_word >> 20
        if lower_immediate >= 1 << 11:
            lower_immediate -= 1 << 12
        self.assertEqual(anchor + hi.offset, high_pc + high_immediate + lower_immediate)
        return anchor, hi.offset, hi.symbol.name, lows

    def test_original_and_strip_all_binary_proofs(self):
        for name, (instructions, positive) in CASES.items():
            with self.subTest(name=name), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                source, script, binary = root / "main.S", root / "link.ld", root / "main"
                source.write_text(".option norvc\n.option norelax\n.text\n"
                                  ".globl _start\n_start:\n" + instructions +
                                  "ret\nhelper: ret\n.bss\n.space 256\n")
                script.write_text(LINKER_SCRIPT)
                self.run_command("compile", ["riscv64-linux-gnu-gcc", "-march=rv64imac",
                    "-mabi=lp64", "-nostdlib", "-static", "-no-pie", "-g0",
                    "-Wl,--no-relax,--build-id=none", "-T", str(script),
                    str(source), "-o", str(binary)])
                stripped = root / "main-stripped"
                self.run_command("strip", ["riscv64-linux-gnu-strip", "--strip-all",
                                            "-o", str(stripped), str(binary)])
                summaries = []
                for form, elf in (("original", binary), ("stripped", stripped)):
                    module, certificates, refusals = self.lift(root, elf, form)
                    summaries.append(self.check_ir(module, positive))
                    if positive:
                        self.assertTrue(certificates.strip())
                        self.assertFalse(refusals.strip())
                    else:
                        self.assertFalse(certificates.strip())
                        self.assertTrue(refusals.strip())
                self.assertEqual(summaries[0], summaries[1])


    def compile_control_fixture(self, root, text, frames=True, data_sections="", emit_relocations=False):
        source, script, binary = root / "main.S", root / "link.ld", root / "main"
        source.write_text(".option norvc\n.option norelax\n.text\n.globl _start\n" +
                          text + data_sections + "\n.bss\n.space 256\n")
        script.write_text(LINKER_SCRIPT.replace(".bss 0x20000",
            ".data 0x1d000 : { *(.data) }\n"
            "  .eh_frame 0x1e000 : { *(.eh_frame) }\n"
            "  .rodata 0x1f000 : { *(.rodata) }\n  .bss 0x20000"))
        argv = ["riscv64-linux-gnu-gcc", "-march=rv64gc",
            "-mabi=lp64", "-nostdlib", "-static", "-no-pie", "-g0",
            "-Wl,--no-relax,--build-id=none", "-T", str(script),
            str(source), "-o", str(binary)]
        if emit_relocations:
            argv.append("-Wl,--emit-relocs")
        self.run_command("compile", argv)
        stripped = root / "main-stripped"
        self.run_command("strip", ["riscv64-linux-gnu-strip", "--strip-all",
                                    "-o", str(stripped), str(binary)])
        return (("original", binary), ("stripped", stripped))

    def test_missing_dispatch_arm_at_known_predecessor_refuses(self):
        # Runtime unwind is the only region extent; the uncovered controls
        # additionally check the outside-FDE unknown-input envelope.
        for variant in ("index", "slot_reload", "conflicting_pointer"):
            for frames in (True, False):
                with self.subTest(variant=variant, frames=frames), tempfile.TemporaryDirectory() as directory:
                    root = Path(directory)
                    if variant == "index":
                        body = "ld a4,0(a0)\nbnez a1,.Ldispatch\nli a4,0\n.Lcase:\n" + PREFIX + \
                            "add a5,s1,a4\nsw zero,-1912(a5)\nret\n.Ldispatch: jr t1\n"
                    elif variant == "slot_reload":
                        body = "ld a4,0(a0)\nbnez a1,.Ldispatch\n" + PREFIX + \
                            "sd s1,0(sp)\nli s1,0\n.Lcase: ld t0,0(sp)\nsd zero,0(sp)\n" + \
                            "ld a0,-2016(t0)\nret\n.Ldispatch: sd a4,0(sp)\njr t1\n"
                    else:
                        body = "ld a4,0(a0)\nbnez a1,.Ldispatch\n" + PREFIX + \
                            "mv t0,s1\nli s1,0\n.Lcase: ld a0,-2016(t0)\nret\n" + \
                            ".Ldispatch: mv t0,a4\njr t1\n"
                    text = "_start:\n" + (".cfi_startproc\n" if frames else "") + body + \
                        (".cfi_endproc\n" if frames else "")
                    for form, elf in self.compile_control_fixture(root, text, frames):
                        module, certificates, refusals = self.lift(root, elf, form)
                        self.check_ir(module, False)
                        self.assertFalse(certificates.strip())
                        self.assertTrue(refusals.strip())

    def test_FDE_less_disconnected_dispatch_keeps_unknown_arm(self):
        # The jump and the candidate have no CFI and no connecting early
        # edge. The layout predecessor's li cannot erase an unbounded arm
        # from an uncertified jump outside the candidate-driven component.
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            text = "_start: ld a4,0(a0)\njr t1\n" + \
                ".Lcase_a: li a4,0\n.Lcase_b:\n" + PREFIX + \
                "add a5,s1,a4\nsw zero,-1912(a5)\nret\n"
            summaries = []
            for form, elf in self.compile_control_fixture(root, text, frames=False):
                module, certificates, refusals = self.lift(root, elf, form)
                self.check_ir(module, False)
                self.assertFalse(certificates.strip())
                self.assertTrue(refusals.strip())
                summaries.append((bool(certificates.strip()), bool(refusals.strip())))
            self.assertEqual(summaries[0], summaries[1])

    def test_missing_dispatch_arm_into_linked_cold_FDE_refuses(self):
        # Hot branches to a separate non-entry block, not to the pair. That
        # block and the pair's layout predecessor both define a4=0. Only the
        # whole linked FDE's missing-dispatch alternative can reject the pair.
        # The second variant additionally requires cold->further transitivity.
        for variant in ("direct_cold", "transitive_cold_to_further"):
            with self.subTest(variant=variant), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                text = "_start:\n.cfi_startproc\nld a4,0(a0)\nbnez a1,.Ldispatch\n" + \
                    "li a4,0\nj .Lcoldlink\n.Ldispatch: jr t1\n.cfi_endproc\n"
                if variant == "transitive_cold_to_further":
                    text += ".Lcold:\n.cfi_startproc\nli a4,0\nj .Lfurtherlink\n" + \
                        ".Lcoldlink: li a4,0\nj .Lfurtherlink\n.cfi_endproc\n"
                    region, link = ".Lfurther", ".Lfurtherlink"
                else:
                    region, link = ".Lcold", ".Lcoldlink"
                text += region + ":\n.cfi_startproc\nli a4,0\n.Lcoldcase:\n" + PREFIX + \
                    "add a5,s1,a4\nsw zero,-1912(a5)\nret\n" + \
                    link + ": li a4,0\nj .Lcoldcase\n.cfi_endproc\n"
                summaries = []
                for form, elf in self.compile_control_fixture(root, text):
                    module, certificates, refusals = self.lift(root, elf, form)
                    self.check_ir(module, False)
                    self.assertFalse(certificates.strip())
                    self.assertTrue(refusals.strip())
                    summaries.append((bool(certificates.strip()), bool(refusals.strip())))
                self.assertEqual(summaries[0], summaries[1])

    def test_direct_FDE_entry_link_keeps_physical_redefinition(self):
        # An explicit branch to the cold FDE's entry is a root, not a link to
        # its interior. Its physical li redefines a4 before the candidate, so
        # the unrelated hot FDE's uncertified jump must not poison every node.
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            text = "_start:\n.cfi_startproc\nld a4,0(a0)\nbnez a1,.Ldispatch\n" + \
                "j .Lcoldentry\n.Ldispatch: jr t1\n.cfi_endproc\n" + \
                ".Lcoldentry:\n.cfi_startproc\nli a4,0\n" + PREFIX + \
                "add a5,s1,a4\nsw zero,-1912(a5)\nret\n.cfi_endproc\n"
            summaries = []
            for form, elf in self.compile_control_fixture(root, text):
                module, certificates, refusals = self.lift(root, elf, form)
                summaries.append(self.check_ir(module, True))
                self.assertTrue(certificates.strip())
                self.assertFalse(refusals.strip())
            self.assertEqual(summaries[0], summaries[1])

    def test_live_slot_frame_boundary_retains_refusal(self):
        for variant in ("same_FDE", "other_FDE", "no_FDE"):
            with self.subTest(variant=variant), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                framed = variant != "no_FDE"
                text = "_start:\n" + (".cfi_startproc\n" if framed else "") + PREFIX + \
                    "sd s1,0(sp)\nli s1,0\nj .Ltarget\n"
                if variant == "other_FDE":
                    text += ".cfi_endproc\n.Ltarget:\n.cfi_startproc\n"
                else:
                    text += ".Ltarget:\n"
                text += "ld t0,0(sp)\nsd zero,0(sp)\nld a0,-2016(t0)\nret\n" + \
                    (".cfi_endproc\n" if framed else "")
                for form, elf in self.compile_control_fixture(root, text, framed):
                    module, certificates, refusals = self.lift(root, elf, form)
                    positive = variant == "same_FDE"
                    self.check_ir(module, positive)
                    self.assertEqual(bool(certificates.strip()), positive)
                    self.assertEqual(bool(refusals.strip()), not positive)

    def test_far_transfer_targets_are_unknown_roots(self):
        for variant in ("JALR_call", "JALR_same_link_base", "compressed_call", "compressed_tail"):
            with self.subTest(variant=variant), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                base = "ra" if variant == "JALR_same_link_base" else "t2"
                if variant.startswith("compressed"):
                    transfer = "c.jalr t2" if variant == "compressed_call" else "c.jr t2"
                    # .text starts at 0x10000. AUIPC+one page equals the
                    # interior case at 0x11000; .org has no symbol oracle.
                    text = "helper:\n.cfi_startproc\nauipc t2,1\n.option rvc\n" + transfer + \
                        "\n.option norvc\nret\n.cfi_endproc\n.org 4092\n" + \
                        "_start:\n.cfi_startproc\nli a4,0\n.Lcase:\n" + \
                        "auipc s1,0x10\naddi s1,s1,-2048\n" + \
                        "add a5,s1,a4\nsw zero,-1912(a5)\nret\n.cfi_endproc\n"
                else:
                    text = "_start:\n.cfi_startproc\nli a4,0\n.Lcase:\n" + PREFIX + \
                        "add a5,s1,a4\nsw zero,-1912(a5)\nret\n.cfi_endproc\n" + \
                        "helper:\n.cfi_startproc\n.Lfar_hi: auipc " + base + ",%pcrel_hi(.Lcase)\n" + \
                        "jalr ra," + base + ",%pcrel_lo(.Lfar_hi)\nret\n.cfi_endproc\n"
                for form, elf in self.compile_control_fixture(root, text):
                    module, certificates, refusals = self.lift(root, elf, form)
                    self.check_ir(module, False)
                    self.assertFalse(certificates.strip())
                    self.assertTrue(refusals.strip())

    def test_two_level_runtime_guard_and_refusal_edges(self):
        # The first map is writable. Its initializer is not a proof oracle.
        # Only the actual LW guard plus same-address no-write LWU window can
        # bound the selector; the final relative table is raw readonly data.
        for mutation in ("complete", "offset", "width", "base_redefinition", "store", "call",
                         "atomic", "fence", "CSR", "ECALL", "EBREAK", "signed_guard",
                         "large_LW_LWU_bound", "non_dominating_guard", "reload_not_dominated",
                         "writable_target_table", "target_table_past_section", "odd_target",
                         "noncode_target", "unbounded_first_index", "counter_wrong_step",
                         "counter_header_bypass", "first_map_past_interval",
                         "taken_stale_store", "taken_stale_call", "taken_invalid_other_table"):
            with self.subTest(mutation=mutation), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                count = "c.li s4,13\n"
                # Initialize the loop's unrelated record read without using
                # the callee's argument/result semantics in the proof.
                start = ".option norvc\n.Lloop_base_hi: auipc s2,%pcrel_hi(map_records)\n" + \
                    "addi s2,s2,%pcrel_lo(.Lloop_base_hi)\n.option rvc\nc.li s0,0\n" + count
                before = ""
                if mutation == "counter_header_bypass":
                    before = "bnez a2,.Lloop\n"
                elif mutation == "non_dominating_guard":
                    before = "bnez a2,.Ltable_hi\n"
                elif mutation == "reload_not_dominated":
                    before = "bnez a2,.Lreload\n"
                loop = start + ".Lloop: ld a1,0(s2)\nmv a0,s3\nsd a5,0(sp)\ncall helper\n" + \
                    ".option norvc\nbeqz a0,.Lselected\n.option rvc\n.Lstep: c.addiw s0," + ("2" if mutation == "counter_wrong_step" else "1") + \
                    "\nc.ldsp t0,0(sp)\nc.addi s2,16\nbne s0,s4,.Lloop\nj .Ldone\n"
                if mutation == "unbounded_first_index":
                    loop = "mv s0,a1\nj .Lselected\n.Lstep: j .Ldone\n"
                bound = "li a4," + ("2147483648" if mutation == "large_LW_LWU_bound" else "4") + "\n"
                guard = ("blt" if mutation == "signed_guard" else "bltu") + " a4,a3,.Ldefault\n"
                between = {"base_redefinition": "addi a5,a5,16\n", "store": "sw zero,8(a5)\n",
                    "call": "call helper\n", "atomic": "amoswap.w t1,zero,(a5)\n",
                    "fence": "fence\n", "CSR": "csrr t1,cycle\n", "ECALL": "ecall\n",
                    "EBREAK": "ebreak\n"}.get(mutation, "")
                reload = ("ld" if mutation == "width" else "lwu") + " a5," + \
                    ("12" if mutation == "offset" else "8") + "(a5)\n"
                section = ".data" if mutation == "writable_target_table" else ".rodata"
                targets = [".Lcase0", ".Lcase1", ".Lcase2", ".Lcase3", ".Lcase4"]
                if mutation == "odd_target":
                    targets[4] += "+1"
                elif mutation == "noncode_target":
                    targets[4] = "final_table"
                if mutation == "target_table_past_section":
                    targets = targets[:4]
                records = 1 if mutation == "first_map_past_interval" else 13
                data = ".data\n.balign 8\nmap_records:\n" + ".zero 8\n.word 0\n.zero 4\n" * records + \
                    ".section " + section + "\n.balign 4\nfinal_table:\n" + \
                    "".join(".word " + target + "-final_table\n" for target in targets)
                default = ".Ldefault: li a0,0\n"
                extra_region = ""
                if mutation == "taken_stale_store":
                    default = ".Ldefault: sw zero,8(a5)\nj .Lguard\n"
                elif mutation == "taken_stale_call":
                    default = ".Ldefault: call helper\nj .Lguard\n"
                elif mutation == "taken_invalid_other_table":
                    # The main suffix stays unchanged. A taken/default arm
                    # reaches a different FDE whose second entry is missing.
                    # Its incomplete incoming envelope cannot certify main.
                    default = ".Ldefault: j .Lother_region\n"
                    extra_region = ".Lother_region:\n.cfi_startproc\n" + \
                        "auipc s5,0x10\nli s5,0\nli t1,1\n" + \
                        "bltu t1,a1,.Lother_return\n" + \
                        ".Lother_hi: auipc t1,%pcrel_hi(other_table)\n" + \
                        "addi t1,t1,%pcrel_lo(.Lother_hi)\nslli a5,a1,2\nadd a5,a5,t1\n" + \
                        "lw a5,0(a5)\nadd a5,a5,t1\n.option rvc\nc.jr a5\n.option norvc\n" + \
                        ".Lother_return: ret\n.cfi_endproc\n"
                    data += ".section .rodata\n.balign 4\nother_table:\n.word .Lother_return-other_table\n"
                text = "_start:\n.cfi_startproc\n" + PREFIX + ACCESS + ".option rvc\n" + before + loop + \
                    ".Lselected: c.slli s0,32\nc.srli s0,32\n.option norvc\n" + \
                    ".Lmap_hi: auipc s2,%pcrel_hi(map_records)\naddi s2,s2,%pcrel_lo(.Lmap_hi)\n" + \
                    "slli a5,s0,4\nadd a5,a5,s2\nlw a3,8(a5)\n" + bound + ".Lguard:\n" + guard + between + \
                    ".Lreload:\n" + reload + ".Ltable_hi: auipc a4,%pcrel_hi(final_table)\n" + \
                    "addi a4,a4,%pcrel_lo(.Ltable_hi)\n.option rvc\nc.slli a5,2\nc.add a5,a4\n" + \
                    "c.lw a5,0(a5)\nc.add a5,a4\nc.jr a5\n.option norvc\n" + \
                    "".join(".Lcase" + str(i) + ": ld a0," + str(-2008 + 8*i) + "(s1)\nj " + \
                        (".Lstep" if i == 4 else ".Ldone") + "\n" for i in range(5)) + \
                    default + ".Ldone: ret\n.cfi_endproc\n" + extra_region + \
                    "helper:\n.cfi_startproc\nli a0,0\nret\n.cfi_endproc\n"
                for form, elf in self.compile_control_fixture(root, text, data_sections=data):
                    module, certificates, refusals = self.lift(root, elf, form)
                    # The first-map counter/hull is intentionally not a certificate.
                    # These controls retain the same actual guard/reload and
                    # readonly final table; no first-map range is claimed.
                    positive = mutation in ("complete", "unbounded_first_index", "counter_wrong_step",
                                            "counter_header_bypass", "first_map_past_interval")
                    self.check_ir(module, positive)
                    self.assertEqual(bool(certificates.strip()), positive)
                    self.assertEqual(bool(refusals.strip()), not positive)
                    table_csv = next((root / (form + "-debug")).rglob("riscv_outside_table_certificate.csv"))
                    self.assertEqual(bool(table_csv.read_text().strip()), positive)
                    if mutation in ("taken_stale_store", "taken_stale_call", "taken_invalid_other_table"):
                        table_refusals = next((root / (form + "-debug")).rglob("riscv_outside_table_refusal.csv"))
                        reason = "dependent-provisional-region-refusal" if mutation == "taken_invalid_other_table" \
                            else "taken-arm-reuses-stale-guarded-load"
                        self.assertIn(reason, table_refusals.read_text())

    def test_legacy_HI_group_with_hidden_outside_lower_refuses(self):
        # A missing arm can hide the outside ADDI from candidate discovery.
        # No outside certificate/refusal row is required for this legacy
        # group: both inferred halves must stay raw independently of it.
        for variant in ("same_FDE", "uncovered", "cross_FDE", "copied_and_killed_cross_FDE",
                        "zero_ADDIW_copied_and_killed_cross_FDE",
                        "spilled_and_killed_cross_FDE", "raw_HI_call_argument", "raw_HI_return",
                        "dead_HI_before_unrelated_JR", "complete_region", "complete_memory_region"):
            with self.subTest(variant=variant), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                framed = variant != "uncovered"
                body = "_start:\n" + (".cfi_startproc\n" if framed else "") + \
                    "auipc s1,0x10\naddi a4,s1,8\n"
                if variant == "complete_region":
                    # An immediate jump is a complete binary edge. There
                    # is no outside lower or unknown dispatch in this group.
                    body += "j .Ldone\n.Ldone: ld a0,0(a4)\nret\n.cfi_endproc\n"
                elif variant == "complete_memory_region":
                    body = "_start:\n.cfi_startproc\nauipc s1,0x10\nld a4,8(s1)\n" + \
                        "j .Ldone\n.Ldone: li a0,0\nret\n.cfi_endproc\n"
                elif variant == "raw_HI_call_argument":
                    body = "_start:\n.cfi_startproc\nauipc a1,0x10\naddi a4,a1,8\n" + \
                        "call helper\nli a1,0\nret\n.cfi_endproc\n" + \
                        "helper:\n.cfi_startproc\nli a0,0\nret\n.cfi_endproc\n"
                elif variant == "raw_HI_return":
                    body = "_start:\n.cfi_startproc\nauipc a0,0x10\naddi a4,a0,8\nret\n.cfi_endproc\n"
                elif variant == "dead_HI_before_unrelated_JR":
                    body += "li s1,0\nbnez a1,.Ldispatch\nret\n.Ldispatch: jr t0\n.cfi_endproc\n"
                elif variant == "cross_FDE":
                    body += "j .Ldispatch\n.cfi_endproc\n.Ldispatch:\n.cfi_startproc\n" + \
                        "jr t0\n.cfi_endproc\n.Lhidden:\n.cfi_startproc\n" + \
                        "addi s1,s1,2047\nld a0,-2015(s1)\nret\n.cfi_endproc\n"
                elif variant in ("copied_and_killed_cross_FDE", "zero_ADDIW_copied_and_killed_cross_FDE"):
                    copy = "addiw t0,s1,0\n" if variant == "zero_ADDIW_copied_and_killed_cross_FDE" \
                        else "mv t0,s1\n"
                    body += copy + "li s1,0\nj .Ldispatch\n.cfi_endproc\n" + \
                        ".Ldispatch:\n.cfi_startproc\njr t1\n.cfi_endproc\n" + \
                        ".Lhidden:\n.cfi_startproc\naddi t0,t0,2047\n" + \
                        "ld a0,-2015(t0)\nret\n.cfi_endproc\n"
                elif variant == "spilled_and_killed_cross_FDE":
                    # Use a memory low for the initial in-section pair, so
                    # the raw value store is a distinct non-lower operand.
                    body = "_start:\n.cfi_startproc\nauipc s1,0x10\nld a4,8(s1)\n" + \
                        "sd s1,0(sp)\nli s1,0\nj .Ldispatch\n.cfi_endproc\n" + \
                        ".Ldispatch:\n.cfi_startproc\njr t1\n.cfi_endproc\n" + \
                        ".Lhidden:\n.cfi_startproc\nld t0,0(sp)\naddi t0,t0,2047\n" + \
                        "ld a0,-2015(t0)\nret\n.cfi_endproc\n"
                else:
                    body += "bnez a1,.Ldispatch\nli s1,0\nj .Lhidden\n" + \
                        ".Ldispatch: jr t0\n.Lhidden: addi s1,s1,2047\n" + \
                        "ld a0,-2015(s1)\nret\n" + (".cfi_endproc\n" if framed else "")
                summaries = []
                for form, elf in self.compile_control_fixture(root, body, framed):
                    module, certificates, _ = self.lift(root, elf, form)
                    upper_interval = next(i for i in module.byte_intervals
                        if i.address is not None and i.address <= 0x10000 < i.address + i.size)
                    upper = upper_interval.symbolic_expressions.get(0x10000 - upper_interval.address)
                    lower = upper_interval.symbolic_expressions.get(0x10004 - upper_interval.address)
                    positive = variant in ("complete_region", "complete_memory_region", "dead_HI_before_unrelated_JR")
                    self.assertEqual(isinstance(upper, gtirb.SymAddrConst), positive)
                    self.assertEqual(isinstance(lower, gtirb.SymAddrConst), positive)
                    self.assertFalse(certificates.strip())
                    candidate_csv = next((root / (form + "-debug")).rglob("riscv_outside_section_candidate.csv"))
                    self.assertFalse(candidate_csv.read_text().strip())
                    blocked_csv = next((root / (form + "-debug")).rglob("riscv_outside_legacy_pair_blocked.csv"))
                    blocked = {tuple(int(x, 16) for x in row.split("\t")[:2])
                        for row in blocked_csv.read_text().splitlines() if row}
                    self.assertEqual((0x10000, 0x10004) in blocked, not positive)
                    # Require the actual blocking rule, not merely a raw pair.
                    # RiscVLoader real syntax decodes MV as ADDI rd,rs,0;
                    # explicit ADDIW rd,rs,0 is also a non-exempt raw use.
                    escape_csv = next((root / (form + "-debug")).rglob("riscv_outside_legacy_raw_hi_escape.csv"))
                    escapes = [tuple(row) for row in csv.reader(io.StringIO(escape_csv.read_text()), delimiter="\t") if row]
                    if variant in ("copied_and_killed_cross_FDE", "zero_ADDIW_copied_and_killed_cross_FDE"):
                        self.assertTrue(any(int(hi,16) == 0x10000 and int(ea,16) == 0x10008 and
                            reason == "unsymbolized raw HI explicit use" for hi,ea,reason in escapes))
                    if variant == "raw_HI_call_argument":
                        self.assertTrue(any(int(hi,16) == 0x10000 and
                            reason == "raw HI passed as call argument" for hi,ea,reason in escapes))
                    if variant == "raw_HI_return":
                        self.assertTrue(any(int(hi,16) == 0x10000 and
                            reason == "raw HI returned to caller" for hi,ea,reason in escapes))
                    if variant == "dead_HI_before_unrelated_JR":
                        self.assertFalse(any(int(hi,16) == 0x10000 for hi,ea,reason in escapes))
                    summaries.append((positive, sorted(blocked)))
                self.assertEqual(summaries[0], summaries[1])

    def test_unambiguous_zero_copy_as_only_legacy_split_use_refuses(self):
        # The copy is the HI's only split use. In particular, there is no
        # earlier nonzero ADDI that would make the HI ambiguous and hide a
        # deleted zero-immediate veto. The original s1 is physically killed
        # before the unrelated JR; its copied t0 value is used in another FDE.
        for variant in ("MV", "ADDI_zero", "ADDIW_zero"):
            with self.subTest(variant=variant), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                copy = {"MV": "mv t0,s1\n", "ADDI_zero": "addi t0,s1,0\n",
                        "ADDIW_zero": "addiw t0,s1,0\n"}[variant]
                text = "_start:\n.cfi_startproc\nauipc s1,0x10\n" + copy + \
                    "li s1,0\nj .Ldispatch\n.cfi_endproc\n" + \
                    ".Ldispatch:\n.cfi_startproc\njr t1\n.cfi_endproc\n" + \
                    ".Lhidden:\n.cfi_startproc\naddi t0,t0,2047\n" + \
                    "ld a0,-2015(t0)\nret\n.cfi_endproc\n"
                summaries = []
                for form, elf in self.compile_control_fixture(root, text):
                    module, certificates, _ = self.lift(root, elf, form)
                    interval = next(i for i in module.byte_intervals if i.address is not None
                        and i.address <= 0x10000 < i.address + i.size)
                    def word(pc):
                        offset = pc - interval.address
                        return int.from_bytes(interval.contents[offset:offset + 4], "little")
                    # .option norvc preserves these physical four-byte sites.
                    # AUIPC's base is 0x20000, inside the single .bss interval.
                    self.assertEqual(word(0x10000), 0x00010497)
                    self.assertEqual(word(0x10004),
                        0x0004829b if variant == "ADDIW_zero" else 0x00048293)
                    self.assertEqual(word(0x10008), 0x00000493)  # li s1,0
                    self.assertEqual(word(0x10010), 0x00030067)  # jr t1
                    self.assertTrue(any(i.section.name == ".bss" and i.address is not None
                        and i.address <= 0x20000 < i.address + i.size
                        for i in module.byte_intervals))
                    for pc in (0x10000, 0x10004):
                        self.assertNotIn(pc - interval.address, interval.symbolic_expressions)
                    self.assertFalse(certificates.strip())
                    candidate_csv = next((root / (form + "-debug")).rglob("riscv_outside_section_candidate.csv"))
                    self.assertFalse(candidate_csv.read_text().strip())
                    blocked_csv = next((root / (form + "-debug")).rglob("riscv_outside_legacy_pair_blocked.csv"))
                    blocked = {tuple(int(x,16) for x in row.split("\t")[:2])
                        for row in blocked_csv.read_text().splitlines() if row}
                    self.assertEqual({pair for pair in blocked if pair[0] == 0x10000},
                                     {(0x10000, 0x10004)})
                    escape_csv = next((root / (form + "-debug")).rglob("riscv_outside_legacy_raw_hi_escape.csv"))
                    escapes = {(int(hi,16), int(ea,16), reason) for hi,ea,reason in
                        csv.reader(io.StringIO(escape_csv.read_text()), delimiter="\t") if hi}
                    self.assertEqual({row for row in escapes if row[0] == 0x10000},
                        {(0x10000, 0x10004, "unsymbolized raw HI explicit use")})
                    # This exported diagnostic is emitted for an ambiguous
                    # split whose endpoints are raw. Together with the sole
                    # blocked pair it rules out ambiguity as a spare refusal.
                    unresolved_csv = next((root / (form + "-debug")).rglob("riscv_unresolved_pcrel_reference.csv"))
                    unresolved = [tuple(row) for row in csv.reader(
                        io.StringIO(unresolved_csv.read_text()), delimiter="\t") if row]
                    self.assertFalse(any(int(row[0],16) == 0x10000 for row in unresolved))
                    summaries.append((sorted(blocked), sorted(escapes)))
                self.assertEqual(summaries[0], summaries[1])

    def test_decoded_immediate_edges_with_relocation_metadata(self):
        # Retained instruction relocations must not make a literal branch
        # lose one of its binary successors. No target table or oracle row
        # supplies this edge; strip-all is a separate equality control.
        for variant in ("bounded_extra_access", "outside_extra_access"):
            with self.subTest(variant=variant), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                text = "_start:\n.cfi_startproc\n" + PREFIX + \
                    "beqz a1,.Lextra\n" + ACCESS + "j .Ldone\n.Lextra: ld a0," + \
                    ("-2008" if variant == "bounded_extra_access" else "0") + \
                    "(s1)\n.Ldone: ret\n.cfi_endproc\n"
                summaries = []
                for form, elf in self.compile_control_fixture(root, text, emit_relocations=True):
                    module, certificates, refusals = self.lift(root, elf, form)
                    positive = variant == "bounded_extra_access"
                    summaries.append(self.check_ir(module, positive))
                    self.assertEqual(bool(certificates.strip()), positive)
                    self.assertEqual(bool(refusals.strip()), not positive)
                self.assertEqual(summaries[0], summaries[1])

    def test_initialized_symbolic_word_anchor_refuses(self):
        # An interior label cannot split an existing 8-byte symbolic word in
        # the qualified exporter. This conservative epoch supports BSS only.
        # The ambiguity flag is confined to this synthetic data-word fixture.
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source, script, binary = root / "main.S", root / "link.ld", root / "main"
            source.write_text(".option norvc\n.option norelax\n.text\n"
                              ".globl _start\n_start:\n" + PREFIX +
                              "ld a0,-2044(s1)\nret\n"
                              ".data\n.quad _start\n.space 248\n")
            script.write_text(LINKER_SCRIPT.replace(".bss 0x20000 (NOLOAD) : { *(.bss) }",
                                                    ".data 0x20000 : { *(.data) }"))
            self.run_command("compile", ["riscv64-linux-gnu-gcc", "-march=rv64imac",
                "-mabi=lp64", "-nostdlib", "-static", "-no-pie", "-g0",
                "-Wl,--no-relax,--build-id=none", "-T", str(script),
                str(source), "-o", str(binary)])
            stripped = root / "main-stripped"
            self.run_command("strip", ["riscv64-linux-gnu-strip", "--strip-all",
                                        "-o", str(stripped), str(binary)])
            for form, elf in (("original", binary), ("stripped", stripped)):
                module, certificates, refusals = self.lift(root, elf, form,
                    ("--allow-ambiguous-data-pointers",))
                self.check_ir(module, False)
                self.assertFalse(certificates.strip())
                self.assertIn("initialized data anchor construction is unsupported", refusals)

    def test_rejected_equal_base_member_refuses_group(self):
        # Both completed ADDIs originally produce 0x207ff. The second upper
        # has an unmatched memory use, so every dependent pair must stay raw.
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source, script, binary = root / "main.S", root / "link.ld", root / "main"
            source.write_text(".option norvc\n.option norelax\n.text\n.globl _start\n"
                "_start: auipc s1,0x10\naddi s1,s1,2047\nbeqz a1,common\n"
                ".balign 32\nauipc s1,0x10\nld a0,0(s1)\naddi s1,s1,2015\n"
                "common: ld a0,-2015(s1)\nret\n.bss\n.space 256\n")
            script.write_text(LINKER_SCRIPT)
            self.run_command("compile", ["riscv64-linux-gnu-gcc", "-march=rv64imac",
                "-mabi=lp64", "-nostdlib", "-static", "-no-pie", "-g0",
                "-Wl,--no-relax,--build-id=none", "-T", str(script),
                str(source), "-o", str(binary)])
            stripped = root / "main-stripped"
            self.run_command("strip", ["riscv64-linux-gnu-strip", "--strip-all",
                                        "-o", str(stripped), str(binary)])
            for form, elf in (("original", binary), ("stripped", stripped)):
                module, certificates, refusals = self.lift(root, elf, form)
                observed = []
                for block in module.code_blocks:
                    raw = block.byte_interval.contents[block.offset:block.offset + block.size]
                    for index in range(0, len(raw), 4):
                        if int.from_bytes(raw[index:index + 4], "little") & 0xfff == 0x497:
                            observed.append(block.address + index)
                            self.assertNotIn(block.offset + index,
                                             block.byte_interval.symbolic_expressions)
                self.assertEqual(sorted(observed), [0x10000, 0x10020])
                self.assertFalse(certificates.strip())
                self.assertIn("unmatched raw HI use", refusals)
                self.assertIn("equal-base dependency refused", refusals)

    def test_binary_TLS_range_does_not_replace_ordinary_frontier(self):
        # The physical TLS section precedes BSS. DDisasm's separate artificial
        # TLS address range must not silently replace the ordinary frontier.
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source, script, binary = root / "main.S", root / "link.ld", root / "main"
            source.write_text(".option norvc\n.option norelax\n.text\n"
                              ".globl _start\n_start:\n" + PREFIX + ACCESS +
                              "ret\n.section .tdata,\"awT\",@progbits\n.quad 0\n"
                              ".bss\n.space 256\n")
            script.write_text(LINKER_SCRIPT.replace(
                ".bss 0x20000", ".tdata 0x1f000 : { *(.tdata) }\n  .bss 0x20000"))
            self.run_command("compile", ["riscv64-linux-gnu-gcc", "-march=rv64imac",
                "-mabi=lp64", "-nostdlib", "-static", "-no-pie", "-g0",
                "-Wl,--no-relax,--build-id=none", "-T", str(script),
                str(source), "-o", str(binary)])
            stripped = root / "main-stripped"
            self.run_command("strip", ["riscv64-linux-gnu-strip", "--strip-all",
                                        "-o", str(stripped), str(binary)])
            summaries = []
            for form, elf in (("original", binary), ("stripped", stripped)):
                module, certificates, refusals = self.lift(root, elf, form)
                summaries.append(self.check_ir(module, True))
                self.assertTrue(certificates.strip())
                self.assertFalse(refusals.strip())
            self.assertEqual(summaries[0], summaries[1])

    def test_shared_HI_inside_and_refused_outside_pair_stay_numeric(self):
        # One old in-section lower must not partially relocate a shared upper
        # while its outside lower is refused. A HI-only gate would miss that.
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source, script, binary = root / "main.S", root / "link.ld", root / "main"
            source.write_text(".option norvc\n.option norelax\n.text\n.globl _start\n"
                "_start: auipc t0,0x10\naddi s1,t0,2032\nld a0,-1904(s1)\n"
                "addi s2,t0,1536\nld a1,0(s2)\nret\n.bss\n.space 1792\n")
            script.write_text(LINKER_SCRIPT)
            self.run_command("compile", ["riscv64-linux-gnu-gcc", "-march=rv64imac",
                "-mabi=lp64", "-nostdlib", "-static", "-no-pie", "-g0",
                "-Wl,--no-relax,--build-id=none", "-T", str(script),
                str(source), "-o", str(binary)])
            stripped = root / "main-stripped"
            self.run_command("strip", ["riscv64-linux-gnu-strip", "--strip-all",
                                        "-o", str(stripped), str(binary)])
            for form, elf in (("original", binary), ("stripped", stripped)):
                module, certificates, refusals = self.lift(root, elf, form)
                self.check_ir(module, False)
                for pc in (0x10000, 0x10004, 0x1000c):
                    interval = next(interval for interval in module.byte_intervals
                        if interval.address is not None and
                        interval.address <= pc < interval.address + interval.size)
                    self.assertNotIn(pc - interval.address, interval.symbolic_expressions)
                self.assertFalse(certificates.strip())
                self.assertIn("unmatched raw HI use", refusals)

    def test_caller_write_ends_callee_saved_value(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source, script, binary = root / "main.S", root / "link.ld", root / "main"
            source.write_text(".option norvc\n.option norelax\n.text\n.globl _start\n"
                "_start:\n" + PREFIX + ACCESS + "mv s6,s1\nli s1,0\n"
                "jalr ra,t1,0\nli s6,0\nld a0,-2016(s6)\nret\n.bss\n.space 256\n")
            script.write_text(LINKER_SCRIPT)
            self.run_command("compile", ["riscv64-linux-gnu-gcc", "-march=rv64imac",
                "-mabi=lp64", "-nostdlib", "-static", "-no-pie", "-g0",
                "-Wl,--no-relax,--build-id=none", "-T", str(script),
                str(source), "-o", str(binary)])
            stripped = root / "main-stripped"
            self.run_command("strip", ["riscv64-linux-gnu-strip", "--strip-all",
                                        "-o", str(stripped), str(binary)])
            for form, elf in (("original", binary), ("stripped", stripped)):
                module, certificates, refusals = self.lift(root, elf, form)
                self.check_ir(module, True)
                self.assertTrue(certificates.strip())
                self.assertFalse(refusals.strip())
                rows = next((root / (form + "-debug")).rglob("riscv_outside_access.csv"))
                accesses = {int(row.split("\t")[2], 16) for row in rows.read_text().splitlines() if row}
                self.assertEqual(accesses, {0x10008})

    def test_complete_readonly_table_and_refusal_mutations(self):
        # The function region is runtime unwind bytes, kept by strip-all.
        # Names in this assembly are compiler inputs, never lifting inputs.
        for mutation in ("complete", "unguarded", "writable", "outside_region",
                         "taken_to_dispatch", "taken_arm_reenters_dispatch", "odd_target"):
            with self.subTest(mutation=mutation), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                source, script, binary = root / "main.S", root / "link.ld", root / "main"
                guard_target = ".Ltable_hi" if mutation == "taken_to_dispatch" else "default"
                guard = "bltu a4,a1," + guard_target + "\n" if mutation != "unguarded" else "addi zero,zero,0\n"
                second = "outside" if mutation == "outside_region" else "case1"
                if mutation == "odd_target":
                    second = "case1+1"
                section = ".data" if mutation == "writable" else ".rodata"
                default = "default: j .Ltable_hi\n" if mutation == "taken_arm_reenters_dispatch" else "default: li a0,0\n"
                source.write_text(".option norvc\n.option norelax\n.text\n.globl _start\n"
                    "_start:\n.cfi_startproc\n" + PREFIX + ACCESS + "li a4,1\n" + guard +
                    "auipc a4,%pcrel_hi(table)\n.Ltable_lo:\n"
                    "addi a4,a4,%pcrel_lo(.Ltable_hi)\n" +
                    "slli a5,a1,2\nadd a5,a5,a4\nlw a5,0(a5)\nadd a5,a5,a4\n"
                    ".option rvc\njr a5\n.option norvc\n"
                    "case0: ld a0,-2008(s1)\nj done\ncase1: ld a0,-2000(s1)\nj done\n"
                    + default + "done: ret\n.cfi_endproc\n"
                    "outside:\n.cfi_startproc\nret\n.cfi_endproc\n.section " + section +
                    "\n.balign 4\ntable: .word case0-table," + second + "-table\n.bss\n.space 256\n")
                # Bind the LO to the actual AUIPC label, not the ADDI.
                text = source.read_text().replace("auipc a4,%pcrel_hi(table)", ".Ltable_hi: auipc a4,%pcrel_hi(table)")
                source.write_text(text)
                script.write_text(LINKER_SCRIPT.replace(
                    ".bss 0x20000", section + " 0x1f000 : { *(" + section + ") }\n"
                    "  .eh_frame 0x1e000 : { *(.eh_frame) }\n  .bss 0x20000"))
                self.run_command("compile", ["riscv64-linux-gnu-gcc", "-march=rv64imac",
                    "-mabi=lp64", "-nostdlib", "-static", "-no-pie", "-g0",
                    "-Wl,--no-relax,--build-id=none", "-T", str(script),
                    str(source), "-o", str(binary)])
                stripped = root / "main-stripped"
                self.run_command("strip", ["riscv64-linux-gnu-strip", "--strip-all",
                                            "-o", str(stripped), str(binary)])
                for form, elf in (("original", binary), ("stripped", stripped)):
                    module, certificates, refusals = self.lift(root, elf, form)
                    self.check_ir(module, mutation == "complete")
                    table_csv = next((root / (form + "-debug")).rglob("riscv_outside_table_certificate.csv"))
                    if mutation == "complete":
                        self.assertTrue(certificates.strip())
                        self.assertFalse(refusals.strip())
                        self.assertTrue(table_csv.read_text().strip())
                    else:
                        self.assertFalse(certificates.strip())
                        self.assertTrue(refusals.strip())
                        self.assertFalse(table_csv.read_text().strip())


if __name__ == "__main__":
    unittest.main()
