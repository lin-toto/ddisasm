"""Address-qualified expressions must survive ABI/COPY symbol forwarding."""

from pathlib import Path
import platform
import subprocess
import tempfile
import unittest

import gtirb
from disassemble_reassemble_check import binary_print, disassemble


@unittest.skipUnless(platform.system() == "Linux" and platform.machine() == "x86_64",
                     "requires Linux x86-64 native tools")
class ElfSymbolForwardingTests(unittest.TestCase):
    def test_copy_relocation_expressions_roundtrip(self):
        # Both PIE and non-PIE can have COPY relocations. Check that references
        # resolve to the specific forwarded symbol, not an arbitrary namesake.
        for flags in (("-fPIE", "-pie"), ("-fno-pie", "-no-pie")):
            with self.subTest(flags=flags), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                source = root / "copy.c"
                source.write_text('''
                    #include <stdio.h>
                    FILE **streams[] = { &stdout, &stderr };
                    int main(void) {
                        if (*streams[0] != stdout || *streams[1] != stderr)
                            return 2;
                        fputs("out\\n", *streams[0]);
                        fputs("err\\n", *streams[1]);
                        return 0;
                    }
                ''')
                binary = root / "ex"
                subprocess.run(["gcc", "-O0", *flags, str(source), "-o", str(binary)], check=True)
                relocs = subprocess.check_output(["readelf", "-rW", str(binary)], text=True)
                self.assertIn("R_X86_64_COPY", relocs)
                result = disassemble(binary)
                module = result.ir().modules[0]
                forwarding = module.aux_data["symbolForwarding"].data
                for name in ("stdout", "stderr"):
                    symbol = next(module.symbols_named(name))
                    copy = next(module.symbols_named(name + "_copy"))
                    self.assertIs(forwarding[copy], symbol)
                    self.assertIsInstance(symbol.referent, gtirb.ProxyBlock)
                    self.assertTrue(any(isinstance(expr, gtirb.SymAddrConst) and expr.symbol is symbol
                                        for interval in module.byte_intervals
                                        for expr in interval.symbolic_expressions.values()))
                rewritten = root / "rewritten"
                binary_print(result.ir_path, rewritten)
                baseline = subprocess.run([str(binary)], capture_output=True, check=True)
                actual = subprocess.run([str(rewritten)], capture_output=True, check=True)
                self.assertEqual((actual.stdout, actual.stderr), (baseline.stdout, baseline.stderr))

    def test_static_abi_symbol_expressions_lift(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "static.c"
            source.write_text("int main(void) { return 0; }\n")
            binary = root / "ex"
            subprocess.run(["gcc", "-O0", "-static", str(source), "-o", str(binary)], check=True)
            module = disassemble(binary).ir().modules[0]
            symbol = next(module.symbols_named("__rela_iplt_start"))
            copy = next(module.symbols_named("__rela_iplt_start_copy"))
            self.assertIs(module.aux_data["symbolForwarding"].data[copy], symbol)


if __name__ == "__main__":
    unittest.main()
