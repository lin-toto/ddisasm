"""Relocations into merged string suffixes need real relocatable symbols."""
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

import gtirb


class StringSuffixRelocationTest(unittest.TestCase):
    def check_suffix(self, compiler, emulator=(), extra=()):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            text = "received rejection status rather than cert"
            suffix = len(text) - 4
            source = root / "library.c"
            source.write_text(f'''
                #include <string.h>
                static const char message[] = "{text}";
                const char *const aliases[] = {{ message + {suffix}, message + {suffix} }};
                const char *get_message(void) {{ return strchr(message, 'r'); }}
            ''')
            library = root / "libtails.so"
            subprocess.run([compiler, "-O0", "-g", "-fno-builtin", "-fPIC", "-shared", "-nostdlib",
                            "-Wl,--build-id=none", *extra, str(source), "-o", str(library)],
                           check=True, capture_output=True)
            irpath = root / "library.gtirb"
            result = subprocess.run(["ddisasm", str(library), "--ir", str(irpath), "-j", "1"],
                                    check=True, capture_output=True, timeout=60)
            self.assertNotIn(b"integral symbol pointing into existing block", result.stderr)
            module = gtirb.IR.load_protobuf(irpath).modules[0]
            message = next(module.symbols_named("message")).referent
            aliases = next(module.symbols_named("aliases")).referent
            for index in range(2):
                expression = aliases.byte_interval.symbolic_expressions[aliases.offset + 8 * index]
                self.assertIsInstance(expression, gtirb.SymAddrConst)
                self.assertIsNotNone(expression.symbol.referent)
                target = expression.symbol.referent.address + expression.offset
                if expression.symbol.at_end:
                    target += expression.symbol.referent.size
                self.assertEqual(target, message.address + suffix)
            assembly, obj = root / "recovered.S", root / "recovered.o"
            subprocess.run(["gtirb-pprinter", "--ir", str(irpath), "--asm", str(assembly),
                            "--shared", "no", "--policy", "complete"], check=True, capture_output=True)
            subprocess.run([compiler, "-c", str(assembly), "-o", str(obj), *extra],
                           check=True, capture_output=True)
            caller = root / "caller.c"
            caller.write_text(f'''
                #include <string.h>
                extern const char *const aliases[];
                extern const char *get_message(void);
                int main(void) {{
                    return strcmp(get_message(), "{text}") || strcmp(aliases[0], "cert") ||
                           aliases[0] != aliases[1] || aliases[0] != get_message() + {suffix};
                }}
            ''')
            rebuilt = root / "rebuilt"
            subprocess.run([compiler, "-no-pie", str(caller), str(obj), "-o", str(rebuilt), *extra],
                           check=True, capture_output=True)
            subprocess.run([*emulator, str(rebuilt)], check=True, capture_output=True, timeout=15)

    @unittest.skipUnless(shutil.which("gcc"), "x64 compiler required")
    def test_x64_string_suffix(self):
        self.check_suffix("gcc")

    @unittest.skipUnless(shutil.which("aarch64-linux-gnu-gcc") and shutil.which("qemu-aarch64"),
                         "AArch64 compiler and emulator required")
    def test_aarch64_string_suffix(self):
        self.check_suffix("aarch64-linux-gnu-gcc", ("qemu-aarch64", "-L", "/usr/aarch64-linux-gnu"))

    @unittest.skipUnless(shutil.which("riscv64-linux-gnu-gcc") and shutil.which("qemu-riscv64"),
                         "RV64 compiler and emulator required")
    def test_riscv_string_suffix(self):
        self.check_suffix("riscv64-linux-gnu-gcc", ("qemu-riscv64", "-L", "/usr/riscv64-linux-gnu"),
                          ("-Wl,--no-relax",))


if __name__ == "__main__":
    unittest.main()
