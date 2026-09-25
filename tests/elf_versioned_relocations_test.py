"""A relocation must retain the version of its particular dynamic symbol."""
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

from disassemble_reassemble_check import disassemble


@unittest.skipUnless(shutil.which("gcc"), "ELF compiler required")
class ElfVersionedRelocationsTest(unittest.TestCase):
    def test_distinct_versions_through_plt_and_got(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            library = root / "library.c"
            library.write_text('''
                int api_old(int x) { return x + 10; }
                int api_new(int x) { return x + 20; }
                __asm__(".symver api_old,api@LIBTEST_1");
                __asm__(".symver api_new,api@@LIBTEST_2");
            ''')
            versions = root / "library.map"
            versions.write_text('''
                LIBTEST_1 { global: api; local: *; };
                LIBTEST_2 { global: api; } LIBTEST_1;
            ''')
            caller = root / "caller.c"
            caller.write_text('''
                extern int api(int);
                extern int old_api(int);
                __asm__(".symver old_api,api@LIBTEST_1");
                int main(void) { return old_api(1) != 11 || api(1) != 21; }
            ''')
            subprocess.run([
                "gcc", "-O2", "-fPIC", "-shared", str(library),
                "-Wl,--version-script=" + str(versions),
                "-Wl,-soname,libversions.so", "-o", str(root / "libversions.so"),
            ], check=True)
            for flags in ([], ["-fno-plt"]):
                with self.subTest(flags=flags):
                    binary = root / ("got" if flags else "plt")
                    subprocess.run([
                        "gcc", "-O2", "-no-pie", *flags, str(caller),
                        "-L" + str(root), "-lversions", "-Wl,-rpath,$ORIGIN",
                        "-o", str(binary),
                    ], check=True)
                    subprocess.run([str(binary)], check=True,
                                   env={**os.environ, "LD_LIBRARY_PATH": str(root)})
                    module = disassemble(binary).ir().modules[0]
                    _, needed, entries = module.aux_data["elfSymbolVersions"].data
                    versions_used = {
                        needed["libversions.so"][entries[symbol][0]]
                        for symbol in module.aux_data["symbolForwarding"].data.values()
                        if symbol.name == "api"
                    }
                    self.assertEqual(versions_used, {"LIBTEST_1", "LIBTEST_2"})


if __name__ == "__main__":
    unittest.main()
