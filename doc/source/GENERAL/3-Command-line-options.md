# Command-Line options

Ddisasm accepts the following options:

`--help`
:   produce help message

`--version`
:   display ddisasm version

`--ir arg`
:   GTIRB output file

`--json arg`
:   GTIRB json output file

`--asm arg`
:   ASM output file

`--debug`
:   generate GTIRB file with debugging information

`--debug-dir arg`
:   location to write CSV files for debugging

`--hints arg`
:   location of user-provided hints file

`--input-file arg`
:   File to disasemble

`--ignore-errors`
:   Return success even if there are disassembly errors.

`--allow-ambiguous-data-pointers`
:   Explicitly permit legacy ELF absolute-data pointer guesses, with a warning
    naming affected objects. By default, a selected pointer without relocation
    evidence is an error: an address-shaped integer is indistinguishable from a
    pointer, and changing its value during relayout can corrupt the program.
    `--ignore-errors` does not enable this policy. Prefer a PIE input or link
    with `-Wl,--emit-relocs` and retain the resulting static relocation tables.
    Non-allocated REL/RELA sections linked to SYMTAB establish coverage only
    for their `sh_info` source section; dynamic relocation tables and static
    tables for other sections do not. Within a covered section, words without
    relocations stay literal. Partially stripped sections without a retained
    table can still be refused. As with other ELF metadata, retained tables
    must not have individual entries removed. ABI-typed constructor/destructor
    arrays and typed ELF metadata handled separately (dynamic, relocation,
    unwind, and PLT/GOT tables) do not require this override.

    On RV64 ELF inputs, the same flag also permits a narrow outside-section
    data-base guess when the complete binary proof fails. An adjacent
    AUIPC/ADDI pair using the same register may select the unique final,
    writable, non-executable, non-TLS zero-fill byte interval, with its computed
    base between 1 and 2047 bytes past that interval. No relocation or bounded
    access is required. The emitted HI expression names the **start** of the
    interval plus the original base's offset; the LO expression names the HI
    instruction. The warning identifies each pair and every waived proof site.

    This assumes the pair executes together and its derived accesses move with
    that interval. A rewriter must preserve the globals' offsets from the start
    label, including through assembly and linking. A wrong provenance/section
    guess or changed internal offsets can silently corrupt data or crash.
    Concrete competing definitions, known entry into the LO, independent raw-HI
    consumers, incompatible equal-base members, contradictory bounded accesses,
    invalid geometry, and incomplete/conflicting emitted expressions still
    refuse. `--ignore-errors` cannot enable a guess or waive its emission checks.

`-K [ --keep-functions ] arg`
:   Print the given functions even if they are skipped by default (e.g. _start)

`--self-diagnose`
:   This option is useful for debugging. Use relocation information to emit a self diagnosis
    of the symbolization process. This option only works if the target
    binary contains complete relocation information. You can enable
    that in `ld` using the option `--emit-relocs`.

`-F [ --skip-function-analysis ]`
:   Skip additional analyses to compute more precise function boundaries.

`--with-souffle-relations`
:   Package facts/output relations into an AuxData table.

`--no-cfi-directives`
:   Do not produce cfi directives. Instead it produces symbolic expressions in .eh_frame
(this functionality is experimental and does not produce reliable results).

`-j [ --threads ]`
:   Number of cores to use.

`-n [ --no-analysis ]`
:   Do not perform disassembly. This option only parses/loads the binary object into GTIRB.

`-I [ --interpreter ] arg`
:   Execute the Souffle interpreter with the specified source directory.

`-L [ --library-dir ] arg`
:   Specify the search directory for the Souffle interpreter to locate functor libraries.

`--profile arg`
:   Generate Souffle profiling information in the specified directory.
