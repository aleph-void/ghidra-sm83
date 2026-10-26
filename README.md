# ghidra-sm83: Sharp SM83 / Game Boy extension for Ghidra

**Very experimental! No compatibility guarantees!**

Continuation of [Gekkio/GhidraBoy](https://github.com/Gekkio/GhidraBoy), which
is archived. Report issues [here](https://github.com/minorum/ghidra-sm83/issues).

This repository is the Ghidra-Rare fork of
[minorum/ghidra-sm83](https://github.com/minorum/ghidra-sm83): the upstream
history is unchanged and the Ghidra-Rare work sits on top of it. It is tested to
the bar in Ghidra-Rare's `docs/VERIFICATION.md` (decode differential against MAME
and the RGBDS assembler, emulator-checked p-code, real ROMs); the results, what
was changed and what is still open are in [GHIDRA-RARE.md](GHIDRA-RARE.md),
authorship in [CREDITS.md](CREDITS.md). Prebuilt zips for each Ghidra version are on
this repository's Releases page.

Supported Ghidra versions:

- 12.1.3
- 12.1.4
- 12.2

![Tetris disassembly](screenshot.png)

## Features

* Sharp SM83 (CPU core used in Game Boy) support for Sleigh
* Game Boy ROM loader:
  - Can load unbanked ROMs (&lt;= 32kB, e.g. Tetris)
  - Can load banked ROMs (&gt; 32kB, e.g. Pokemon)
  - Can load greyscale boot ROMs (DMG/DMG0/MGB/SGB/SGB2)
  - Can load color boot ROMs (CGB/CGB0)
* Calling conventions for SDCC/GBDK-2020 code (`__sdcccall1`, `__sdcccall0`) next to the
  assembly-oriented `__asm*` ones
* `GameBoySymbolImport` script: labels (and, optionally, functions) from RGBDS, WLA-DX and
  BGB `.sym` files and GBDK/SDCC `.noi` files
* Memory blocks based on the hardware memory map
  - Banked regions use overlays, Ghidra's only way to map several contents
    at the same address
  - GB vs GBC differences are handled (e.g. banked WRAM)
- Symbols for hardware registers (0xFFxx range)
  - GB vs GBC differences are handled (e.g. existence of KEY1 register)
* Game Boy cartridge header data types
  - Enumerated types for some things

## How to install

1. Download a [prebuilt release](https://github.com/minorum/ghidra-sm83/releases), or build it yourself.
2. Start Ghidra
3. File -> Install Extensions; uninstall GhidraBoy if it is installed
4. Press the plus icon ("Add extension")
5. Choose the built or downloaded SM83 zip file
6. Restart Ghidra when prompted to load the extension properly

## How to build

As a prerequisite, you need to have a Ghidra installation somewhere (an actual
installation, not a copy of Ghidra source code!).

```
export GHIDRA_INSTALL_DIR=/path/to/ghidra
./gradlew
```

or

```
./gradlew -Pghidra.dir=/path/to/ghidra
```

You can then find a built extension .zip in the `build/distributions` directory.
Ghidra-Rare's release builds use `tools/build-module.sh --standard` instead (Ghidra's own
`buildExtension` Gradle script); the extension is named `SM83` either way.

## Open questions / problems

Status in this fork: **fixed**, **remaining** (with the reason), or unchanged from upstream.

- Decompiler output is difficult to read for some carry-chain idioms. 16-bit
  shifts through carry on a register pair (`SRL B` / `RR C`) and single rotates
  decompile as shifts, and a 16-bit `SUB` / `SBC` compare as a byte-wise
  three-way comparison. These stay byte-level: an 8-bit value shifted into 16
  bits through `A` (`SLA C` / `RLA`), 16-bit `ADD` / `ADC` (`CONCAT11` with
  `CARRY1`) and chains of rotates. The "Game Boy JP (HL) Jump Tables" analyzer recovers
  `LD A,(HL+)` / `LD H,(HL)` / `LD L,A` / `JP HL` tables Ghidra's switch
  recovery misses; other pointer loads are not recognized.
  **Remaining**: the p-code is exact (checked on the emulator); how the decompiler
  folds carry flags into wider arithmetic is outside the module.
- Default "ASM calling convention" assumes all registers can be inputs and/or
  outputs. Inputs/outputs are often guessed incorrectly; the `__asm_a`,
  `__asm_hl`, `__asm_f`, `__asm_void` and `__asm_saved` conventions narrow the
  outputs or mark BC/DE/HL as preserved, but still have to be chosen per function.
  **Remaining** for hand-written assembly (the registers a routine uses are not
  declared anywhere); **fixed** for SDCC/GBDK-2020 code, which has a documented
  ABI: `__sdcccall1` (the default of SDCC 4.x) and `__sdcccall0`. Ghidra cannot
  express every placement rule of `__sdcccall1`: it lists parameters in register
  order (`A`, `DE`, `BC`, then the stack), so `f(uint8_t *p, uint8_t n)` (`p` in
  `DE`, `n` in `A`) shows `n` first, and a 16-bit second parameter after an 8-bit
  first one (SDCC: `BC`) is assigned `DE`. Types and registers are right for the
  common shapes (`f(u8, u8)`, `f(u16, u16)`, results in `A`/`BC`/`DEBC`). SDCC functions pop
  their stack parameters themselves (`pop hl; add sp,n; jp (hl)`), which the prototype's fixed
  stack effect of 2 cannot describe: set the purge of such a function by hand.
- Banked memory uses overlays. The "Game Boy Bank Switching" analyzer resolves
  calls into 0x4000-0x7fff after constant bank register writes (including
  MBC1/MBC5 upper bank bits), and inline
  far call / jump table dispatchers once their addresses are set in the
  analysis options; other cross-bank calls still need manual resolution.
  On GBC, VRAM bank 0 and WRAM bank 1 are in the default address space; the
  "Game Boy RAM Banks" analyzer moves references into the other banks after
  constant `VBK`/`SVBK` writes, and `LD A,(nn)` / `LD (nn),A` decompile to the
  selected bank. Accesses through `(HL)` still use the default space.
  **Improved**: entry code that calls into 0x4000-0x7fff before any bank write
  now goes to bank 1, the power-up bank (also for code it copies to RAM).
  **Remaining**: a bank that depends on run time values or on which of several
  paths was taken is not knowable statically.

### Limitations inherited from GhidraBoy

From the [issue list of Gekkio/GhidraBoy](https://github.com/Gekkio/GhidraBoy/issues):

- #3 MBC register writes referenced bank 0 ROM: **fixed** in the upstream
  continuation (`mbc_write` user op, no ROM reference).
- #4 Processor manual index: **remaining**. The manual is Nintendo's, and its
  page numbers cannot be checked here without distributing it.
- #5 GBDK calling convention: **fixed** (see above).
- #7 `ADC A,H` missing: **not a bug**. Every one of the 501 defined opcodes is
  compared with MAME, and `ADC H` (0x8c) decodes (the module prints the
  accumulator operand of `ADD`/`ADC`/`SBC` implicitly, `ADC H`).
- #11 Loading SYM symbol files: **fixed**, `GameBoySymbolImport` (Script Manager,
  category "Game Boy").
- #12 Cartridge RAM banks (`xramN` overlays) and #14 echo RAM: **fixed** in the
  upstream continuation; echo RAM is now executable like the work RAM it mirrors.
- #17 Function entry points not recognized: **fixed** by upstream's analyzers
  (inline jump tables, unowned code, vectors), and `GameBoySymbolImport ... functions`
  creates a function at every global label on code. Not testable on the reporter's
  ROM, which is commercial.

## License

Licensed under the Apache License, Version 2.0.
