# Ghidra-Rare notes: Sharp SM83 (Game Boy CPU, LR35902)

This is the Ghidra-Rare fork of [minorum/ghidra-sm83](https://github.com/minorum/ghidra-sm83) (Apache-2.0), itself the
continuation of [Gekkio/GhidraBoy](https://github.com/Gekkio/GhidraBoy). Authors, upstream commit and the list of changes are
in [CREDITS.md](CREDITS.md). The module is verified to the bar in Ghidra-Rare's `docs/VERIFICATION.md`; this page has the
results and the gaps. Prebuilt zips for Ghidra 12.1.3, 12.1.4 and 12.2 are on this repository's Releases page.

## What it covers

- SLEIGH specification of the SM83 (`SM83:LE:16:default`): all 245 defined base opcodes and all 256 `CB`-prefixed opcodes
  (the 11 undefined opcodes `D3 DB DD E3 E4 EB EC ED F4 FC FD` are not instructions), with p-code for registers, flags
  (including the half-carry of `ADD HL`, `ADD SP,e` and `DAA`), the `FF00`-page forms, `HL+`/`HL-`, stack and calls.
- Upstream's Game Boy ROM / boot ROM loader, hardware memory map with banked overlays, hardware register symbols and data
  types, and its analyzers (bank switching, RAM banks, interrupt handlers, callee-saved registers, unowned code, `JP (HL)`
  jump tables) and the Debugger emulator factory.
- Ghidra-Rare additions: SDCC/GBDK calling conventions, a symbol file import script, RAM-code copies found by running the
  copy helper, the power-up ROM bank for entry code (see `CREDITS.md`).

## How to test

```
GHIDRA_INSTALL_DIR=<ghidra with this directory under Ghidra/Processors/SM83 (or the zip installed)> test/run-tests.sh
JOBS=4 test/run-tests.sh --real <workdir>   # also fetches/builds the real-code samples (needs cmake, a C compiler, bison, libpng)
test/run-tests.sh --upstream                # also runs upstream's JUnit suite (./gradlew test)
```

Tools: MAME `unidasm` (`-arch lr35902`), RGBDS (`rgbasm`/`rgblink`, built by `--real`), JDK 21+ with `javac` (`JAVA_HOME`;
Ghidra 12.2 needs JDK 25). The harness lives in `test/`:

| File | Purpose |
|---|---|
| `gen_corpus.py`, `run-decode.sh`, `compare.py` | decode corpora, MAME differential, bucketed differences |
| `asm_roundtrip.py` | Ghidra's disassembly assembled again with RGBDS and compared byte for byte |
| `every-entry.sh`, `EveryEntry.java` | every SLEIGH constructor decodes at least one instruction |
| `emu-test.sh`, `SM83EmuTest.java`, `emu/cases.txt` | hand-computed p-code cases in Ghidra's emulator, plus the broken-expectation check |
| `fetch-samples.sh` | pinned, SHA-256-checked fetch and build of RGBDS, WLA-DX, the Mooneye test suite and GBDK-2020 |
| `real-check.sh`, `RealCheck.java`, `real_compare.py` | headless import without a forced language, analysis, decompile every function, MAME comparison at the same addresses |
| `symbol-check.sh`, `conv-check.sh` | symbol import and SDCC calling convention checks |

## Results

| Area | Result |
|---|---|
| Decode | vs MAME `unidasm -arch lr35902`, 146,432 slots (every first byte x 7 operand patterns plus every `CB` opcode; every first/second byte pair; every high operand byte of the 17 three-byte forms; 65,536 random slots): 122,985 exact, 17,706 semantic (same instruction, different spelling), 5,741 both invalid (the 11 undefined opcodes), **0 unexplained**. Second oracle: Ghidra's own text assembled with RGBDS 1.0.1 gives the original bytes for 73,182 instructions (386 differ only in `STOP`'s ignored second byte, which the assembler writes as 00). Every constructor reached: 121/121 (97,150 decodes) |
| Semantics | Emulator (`EmulatorHelper`) 114/114 hand-computed cases: all ALU forms and flags (half carry, carry, `DAA` in all four N/H/C situations, `ADC`/`SBC` carry chains), rotates/shifts/`SWAP`/`BIT`/`RES`/`SET` on registers and `(HL)`, 16-bit `ADD`/`INC`/`DEC`, `ADD SP,e`, `LD HL,SP+e`, every load addressing mode (`(BC)`, `(DE)`, `(HL+/-)`, `LDH`, `(C)`, `(nn)` incl. VRAM/WRAM/MBC ranges), `PUSH`/`POP` (`POP AF` masks F), `CALL`/`RET` and conditional forms, `RST`, `RETI`, `JP`/`JR` taken and not, loops, `DI`/`EI`/`HALT`/`STOP`. A deliberately wrong expectation is detected. Upstream's JUnit suite (emulator, decompiler, loader, analyzers): 492 tests passed before this fork's changes; 496 (492 + 4 new) pass after |
| Real code | 175 ROMs imported without a forced language (auto-detected `SM83:LE:16:default`): 115 Mooneye test suite ROMs (MIT, assembled from the pinned source with WLA-DX 10.5) and 60 programs built with GBDK-2020 4.5.0/SDCC from its examples (single-bank and MBC5 autobanked, `.gb` and `.gbc`) plus `test/c/conv.c`. 149,843 instructions, 3,483 functions; every instruction of every analysed run agrees with MAME at the same address (143,215 exact, 6,628 semantic, 0 unexplained). 3,480 functions decompile, 1 fails, 2 time out at 30-60 s under load (both in `crash.gb`, 21,000 instructions). 91 bad-instruction bookmarks, all explained: 23 are Ghidra's repeated-NOP run limit (NOP-padded timing ROMs), 66 are calls/jumps into the switchable window whose bank is not statically known (Mooneye's MBC tests), 2 run past the end of a copied RAM routine or of the ROM |
| Spec files | `.cspec` has `<global>`, default prototype `__asm`, `__asm_*`, `__interrupt`, `__sdcccall1`, `__sdcccall0`; `.pspec` with volatile I/O ranges and the inject library. No ELF (no ELF Game Boy binaries) and no DWARF (SDCC emits none) |
| Calling convention | SDCC `__sdcccall1`: `f(u8,u8)` -> `A`,`E` and `f(u16,u16)` -> `DE`,`BC` with results in `A`/`BC` recovered correctly by the decompiler on `test/c/conv.c`; `GameBoySymbolImport` verified on a WLA-DX `.sym` (47/47 labels) and a GBDK `.noi` |
| Builds | `.slaspec` compiles on Ghidra 12.1.3, 12.1.4 and 12.2; `sm83.sla` is about 11 KB; `tools/build-module.sh --standard --name SM83` builds the zip for all three |

### Differences from MAME, all explained

Display only: `ADD/ADC/SBC A,r` (Ghidra writes `ADD r`), `LDH` forms (Ghidra `LDH A,(0xff44)`, MAME `ld a,($FF44)`; `LDH (C),A` vs `ld ($FF00+c),a`), `JP HL` vs `jp (hl)`, `STOP` (MAME shows the ignored operand byte), `ADD SP,e` / `LD HL,SP+e` (Ghidra shows `e` signed, MAME as the unsigned byte). Both decoders treat `D3 DB DD E3 E4 EB EC ED F4 FC FD` as undefined.

### Confirmed bugs in reference tools

- MAME `lr35902`: `JR` targets are printed unwrapped, so a backward jump near address 0 gives `$FFFFFFE2` where the 16-bit CPU wraps to `$FFE2` (confirmed: PC is 16 bits).
- RGBDS always assembles `STOP` with a 00 second byte (not a bug: the byte is ignored by the CPU, so `STOP` decodes any value).

### Changes found by testing

All are commits on `ghidra-rare`; details in `CHANGELOG.md`.

- Latent `NullPointerException` in `GameBoyBankAnalyzer.loads()` (found by the first real ROM with a non-constant register load before a call).
- RAM routines copied by helpers other than the five recognised loops (Mooneye's reversed `DE`->`HL` helper, GBDK's `rst $30` copier) were not mapped; the jump into HRAM produced a "Bad Instruction" bookmark. Now found by running the helper in the emulator.
- Entry code calling into 0x4000-0x7FFF before any bank write was unresolved (bank 1 is mapped at power-up).
- A jump into RAM code left a stale bookmark and an empty default-space function; echo RAM was not executable.
- `GameBoyKindOption` overrode `Option.getCustomEditorComponent()`, whose signature changed in Ghidra 12.2: the module did not compile there. The option is now a plain enum option.
- GBDK conventions, symbol import (issues #5, #11, #17 of GhidraBoy).

## Known gaps

| Gap | Why it stays |
|---|---|
| `IME`, `halt`, `stop`, `mbc_write` are user ops; interrupt dispatch, `EI`'s one-instruction delay, the HALT bug, STOP speed switching and MBC bank switching are not modelled | CPU/cartridge hardware state; the user ops keep `DI`/`EI`/bank writes visible in the decompiler where a register write would be removed as dead. Callbacks are provided in the emulator factory |
| The 11 undefined opcodes are bad instructions | The hardware locks up on them |
| Calls and jumps into 0x4000-0x7FFF are resolved only after constant bank writes, from the power-up state, or through configured dispatchers (66 unresolved flows in the Mooneye MBC tests) | The bank depends on run-time values or on which of several merged paths ran |
| RAM code that is written byte by byte (not copied from ROM) is a function in uninitialised RAM that decompiles as `halt_baddata`; a copied routine that falls through past its copied bytes makes that one function fail to decompile (`lcdon_write_timing-GS`) | The bytes are not in the program |
| Carry-chain idioms (`SRL B`/`RR C`, 16-bit `SBC` compares) decompile byte-wise | Decompiler rule behaviour outside the module; the p-code is exact |
| `__sdcccall1`: parameter order for mixed `A`/`DE` placement, 16-bit second parameter after an 8-bit first one, callee-popped stack parameters | Ghidra prototypes list registers in a fixed order and have one fixed stack effect |
| No processor manual index (GhidraBoy #4) | The manual is Nintendo's; its page numbers cannot be checked without the PDF |

## Unverified

- Boot ROM loading (DMG/DMG0/MGB/SGB/SGB2/CGB): no freely redistributable boot ROM.
- Commercial game ROMs and the Game Boy Color double-speed / SGB specifics; MBC variants the header table does not name (MBC1 multicart wiring, MBC30, MBC6/7 bank rules).
- The Debugger emulator factory inside the Ghidra GUI (upstream's tests drive `GameBoyEmulation` directly).
- The loader's hardware type drop-down in the GUI import dialog (headless import and the JUnit loader tests pass; the dialog was not opened).
- Decompile of hand-written assembly beyond the Mooneye programs (calling convention guesses stay per function).

