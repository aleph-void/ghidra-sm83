# Credits

## Upstream

- Source: https://github.com/minorum/ghidra-sm83 ("Sharp SM83 / Game Boy extension for Ghidra")
- Commit this fork starts from: `dd3eb425a654da5b0b64c690cc2386a259d65197` ("Release: 20260915 (#64)").
  The full upstream history (254 commits) is preserved; Ghidra-Rare's work is on branch `ghidra-rare` on top of it.
- License: Apache License 2.0 (`LICENSE`, unchanged). The source files keep their copyright and license headers
  ("Copyright 2019-2020 Joonas Javanainen"). Ghidra-Rare's changes and additions are under the same license.

## Original authors

The module is the continuation of [Gekkio/GhidraBoy](https://github.com/Gekkio/GhidraBoy) (Apache-2.0, archived), which
Joonas Javanainen wrote in 2019-2020 (SLEIGH specification, loader, data types). Git author names in the history, with
GitHub logins where known:

| Author | GitHub | Commits |
|---|---|---|
| Joonas Javanainen | @Gekkio | 184 |
| Michal Andrzejczak | @minorum | 63 |
| Antonio Vazquez | @antoniovazquezblanco | 4 |
| Andrew Cook | @ariscop | 1 |
| SuperPupperDoggo | @SuperPupperDoggo | 1 |
| tellowkrinkle | @TellowKrinkle | 1 |

(`git log --format=%an | sort | uniq -c` on the upstream commit gives the same counts; minorum's commits appear under
the name "Michal Andrzejczak" and "minorum".)

## Other implementations looked at

- CTurt/GameBoy_GhidraSleigh: a Z80 SLEIGH adapted to the Game Boy CPU. It has no license, so nothing was taken from it;
  its `.cspec` is also rejected by Ghidra 12 (`segmentop` attribute `baseinsize`).
- resonancellc/SleighGB: no license, last changed in 2019; nothing taken.

## Tools used for verification (not part of this repository)

MAME `unidasm` (BSD-3-Clause, `lr35902` disassembler), RGBDS 1.0.1 (MIT), WLA-DX 10.5 (GPL-2), the Mooneye test suite
(MIT, Joonas Javanainen), GBDK-2020 4.5.0 with SDCC (GPL / MIT, see its `licenses/`). They are fetched by
`test/fetch-samples.sh` by pinned URL and SHA-256 and never committed.

## What Ghidra-Rare changed

- `GameBoyBankAnalyzer`: RAM-code copies made by any helper routine (any direction, any counter, `RST` or `CALL`) are found
  by running the helper in the p-code emulator (`copyByEmulation`); fixed a latent `NullPointerException` in `loads()` (a
  mixed `int`/`null` conditional unboxed the null); entry code calling into 0x4000-0x7FFF before any bank write goes to
  the power-up bank 1 (`fromReset`); the stale "Bad Instruction" bookmark and the empty default-space function at a jump
  into RAM code are removed.
- `GameBoyUtils`: echo RAM blocks are executable.
- `sm83.cspec`: `__sdcccall1` and `__sdcccall0` prototypes for SDCC/GBDK-2020 code.
- `ghidra_scripts/GameBoySymbolImport.java`: symbol file import.
- `settings.gradle.kts`: the extension is named from `extension.properties` (`SM83`); `extension.properties`, `.gitignore`.
- README.md: stale claims corrected, each listed limitation marked fixed or remaining; CHANGELOG.md `[Unreleased]`.
- Tests: two new JUnit tests for the analyzer, and `test/` (generators, differential and emulator harnesses, real-code
  scripts); results in `GHIDRA-RARE.md`.
