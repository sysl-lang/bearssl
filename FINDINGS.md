# What vendoring BearSSL found in sysl

Found against the prerelease of sysl's `vendored-c` branch (3ffffa28), meant for alpha.14. BearSSL's
`src/` and `inc/` are vendored unchanged.

## 1. `build-lib` compiles the package's own shim without the `c` block's include roots (bug)

`shim.c` (needed because 16 BearSSL functions are `static inline`) fails under `build-lib` on the host
and on a board: `shim.c:7:10: fatal error: 'bearssl.h' file not found`. `test` and `build` give the shim
the roots, as packages.md says they must. The same bug lwIP found (its FINDINGS 1).

## 2. No way to hand BearSSL a `libc = true` package's headers (gap) — FIXED in sysl 0.1.2 (`if = "!libc"`, cstd v0.1.0)

On a freestanding target BearSSL's headers include `<string.h>`. Nothing delivers cstd's:
- cstd has no `c { libc }` block or tag yet;
- `build-lib` refuses a `dependencies` block, and its advice "supply 'cstd' as --lib" fails even when
  `--lib` is given;
- a `--lib` root overriding a coordinate drops its exports (`'<cstd>' is no package of the graph`, and
  `takes  from 0 package(s)`, a word missing from the message);
- a board's `cstd { path }` does not satisfy bearssl's coordinate, which is fetched instead.
Wanted: a `--lib` override that counts as the package it overrides, and target-only dependencies.

## 3. A failed `c const` probe is buried under its consequences (rough edge)

A board build shows `the value of 'AES_CTR_WORDS' is not a constant expression … showing the first 5 of
167 errors`. The cause, `the C compiler refused this file's 'c const' block: 'string.h' file not found`,
is among the 162 not shown, and no flag shows them. The same as lwIP's FINDINGS 6.

## 4. Whole-aggregate loads and stores make clang's time grow quadratically (compiler bug)

A struct literal built from by-value calls emits whole-aggregate `load`/`store` of the struct:
`struct Big { data: [33000]u8, n: int }` and `two() -> &Two = Two(big(), big())` takes 74 s to build,
against 4 s at `[8000]u8`. A test helper with four such fields sat in clang for over 22 minutes. The tests
set contexts up as separate locals meanwhile.

**Status: Fixed in sysl 0.1.x; workaround removed.** The reduction builds in 0.8 s on 0.1.1, and the test
session is one pinned struct built from four by-value constructors again.

## Smaller

5. Every `@tests` file of one module must state identical `@requires`, so `(heap, os)` is repeated in
   all eight.
6. A library's `include` roots also serve the package's own shim and probes, so those see BearSSL's
   private `src/` headers. There is no root kept private to the library's own files.
7. An accessor returning a slice of self takes `*self`, so each match arm copies the value first.

**Status: 1–6 accepted for alpha.14; 7 is queued.**
- vendored-c round 2 covers 1, 3 and 6 (`include_private`). **Built and adopted** against edb75ec4:
  1 (`build-lib` host passes), 6 (`src` is `include_private`; the shim and probes need only `inc/`,
  54 tests plain and ASan pass). Still rough: 3 (a refused probe quotes clang's one error, but the sysl
  errors around it still print, 38 in all, and the clang error is not first among them). The libc gap
  (2) is closed: `build-c . --target thumbv7em-freestanding` and `riscv32-freestanding` pass with cstd.
- `lib-override` and `target-deps` cover 2.
- `aggregate-copy` covers 4: large copies become memcpy or sret.
- `tests-files` covers 5.

The separate-locals reshape from 4 is undone (sysl 0.1.1). 7 is not reproduced as a copy but is still open:
an accessor handing back a slice of a `self` array is refused on 0.1.1 as outliving its frame.
