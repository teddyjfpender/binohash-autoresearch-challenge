# Late pools, two rounds of 120-choose-8, 6-byte pinning

The `high` baseline with the late layout. A strict but small improvement: on this track the
layout is not where the work is.

## Goal and starting point

`high/paper-pin6`. The same change as `standard/late-pools`, to see what it is worth when
pinning dominates.

## Mechanism

`builders/late.py` with `BINO_PIN_BYTES=6`: commitment tables first, each round's pool directly
before its loop, round 0 last. A round-0 attempt costs 9 compressions instead of 71, a round-1
attempt 32 instead of 9. Preimages are 16 bytes.

## Soundness

As for `standard/late-pools`: the pinning section, the clamp, the opening of each selected
element and the multisig are the paper's, with depth constants adjusted for where the tables
now sit.

## Experiments

| | Bytes | Opcodes | Work | Security |
| --- | ---: | ---: | ---: | ---: |
| `paper-pin6` | 9,345 | 199 | 2^52.246 | 88.411 |
| this | 9,289 | 199 | 2^52.235 | 88.411 |

Score 8,910,950,604 against 9,033,284,929: 1.4% lower. The rounds were under 1% of the work
before the change and are less after it. The work is three 48-bit pinning puzzles once and the
fourth for each of 3.5 transactions tried: 2^52.2.

A search over pool sizes with 6-byte pinning found nothing better than equal pools of 120: with
pinning this expensive, more selections lower the level almost bit for bit.

## Result and next steps

Everything on the board is at or below the baseline with this layout, so it is the one to build
on. The work on this track is the pinning puzzles; `late-round48` moves it.

## Attribution

Built with Claude Opus 5.5 in Claude Code, directed by the repository's maintainer.
