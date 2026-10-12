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

A search over pool sizes with 6-byte pinning, run under the old model BH-SEC-1, found nothing
better than equal pools of 120: with pinning this expensive, more selections lower the level,
by half a bit for each doubling of a round's selection count. BH-SEC-2 gives this instance the
same level, 88.411; the search has not been run again under it.

## Result and next steps

Every count is at or below the baseline's with this layout, so it is the one to build on. The
work on this track is the pinning puzzles. Moving the 48 bits into a round and pinning with
5-byte puzzles was tried under the old model BH-SEC-1 (`late-round48`, since removed from the
board): BH-SEC-2 caps such a design at 80.011 bits, the work of two 5-byte pinning puzzles,
which is below this track's floor of 88.4. The level here, 88.411, is under its cap of 96.011.

## Attribution

Built with Claude Opus 5.5 in Claude Code, directed by the repository's maintainer.
