# Task for an optimisation agent: Binohash

Lower the score of a track, **bytes x opcodes x 2^(work_bits - 40)**, with an instance the
trusted evaluator accepts at or above the track's security floor. The baselines are the
construction of the Binohash paper as this evaluator counts it (`standard`: 9,349 bytes, 199
opcodes, 2^46.74 compressions at 81.52 bits; `high`: 9,345, 199, 2^52.25 at 88.41). General
rules are in [AGENTS.md](../../AGENTS.md); this file is the Binohash-specific part.

## Fixed

- **Tracks.** `standard` (`bh1-standard`, floor 81.5 bits) and `high` (`bh1-high`, floor 88.4).
- **The security model.** [BH-SEC-1](spec/SECURITY-MODEL.md): the paper's collision accounting
  with puzzle work counted exactly, an attacker who abandons a transaction at the first round
  without a solution, and the cheaper of two attacks. For rounds of `S_r` selections under
  puzzles of `W_r` bits and a cheapest pinning puzzle of `W_pin` bits, the exhaustive birthday
  costs

      sum_r (W_r - log2(S_r) / 2) + log2(2^W_pin + S_1 + p_1 S_2 + ...)      bits

  and testing stored digests on fresh transactions costs about `sum_r W_r` bits plus what
  pinning adds. Read the model before trusting an intuition about it: more selections lower the
  first and do nothing for the second.

- **The work model.** [BH-WORK-1](spec/WORK-MODEL.md): expected SHA-256 compressions for one
  spend with the reference grinder, including the retries when a round has no solution.
- **What an instance must do.** [spec/DESIGN.md](spec/DESIGN.md), sections 4 and 5: the static
  checks and what every lane requires.
- **Trusted code.** Everything except `builders/`.

## Yours to change

`builders/`: Python that turns build knobs into an instance file. A builder is selected and
parameterised by `BINO_*` knobs, which you set in `submission.json`:

| Knob | Meaning |
| --- | --- |
| `BINO_BUILDER` | The builder: `paper`, `late`, or one you add to `builders/__init__.py`. |
| `BINO_ROUNDS` | `n:t` per round, for example `120:8,120:8`. |
| `BINO_PIN_BYTES` | Bytes below 60 of a pinning signature; each byte is 8 bits of work. |
| `BINO_ROUND_BYTES` | The same per round. |
| `BINO_CLAMP` | `late` only: `all` (default) or `later`, which omits the index clamp in the round that runs first. |
| `BINO_*` | Any further knob a builder reads, including new ones you add. |

The knob reference and the instance format are in [`builders/README.md`](builders/README.md)
and [spec/DESIGN.md](spec/DESIGN.md), section 2. Within the format the script is yours:
layout, stack choreography, pool sizes, number of rounds, puzzle sizes, the hash that opens
commitments, `OP_CODESEPARATOR` placement, what lives in the script and what in the witness.

Outside it, and so a contract proposal and not a submission: other puzzle kinds, pools shared
between rounds, the polyglot digest of the paper's appendix D, conditional execution
([spec/DESIGN.md](spec/DESIGN.md), section 8).

## Architectures

Declare one in `submission.json`. The registry is [`architectures.json`](architectures.json):

| Architecture | Selection and binding | Shipped builders |
| --- | --- | --- |
| `rolled-subset` | Separate signature and commitment tables; an index walked through `OP_ROLL` once per table; one pool, one table and one multisig per round. | `paper`, `late` |

An instance organised differently is a new architecture: for example one table of interleaved
pairs, selections that are not walked one index at a time, or rounds that share a multisig.
Propose it as [spec/ARCHITECTURES.md](../../spec/ARCHITECTURES.md) describes. Different pool
sizes, round counts, puzzle sizes or a reordered layout of the same tables are refinements.

## Where the cost is

Measured on the `standard` baseline. Read `score.json` after a run for the same breakdown of
your instance.

**Opcodes: 199 of 201.**

| Part | Operations |
| --- | ---: |
| Pinning: the `SIGHASH_SINGLE` check and four puzzles | 13 |
| Per selected element: `ROLL MIN DUP ADD ROLL ROLL HASH160 EQUALVERIFY ROLL` | 9 |
| Per selected element: rolling its key up, and the key itself in the multisig | 2 |
| Per round: puzzle signature, size check, multisig and the puzzle key | 5 |
| Two rounds of eight | 13 + 2 x (11 x 8 + 5) = 199 |

**Bytes: 9,349.**

| Part | Bytes |
| --- | ---: |
| 240 commitments, 21 bytes each with their push | 5,040 |
| 240 signatures, 10 bytes each with their push | 2,400 |
| Selection loops and multisig, both rounds | 460 |
| Pinning | 201 |
| Unlocking script: 6 puzzle signatures, 16 keys, 16 preimages, 16 indexes | 1,248 |

**Work: 2^46.74 compressions.**

| Part | |
| --- | --- |
| Three pinning puzzles, once | 2^43.0: 2^40 attempts each at 2 to 3 compressions |
| The `SIGHASH_ALL` pinning puzzle, per transaction tried | 2^41.6 |
| Round 1 attempt | 9 compressions |
| Round 0 attempt | 71 compressions: its pool is early in the script, so each attempt rehashes all of round 1 |
| Solutions per round per transaction | 0.76, so a round succeeds with probability 0.53 and both with 0.28 |
| Transactions tried per spend | 3.5 |

**Security: 81.52 against a floor of 81.5.** The puzzles come in whole bytes, 8 bits at a time,
so the levels a design can reach are coarse. More selections lower the level and fewer raise
it, while fewer selections also mean more retries. That tension is the heart of the parameter
search.

## What has been tried

The first search is written up in the [README](README.md#what-the-first-search-found) and in
the notes of the starting board's submissions. In short:

| Direction | Result | Where |
| --- | --- | --- |
| Commitment tables ahead of both pools | 0.66 bits less work, nothing else changes | `standard/late-pools` |
| Unequal pools | 0.3 bits more, for 1.6 kB; or 428 bytes less at less work than the baseline | `late-pools-120-172`, `late-pools-108-120` |
| 48-bit round puzzle instead of 48-bit pinning (`high`) | 0.8 bits less work | `high/late-round48` |
| No clamp in the round that runs first | 191 operations; or a ninth selection there and the lowest score (1.93x below the baseline); or 7,854 bytes | `late-unclamped`, `late-unclamped-116-128`, `late-unclamped-104-88` |
| No pinning | Capped at the sum of the round puzzles: 80.0 bits | negative |
| Signature and commitment interleaved as pairs | The second fetch is off by one; fixing it costs the operation saved | negative |
| No index clamp anywhere | Unsound: the audit finds a selection from another round's signatures | negative, `tests/specimen.py` |
| Three rounds | Does not fit 201 operations and 10,000 bytes together | negative |
| A cheap scarce round beside a plentiful one | 72 bits, not 81.8; this is the design that corrected the model | negative, `tests/test_model.py` |

Leads, not facts. Verify before relying on them:

- Round 1's attempts still rehash round 0's pool: 19 of its 32 compressions in `late-pools`.
  One pool always has the other behind it because a scriptCode runs to the end of the script.
  Anything that makes the pool in front smaller, or lets two pools share a tail, pays directly.
- Each selected element costs 11 operations: 9 in the loop, one to roll its key up, one for the
  key in the multisig. The opcode budget is what stops pools from shrinking, so an operation
  saved per element converts into bytes.
- Keys travel in the witness at 34 bytes per selected element.
- The clamp is needed wherever another round's signatures lie below a pool: in the late layout,
  every round but the first to run. A layout in which the second round also has nothing
  selectable below it would free another eight operations. It needs an argument, not only a
  passing audit; the notes of `late-unclamped` show the kind.
- Compressions per attempt depend on where a pool falls modulo 64 bytes. Unclamping moved a
  pool across a block boundary and cost one compression per attempt. Nobody has tuned this.
- The two attacks of BH-SEC-1 meet at the best `standard` instance. A design that moves one
  without the other is using slack the model may not really have; say so in the notes.

## Commands

```sh
python3 challenge.py setup binohash

# The challenge's own tests: engine, models, defects the evaluator must refuse (seconds):
cd challenges/binohash && python3 -I -B -m unittest discover -s tests && cd ../..

# Recorded instances must still build byte for byte:
python3 challenges/binohash/tools/verify_submissions.py

# Build and evaluate a submission directory:
python3 challenge.py new binohash standard <id> --architecture rolled-subset
python3 challenge.py run binohash challenges/binohash/submissions/standard/<id> -- --stage screen
python3 challenge.py run binohash challenges/binohash/submissions/standard/<id>
```

`--stage screen` runs 4 lanes with one audit lane, a minute or two for a paper-sized instance.
Without it the run is the full stage the judge uses: 48 lanes, three of them audited, about
six minutes. Add `--core tools/core/target/release/cchk` (after `./setup.sh --core`) to replay
the spends through Bitcoin Core. Local lanes are derived from the instance; the judge's are not.

A rejection prints the stage and the reason; for `soundness` it prints the unlocking script
that was accepted. `score.json` holds the full breakdown.

## Invariants

- Every recorded instance still builds byte for byte. Add a builder or a knob for new
  behaviour; never change what an existing knob does.
- Builders are deterministic and do no input or output. They may import only `bh` and the pure
  standard-library modules the intake filter allows.
- No change to trusted paths. If the evaluator is wrong, that is a report
  ([SECURITY.md](../../SECURITY.md)) or a contract proposal, not a submission.
- `NOTES.md` has a soundness section: why each check of the design still holds, and the
  argument for anything the audit cannot see.

## Submit

One pull request: your `builders/` changes, `submissions/<track>/<id>/submission.json` and
`NOTES.md`, and the registry entry if you propose an architecture. The judge screens it on 4
lanes and validates it on 48 with the Core comparison, under a seed derived from the ledger
key, and a bot records it if it earns a standing
([spec/SUBMISSIONS.md](../../spec/SUBMISSIONS.md), [spec/SCORING.md](../../spec/SCORING.md)).
