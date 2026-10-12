# Binohash optimisation

**Goal.** Make Binohash cheaper to use without making it weaker: lower the product of
**script bytes x opcodes x honest grinding work** while the claimed security level stays at or
above a fixed floor.

Binohash (Linus 2026) gives Bitcoin Script a transaction digest it can read, with no consensus
change. A legacy locking script embeds a pool of signatures; the spender picks a subset, and
`OP_CHECKMULTISIG`'s FindAndDelete removes exactly that subset from what gets signed, so each
subset yields a different sighash. The spender grinds subsets until one lets them produce a
signature short enough to pass an `OP_SIZE` check. The subset that worked is the digest: it is
in the unlocking script as plain numbers, bound to the transaction by proof of work and to the
spender by one-time commitments. That is transaction introspection for protocols such as BitVM
bridges, today.

It is also expensive in three ways that pull against each other. The published two-round
script uses 199 of the 201 operations consensus allows, leaving nothing for the application.
It is about 8 kB of non-standard script plus over a kilobyte to spend. And a spend takes around
2^47 SHA-256 compressions of grinding. Cutting any one is easy if security may drop; this
challenge fixes security and asks for all three.

## Tracks

| Track | Security floor | Spec | Baseline |
| --- | ---: | --- | --- |
| `standard` | 81.5 bits | `bh1-standard` | The paper's 5-byte configuration: two rounds of 120-choose-8 |
| `high` | 88.4 bits | `bh1-high` | The same with 6-byte pinning puzzles |

The floors are the levels of the paper's two published configurations **as this evaluator
counts them**, under the model [BH-SEC-1](spec/SECURITY-MODEL.md).

## What is counted

| | Count | From |
| --- | --- | --- |
| `bytes` | Locking script plus the largest honest unlocking script | The instance's bytes |
| `opcodes` | The interpreter's operation count on an honest spend | Executing it |
| `work_bits` | log2 expected SHA-256 compressions for one spend | The script's layout and puzzles, [BH-WORK-1](spec/WORK-MODEL.md) |
| `security_bits` | Collision resistance in sighash evaluations | The puzzles and pools, [BH-SEC-1](spec/SECURITY-MODEL.md) |

    score = bytes x opcodes x 2^(work_bits - 40)        lower is better

All four are exact functions of the instance. None is taken from the submitter.

## Acceptance

An instance is valid when the trusted evaluator ([design](spec/DESIGN.md)) finds that

- it respects every consensus limit and is at or above its track's floor;
- on every judge-chosen transaction, an honest spend of its test twin, ground by the judge, is
  accepted with real signature verification, and the execution made every check the instance
  declares: each puzzle signature size-checked under a key whose discrete logarithm is
  disclosed, each round's selection drawn from its pool, each selected element opened against
  its commitment;
- a spender who alters the unlocking script, and can satisfy any signature check they control,
  never gets an accepted spend without those checks;
- the script refuses transactions that do not trigger the `SIGHASH_SINGLE` bug, and holds no
  signature a pool does not declare.

Skipping a check does not make an instance cheaper; it makes it invalid.

## Reference numbers

The starting board, as recorded in the ledger: each instance validated at the full stage under a
ledger-key seed, with the Core comparison ([`results.tsv`](results.tsv)).

| Track | Instance | Bytes | Opcodes | Work | Security | Score | |
| --- | --- | ---: | ---: | ---: | ---: | ---: | ---: |
| `standard` | Baseline: paper construction | 9,349 | 199 | 2^46.740 | 81.521 | 198,865,940 | |
| `standard` | Late pools, same parameters | 9,293 | 199 | 2^46.081 | 81.521 | 125,190,801 | 1.59x |
| `standard` | Late pools, 120 and 172 | 10,929 | 199 | 2^45.777 | 81.524 | 119,256,975 | 1.67x |
| `standard` | Late pools, 108 and 120 | 8,921 | 199 | 2^46.244 | 81.643 | 134,554,401 | 1.48x |
| `standard` | First round unclamped, same parameters | 9,269 | 191 | 2^46.121 | 81.521 | 123,217,063 | 1.61x |
| `standard` | First round unclamped, 116x8 and 128x9 | 9,477 | 201 | 2^45.757 | 81.546 | 103,014,088 | 1.93x |
| `standard` | First round unclamped, 104x8 and 88x9 | 7,854 | 201 | 2^46.559 | 81.959 | 148,847,895 | 1.34x |
| `high` | Baseline: paper construction, 6-byte pinning | 9,345 | 199 | 2^52.246 | 88.411 | 9,033,284,929 | |
| `high` | Late pools, same parameters | 9,289 | 199 | 2^52.235 | 88.411 | 8,910,950,604 | 1.01x |
| `high` | First round unclamped, same parameters | 9,265 | 191 | 2^52.235 | 88.411 | 8,530,623,757 | 1.06x |
| `high` | 6-byte round puzzle, 5-byte pinning | 10,634 | 199 | 2^51.423 | 89.231 | 5,810,524,983 | 1.55x |

The rows below each baseline come from the first search run against the evaluator
([what it found](#what-the-first-search-found)).

Against the paper's own figures ([`targets.json`](targets.json), with conventions):

- **Opcodes agree**: 199.
- **The locking script** is 8,101 bytes here and 8,028 in the paper; the evaluator also counts
  the 1,248-byte unlocking script.
- **Security is about two and a half bits lower** than the paper states (81.5 against about
  84). Two bits are the puzzle: a signature `k` bytes short costs `8k` bits of work, not
  `8k + 2`, because the interpreter also accepts the negated nonce and values of `s` that wrap
  around the group order. One spend through each of the four cases was accepted by Bitcoin
  Core's consensus library ([SECURITY-MODEL.md](spec/SECURITY-MODEL.md), section 3). The rest
  is an attacker who abandons a transaction when its first round has no solution.
- **Honest work** is 2^46.74 compressions here and 2^44.6 sighash evaluations in the paper. The
  units differ, the puzzle is two bits easier, and the evaluator counts something the paper's
  figure leaves out: with 2^39.6 subsets against a 2^40 puzzle, both rounds have a solution for
  only 28% of transactions, so the spender tries 3.5 on average.

## What the first search found

Before opening the board, four rounds of search were run against the evaluator: parameter
searches with exact counts, a new layout, and a study of where the index clamp is needed. They
found less in the construction than in the judge.

**In the judge** (all fixed, each with a regression test):

- *The first security model could be gamed.* It charged every transaction for searching every
  round. The search found a "qualifying" design sixteen times cheaper than the baseline: a
  cheap, scarce 32-bit round next to a plentiful 40-bit one. Its real level is 72 bits, because
  seven transactions in eight are abandoned after the cheap round. The model now lets the
  attacker abandon transactions, and adds a second attack (stored digests) that caps what large
  pools can buy.
- *The first audit missed a real attack.* Its dishonest spender could not open commitments it
  had not been given. The attacker of this model is the instance's owner, who can open all of
  them. With that, removing the paper's index clamp is caught at once: an index in the second
  round reaches signatures the first round left on the stack.
- *An unenforced check looked enforced.* Once the spender could open any commitment, a script
  that compared a hash and dropped the result passed. Equalities are now tracked as enforced
  or not.
- *The work model overcharged retries.* A spender who must change the transaction repeats one
  pinning puzzle, not four, which is also what the security model charges the attacker.

**In the construction:**

- *Layout is worth 0.66 bits of work for free.* Moving the commitment tables ahead of both
  pools takes a first-round attempt from 71 compressions to 9 (`late-pools`).
- *Unequal pools are worth another 0.3 bits*, for 1.6 kB (`late-pools-120-172`), or 428 bytes
  less than the baseline at less work (`late-pools-108-120`).
- *On the `high` track the 48 bits belong in a round, not in pinning*: one 48-bit puzzle
  attempted at 9 compressions instead of 6.5 pinning puzzles (`late-round48`).
- *The clamp is needed in every round but the first to run.* Below the first pool there are
  only commitments and the witness, and an index that reaches the witness throws every later
  fetch off by two. That frees eight operations (`late-unclamped`, 191), or pays for a ninth
  selection and a pool 44 elements smaller (`late-unclamped-116-128`, the lowest score, and
  `late-unclamped-104-88`, 7,854 bytes). These four instances rest on a written argument as
  well as the audit and want a second reader.
- *Negative:* pairing each signature with its commitment saves no operation; dropping pinning
  caps the level at 80 bits; the opcode budget, at 11 operations per selected element, is what
  stops pools from shrinking.

The gains inside this contract are a factor of 1.5 to 1.9 on the score, 16% on bytes and 4%
on opcodes; none is an order of magnitude. Larger ones need mechanisms the
evaluator does not yet judge ([roadmap](../../spec/ROADMAP.md)): fewer bytes per pool element
is the lever everything else waits on.

## The board

- [`results.tsv`](results.tsv): every validated instance ([format](../../spec/LEDGER.md)).
- [`architectures.json`](architectures.json): the architectures instances are grouped by.
- [`submissions/`](submissions/): one directory per recorded instance, with the build knobs that
  reproduce it and its notes.
- [`starting-board.json`](starting-board.json): the instances the board starts from.
- [`targets.json`](targets.json): the paper's published points, with conventions.
- [`data/site/binohash/leaderboard.json`](../../data/site/binohash/leaderboard.json): elites per
  architecture, the three-way front and the improvement history, derived from the ledger.

## Take part

Read [TASK.md](TASK.md). In short:

```sh
python3 challenge.py setup binohash
python3 challenge.py new binohash standard my-instance --architecture rolled-subset
python3 challenge.py run binohash challenges/binohash/submissions/standard/my-instance -- --stage screen
```

You may change only [`builders/`](builders/). The evaluator, the specs and the tests are the
contract.

## Layout

| Path | Trust | What it is |
| --- | --- | --- |
| [`builders/`](builders/) | **editable** | Instance builders. [`README.md`](builders/README.md) is the knob reference. |
| [`evaluator/`](evaluator/) | trusted | Curve and script engine, signature hash, models, judge. Python standard library only. |
| [`specs/`](specs/) | trusted | The pinned spec of each track: model, floor, validation sizes. |
| [`tests/`](tests/) | trusted | Engine and model tests, Core-judged vectors, and defects the evaluator must refuse. |
| [`tools/`](tools/) | trusted | The Core comparison and the byte-identity check of recorded instances. |
| [`spec/`](spec/) | | Design contract, security and work models, conventions, references. |
| [`submissions/`](submissions/) | | One directory per submission. |

## Scope

A row says an instance passed the evaluator's checks and what it costs under the evaluator's
counting. The security level is a claim under the stated model and its assumptions, with an
audit as evidence; it is not a proof, and the model assumes a downstream verifier that enforces
the hash type of round signatures (Binohash 7.1). Nothing here grinds a production puzzle,
funds a transaction or says anything about relay policy; Binohash spends are non-standard.
Judged instances are specimens with public secrets and must never hold funds. Binohash is not
quantum-safe. References are in [spec/REFERENCES.md](spec/REFERENCES.md).
