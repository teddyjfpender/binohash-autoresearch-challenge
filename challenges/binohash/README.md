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
| `standard` | 80.0 bits | `bh1-standard` | The paper's 5-byte configuration: two rounds of 120-choose-8 |
| `high` | 88.4 bits | `bh1-high` | The same with 6-byte pinning puzzles |

The floors are the levels of the paper's two published configurations **as this evaluator
counts them**, under the model [BH-SEC-2](spec/SECURITY-MODEL.md), rounded down to a tenth of a
bit: 80.011 and 88.411 bits.

The model caps every level at the work of satisfying the two cheapest pinning puzzles with one
signature mode (the *pinning cap*). With 5-byte pinning puzzles the cap is 80.011 bits and with
6-byte puzzles it is 96.011. The rounds of the `standard` baseline are worth 81.521 bits, so
its level is the cap. On the `high` track 6-byte pinning is required in practice, because
5-byte pinning cannot be credited above 80.011.

## What is counted

| | Count | From |
| --- | --- | --- |
| `bytes` | Locking script plus the largest honest unlocking script | The instance's bytes |
| `opcodes` | The interpreter's operation count on an honest spend | Executing it |
| `work_bits` | log2 expected SHA-256 compressions for one spend | The script's layout and puzzles, [BH-WORK-1](spec/WORK-MODEL.md) |
| `security_bits` | Collision resistance in sighash evaluations | The puzzles and pools, [BH-SEC-2](spec/SECURITY-MODEL.md) |

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
| `standard` | Baseline: paper construction | 9,349 | 199 | 2^46.740 | 80.011 | 198,865,940 | |
| `standard` | Late pools, same parameters | 9,293 | 199 | 2^46.081 | 80.011 | 125,190,801 | 1.59x |
| `standard` | First round unclamped, same parameters | 9,269 | 191 | 2^46.121 | 80.011 | 123,217,063 | 1.61x |
| `high` | Baseline: paper construction, 6-byte pinning | 9,345 | 199 | 2^52.246 | 88.411 | 9,033,284,929 | |
| `high` | Late pools, same parameters | 9,289 | 199 | 2^52.235 | 88.411 | 8,910,950,604 | 1.01x |
| `high` | First round unclamped, same parameters | 9,265 | 191 | 2^52.235 | 88.411 | 8,530,623,757 | 1.06x |

The last column is the baseline's score divided by the row's. All six instances use the paper's
parameters; the rows below each baseline differ from it in layout only
([how the board came to be these six](#what-the-first-search-found)).

Against the paper's own figures ([`targets.json`](targets.json), with conventions):

- **Opcodes agree**: 199.
- **The locking script** is 8,101 bytes here and 8,028 in the paper; the evaluator also counts
  the 1,248-byte unlocking script.
- **Security is about four bits lower** than the paper states (80.0 against about 84). Two
  bits are the puzzle: a signature `k` bytes short costs `8k` bits of work, not `8k + 2`,
  because the interpreter also accepts the negated nonce and values of `s` that wrap around the
  group order. One spend through each of the four cases was accepted by Bitcoin Core's
  consensus library ([SECURITY-MODEL.md](spec/SECURITY-MODEL.md), section 3). About half a bit
  is in how the rounds are counted (section 4 of the model), which leaves them worth 81.521
  bits. The last bit and a half is the pinning cap of 80.011 bits.
- **Honest work** is 2^46.74 compressions here and 2^44.6 sighash evaluations in the paper. The
  units differ, the puzzle is two bits easier, and the evaluator counts something the paper's
  figure leaves out: with 2^39.6 subsets against a 2^40 puzzle, both rounds have a solution for
  only 28% of transactions, so the spender tries 3.5 on average.

## What the first search found

The board has been searched twice. A parameter search was run before any row was recorded, and
an agent search was then run against the first recorded board. Both found more wrong with the
judge than they found in the construction. The model that came out of the second is BH-SEC-2;
the one it replaced is called BH-SEC-1 below.

### The parameter search

Four rounds of search were run against the evaluator: parameter searches with exact counts, a
new layout, and a study of where the index clamp is needed.

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
- *The clamp is needed in every round but the first to run.* Below the first pool there are
  only commitments and the witness, and an index that reaches the witness throws every later
  fetch off by two. That frees eight operations (`late-unclamped`, 191). This rests on a
  written argument as well as the audit and wants a second reader.
- *Negative:* pairing each signature with its commitment saves no operation, and the opcode
  budget, at 11 operations per selected element, is what stops pools from shrinking.

The search also tuned parameters against BH-SEC-1 and its `standard` floor of 81.5 bits:
unequal pools, a ninth selection in the unclamped round, and on the `high` track a 48-bit round
puzzle with 5-byte pinning. Eleven instances were recorded as the first board, five of them of
this kind.

### The agent search

An agent search against that board found three more errors in the judge. Each is fixed in
BH-SEC-2 and kept as a regression test
([SECURITY-MODEL.md](spec/SECURITY-MODEL.md), section 8).

- *Searching part of a round helps the attacker.* BH-SEC-1 said it never does. An attacker who
  searches one common subset of each round's selections in every transaction loses only the
  factor by which the colliding pairs shrink, not its square. The model now minimises the
  birthday attack over the sizes of those subsets. Two recorded instances (pools 120-choose-8
  with 172-choose-8, and 116-choose-8 with 128-choose-9) had been credited 81.52 and 81.55
  bits and are worth 81.04 and 81.03.
- *Pinning was credited at any puzzle size.* Four pinning puzzles force four sighash modes
  only while one signature mode cannot serve two of them, and making it do so costs
  `2^(Wa + Wb)` for the two cheapest puzzles. `security_bits` is now capped there: 80.011 bits
  with 5-byte pinning puzzles and 96.011 with 6-byte ones.
- *The audit's spender was too weak.* A copy of the `late` builder with every index clamp
  removed passed the audit. It lets the last index of a round take a signature the previous
  round did not select: the commitment fetch lands on an unlocking item and the preimage
  fetch on a script constant, and the spender sets the one to the hash of the other. The
  audit's spender can now set an unlocking item to whatever the other side of an equality
  evaluates to, alters three or four unlocking items of different kinds at once, and plants
  signatures short enough to fit under the largest pools. An instance is also refused if a
  declared preimage is public or shared ([DESIGN.md](spec/DESIGN.md), sections 4 and 5). That
  script is refused now.

### The board now

The contract moved to a new epoch, `binohash-v2`, and the board was recorded again under
BH-SEC-2 with six instances.

- The paper's standard configuration counts as 80.011 bits, the cap, where its rounds alone
  are worth 81.521. The `standard` floor moved from 81.5 to 80.0 with it. The `high` floor
  stays at 88.4: the 6-byte-pinning configuration is below its cap and still counts as 88.411.
- The five instances tuned against the old model were removed. Four on the `standard` track
  (`late-pools-120-172`, `late-pools-108-120`, `late-unclamped-116-128` and
  `late-unclamped-104-88`) were shaped by a floor and a model that no longer apply. The fifth,
  `high/late-round48`, has 5-byte pinning and now counts as 80.011 bits, below the `high`
  floor.
- The six that remain use the paper's parameters. Their bytes, opcodes and work are as first
  recorded; only the security figure of the three `standard` rows changed.

What remains of the gains is a factor of 1.6 on the `standard` score and 1.06 on `high`, with
1% fewer bytes and 4% fewer opcodes. The parameter space is open again under the new model. On
the `standard` track every design with 5-byte pinning whose rounds are worth at least 80.0
bits counts as 80.011, so round parameters are no longer held to a knife edge and trade bytes
against retries. On the `high` track pinning costs 2^48 per transaction and dominates, so more
selections lower the level and the floor limits the product of the two rounds' selection
counts. Larger gains need mechanisms the evaluator does not yet judge
([roadmap](../../spec/ROADMAP.md)): fewer bytes per pool element is the lever everything else
waits on.

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
