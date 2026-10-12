# BH-SEC-1: the security level the challenge holds fixed

Every track fixes a floor on one number, `security_bits`. This document defines that number.
It is the accounting of the Binohash paper (Linus 2026, sections 4.6 and 5.3) with three
changes: puzzle work is counted exactly from the script; the attacker abandons a transaction as
soon as one round has no solution; and rounds whose selection count does not match their
puzzle are priced by the cheaper of two attacks. The implementation is
[`evaluator/bh/model.py`](../evaluator/bh/model.py).

The number is a **claimed level under stated assumptions**. It is not a proof, and it is not a
statement about any deployment. Section 6 lists the assumptions.

## 1. The game

A Binohash instance is a locking script. A spend carries a **digest**: for each round, the set
of `t` pool elements its unlocking script selects. The attacker is a spender who knows every
secret of the instance. They win by producing two different transactions that spend the script
with the same digest, where the second is one a downstream verifier accepts (section 6,
assumption A3). `security_bits` is the base-2 logarithm of the number of sighash evaluations
the best known such attack needs.

## 2. What an instance is made of

| Part | In the script | Counted as |
| --- | --- | --- |
| Pinning puzzle | `OP_SIZE <size> OP_EQUALVERIFY <key> OP_CHECKSIG(VERIFY)` on a spender signature | `W` bits each (section 3) |
| Round | A pool of `n` signatures, `t` of which are selected and verified with a puzzle signature by one `OP_CHECKMULTISIG` | `S = C(n, t)` selections and a puzzle of `W_r` bits |
| Commitments | One hash per pool element, opened for each selected element | Required; not part of the number (section 5) |

## 3. Puzzle work, counted exactly

A size puzzle demands a signature of exactly `size` bytes under a key `P = d*G` whose `d` is
public. A DER signature is `7 + len(r) + len(s)` bytes with its hash-type byte. The shortest
`r` with a known nonce is `r_min`, the 21-byte x-coordinate of `(1/2)G`; a shorter one is
assumed out of reach (assumption A1). So `len(s) = size - 28`, and with nonce `k = ±1/2`:

    s = ±2 (z + d * r_min)  mod n

for the sighash `z`. The puzzle accepts `z` when either sign gives an `s` whose DER integer is
exactly `size - 28` bytes: `s` in `[2^(8m-9), 2^(8m-1))` for `m = size - 28`.

The evaluator counts every accepted `z`:

- **Both nonce signs.** `-R` has the same x-coordinate as `R`, so `(r_min, n - s)` is as valid
  as `(r_min, s)`.
- **Reduction mod n.** `z -> 2(z + c) mod n` is a bijection of `[0, n)`. Small values of `s`
  come from `z` near `-c` and from `z` near `-c + n/2`.

That is four intervals of `z`, each `2^(8m-2)` long less a 1/256 sliver, so the acceptance
probability is `2^-(8k) * (1 - 2^-8)` for a signature `k` bytes below 60:

    W = 8k + 0.0056 bits

The paper counts `8k + 2`: it takes `s = 2(z + 1)` over the integers, which needs `z` to have
`8k + 2` leading zero bits and is one of the four intervals. The other three are equally valid
signatures. One spend through each of the four has been replayed through Bitcoin Core's
consensus library and accepted (`tests/data/core-vectors.txt`, the last four lines; the test
`test_all_four_ways_to_be_short_are_real_signatures` constructs them). The evaluator's count
applies to the baseline and to every submission alike, so levels are comparable across the
board; they are about two bits per puzzle below the paper's figures
([`targets.json`](../targets.json)).

`d` must be disclosed in the instance and the evaluator checks `P = d*G`. A puzzle whose key
has no disclosed discrete logarithm is not a puzzle the evaluator can count.

## 4. The level: the cheaper of two attacks

Let `C_pin` be the cost of the cheapest pinning puzzle, `2^min(W_i)`, when pinning is credited
(below), else 0. Let round `r` have `S_r` selections and a puzzle of `W_r` bits. For one pinned
transaction, a given selection solves its puzzle with probability `q_r = 2^-W_r`; the round has
`lambda_r = S_r q_r` solutions on average and at least one with probability
`p_r = 1 - exp(-lambda_r)`.

Both attackers work through a transaction's rounds one at a time, in the order that suits them,
and **abandon the transaction at the first round with no solution**. Trying every selection of
every round therefore costs, per transaction,

    full = min over orders ( C_pin + S_{r1} + p_{r1} S_{r2} + p_{r1} p_{r2} S_{r3} + ... )

**Attack 1: exhaustive birthday.** Pin `T` transactions and find every solution of each. Two
transactions share a solved selection of round `r` in an expected `S_r q_r^2` ways, and a whole
digest in the product over rounds. Over `T^2 / 2` pairs that reaches one at
`T = prod_r 2^(W_r) / sqrt(S_r)`:

    birthday = full * prod_r 2^(W_r) / sqrt(S_r)

Searching only part of a round's selections never helps: it saves a factor in cost and loses
its square in pairs.

**Attack 2: stored digests.** Collect `N` digests, each from some transaction, then pin fresh
transactions and test the stored digests on them: one evaluation per test, success
`prod_r q_r` per test. That needs `2^(sum W_r)` tests in all, on `2^(sum W_r) / N` fresh
transactions:

    stored = 2^(sum W_r) * C_pin / N  +  2^(sum W_r)  +  N * per_digest

with `N >= 1` chosen to minimise it, and `per_digest` the cheaper of finding digests by full
search (`full / prod_r lambda_r`) or by stopping at each round's first solution.

    security_bits = log2( min(birthday, stored) )

**Relation to the paper.** For one round with `S = 2^W`, `birthday` is section 4.6 exactly. For
two rounds it is section 5.3 except that the paper charges both rounds to every transaction,
while an attacker skips the second round when the first has no solution; with `S = 2^W` that
is 0.19 bits. The paper writes the digest size as `min(E, W)`; this model replaces that with
the two counts above. They differ from it in both directions when `S_r` and `2^W_r` differ:

- Fewer selections than the puzzle is hard: a pinned transaction often has no digest. The
  digest space is small, but so is the number of digests; `birthday` counts both.
- More selections than the puzzle needs: `birthday` alone would say the level keeps rising,
  because every transaction costs more to search exhaustively. `stored` caps it: nobody needs
  to search a large pool exhaustively to test a known digest. Without pinning the level cannot
  exceed `sum W_r`.

Both refinements were found by this repository's own parameter search, which is the reason a
search is run against a model before a board opens: the first version credited a scarce cheap
round with security it does not give, and a design 16 times cheaper than the baseline
"qualified". `tests/test_model.py` keeps that design as a regression test.

**Constants are dropped**, as the paper drops them: the `sqrt(2)` of the birthday bound and the
factor of at most two for testing a stored digest round by round.

**When pinning is credited.** `C_pin` is non-zero only if all of these hold, each checked by
the evaluator:

1. There are exactly four pinning puzzles and their accepted sighash sets are pairwise
   disjoint. One signature mode then serves at most one puzzle, so the four modes that are not
   `SIGHASH_SINGLE` are all used, `SIGHASH_ALL` among them.
2. No puzzle accepts the `SIGHASH_SINGLE` bug digest.
3. The script refuses any spend whose transaction does not trigger the `SIGHASH_SINGLE` bug.
   `SIGHASH_SINGLE` signatures then all sign one constant and are useless for pinning.

An instance with no pinning puzzles is valid and has `C_pin = 0`.

**What the model may still miss.** It considers two attack families. A hybrid that beats both
on some shape of instance would be a finding about the model: report it
([SECURITY.md](../../../SECURITY.md)).

## 5. What is required but not in the number

- **Every selection is counted.** `S_r = C(n, t)` assumes the pool has exactly the declared
  `n` signatures, all distinct, each in the scriptCode the round's multisig signs, pools of
  different rounds disjoint, and no other signature-shaped push in the script. The evaluator
  checks each of these. More real selections than counted would overstate the level.
- **A selection is authorised.** Each selected element is opened by a preimage of its own
  commitment: at least 20 bytes of hash output, at least 16 bytes of preimage, no commitment
  shared between elements or rounds. This is the one-time signature that makes the digest
  usable downstream (Binohash section 6.4). Its strength is a hash preimage and is not folded
  into `security_bits`.
- **Only declared structure passes.** The soundness audit ([DESIGN.md](DESIGN.md), section 5)
  requires every accepted spend the judge can construct to have used a declared selection, a
  size-checked puzzle signature under the declared key, and an opening for every selected
  element. The audit's spender can open any commitment, because the attacker of section 1 is
  the instance's owner.

## 6. Assumptions

| | Assumption | Source |
| --- | --- | --- |
| A1 | No signature nonce with an x-coordinate shorter than `r_min` is known, and none with a comparably short one besides `±(1/2)G`. | Binohash 2.1.3 (about 2^96 work to find one). A quantum adversary breaks this outright; see the paper and QSB. |
| A2 | Working 2^(2W) to satisfy two puzzles with one signature mode is infeasible. | Binohash 3.1 |
| A3 | The downstream verifier inspects the spend and rejects any round signature whose hash type is not `SIGHASH_ALL` (0x01). Without it, a round signature under `ANYONECANPAY\|NONE` commits to almost nothing and the level collapses to one round's work. | Binohash 7.1 |
| A4 | Changing a pinned transaction costs at least one pinning puzzle. | Binohash 5.3 |
| A5 | SHA-256 behaves as a random function of the sighash preimage. | |

Outside the model, by choice:

- **Hash-type byte freedom** (Binohash 7.2). Any of 256 hash-type bytes is consensus-valid and
  each gives a different sighash, which gives the on-chain half of a collision up to 8 bits per
  spender signature. The paper prices this at under one bit for its configuration. It is not
  in `security_bits`; a design that changes how much it matters should say so in its notes.
- **Second-preimage resistance against a third party.** The paper's threat model is collision
  resistance against the spender; so is this one.
- **Quantum adversaries.** A1 fails. That is the subject of QSB, not of this challenge.

## 7. Changing the model

The model is part of the contract. A puzzle kind the evaluator does not know, a different
pinning argument, a relaxed rule of section 5 or a different formula is a new contract epoch
([VALIDATION.md](../../../spec/VALIDATION.md)), proposed in Discussions with the prefix
`[Contract]`. A report that the model overstates the level of an instance it accepts is a
soundness report: use [SECURITY.md](../../../SECURITY.md).
