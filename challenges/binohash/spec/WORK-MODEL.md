# BH-WORK-1: honest grinding work

`work_bits` is the base-2 logarithm of the expected number of SHA-256 compressions an honest
spender performs for one spend, using the reference grinder defined here. It is computed from
the production script, exactly, by [`evaluator/bh/model.py`](../evaluator/bh/model.py) and
`Judge.count` in [`evaluator/bh/judge.py`](../evaluator/bh/judge.py). Nothing is timed.

Compressions were chosen over sighash evaluations because one evaluation of a 9 kB preimage is
not one unit of work, and how much of it must be redone per attempt is a property of the
script's layout: something a design can improve and the board should see. Grinding a size
puzzle needs no elliptic-curve arithmetic (Binohash 8.1.1), so compressions are the whole cost.

## 1. An attempt

An attempt computes one legacy sighash, a double SHA-256 of a preimage, and tests it against a
puzzle (both nonce signs, [SECURITY-MODEL.md](SECURITY-MODEL.md) section 3). A grinder keeps
the SHA-256 state of the longest prefix that does not change between attempts. If the preimage
is `L` bytes and its first `a` bytes are fixed, an attempt costs

    kappa = ceil((L + 9) / 64) - floor(a / 64) + 1

compressions: the blocks from the one holding the first varying byte to the end of the padded
message, plus one for the outer hash.

## 2. The reference transaction

Three inputs, the Binohash input second, one output `OP_RETURN <32 bytes>`:

    version | 3 | input 0 | outpoint, scriptCode, sequence | input 2 | 1 | output | locktime | hash type

The Binohash input's index (1) is not below the number of outputs (1), which triggers the
`SIGHASH_SINGLE` bug the construction depends on. Input 2 and the output follow the scriptCode,
so the fields the pinning grind varies are all in the tail of the preimage.

## 3. Pinning

Four puzzles, one sighash mode each, ground in the order of Binohash 3.1.1. Each varies a field
that the modes before it do not sign, so earlier solutions survive:

| Puzzle | Hash type | Field varied | Typical kappa |
| --- | --- | --- | ---: |
| first | `NONE\|ANYONECANPAY` (0x82) | `nLockTime` | 2 |
| second | `NONE` (0x02) | input 2's outpoint | 3 |
| third | `ALL\|ANYONECANPAY` (0x81) | the output's payload | 3 |
| fourth | `ALL` (0x01) | input 2's sequence | 3 |

`a` is the offset of the varied field in that mode's preimage and `L` its length, both taken
from the actual serialisation. A puzzle of `W` bits takes `2^W` attempts on average, at a cost
of `2^(W_i) * kappa_i` compressions.

A script cannot make pinning attempts cheaper by moving things: the tail is the transaction's.
It can only choose how hard the puzzles are.

## 4. A round

The round's preimage is the reference transaction under `SIGHASH_ALL` with the scriptCode from
the last `OP_CODESEPARATOR` before the round's multisig, the `t` selected pushes removed. The
reference grinder enumerates selections so that the element latest in the script changes
fastest and the state before it is kept. The first varying byte is therefore just before the
*innermost* selected element, taken at its expected position: with the pool's pushes in script
order at offsets `o_1 < ... < o_n`,

    m = ceil(t (n + 1) / (t + 1))                    the expected largest of t ranks out of n
    a = (bytes before the scriptCode) + o_m - (t - 1) * (push length)

and `L` is the preimage length with `t` pushes removed. Everything after the pool in the
scriptCode, and the transaction's tail, is rehashed on every attempt. **This is where layout
matters**: in the published construction a first-round attempt rehashes the whole second round
(71 compressions) while a second-round attempt rehashes only what follows its own pool (9).

A round with `S` selections and a puzzle of `W` bits has, for a given pinned transaction,
`lambda = S * 2^-W` solutions on average. It has at least one with probability
`p = 1 - exp(-lambda)`, and searching it until the first solution or to exhaustion takes
`p * 2^W` attempts on average:

    attempts_r = p_r * 2^(W_r)        cost_r = attempts_r * kappa_r

## 5. A spend

Rounds are independent: one round's selection is not in another's sighash, because
`OP_CHECKMULTISIG` removes only its own signatures. The spender searches them in whichever
order is cheapest and stops at the first round with no solution.

Then the transaction must change, but only one pinning puzzle has to be solved again. Varying
input 2's sequence changes the `SIGHASH_ALL` sighash, which the rounds sign, and no other
pinning signature's: `NONE` zeroes other inputs' sequences and the `ANYONECANPAY` modes do not
sign other inputs at all. The spender gives `SIGHASH_ALL` to the cheapest pinning puzzle. This
is the same step the security model charges the attacker for (assumption A4), so both sides
change a pinned transaction at the same price.

    try  = pin_ALL + cost_{r1} + p_{r1} cost_{r2} + p_{r1} p_{r2} cost_{r3} + ...   (cheapest order)
    work = (the other three pinning puzzles, once)  +  try / prod_r p_r

`work_bits = log2(work)`. `score.json` also reports the pinning share, the probability that a
transaction has a full digest, the expected number of tries and the order.

For the published configuration: `lambda = 0.76`, `p = 0.53` per round and 0.28 for both, so
3.5 tries per spend; three pinning puzzles once at `2^43.0`; the cheap round first;
`work = 2^46.74`.

The security model caps this configuration's level at 80.011 bits whatever its rounds are
worth above that ([SECURITY-MODEL.md](SECURITY-MODEL.md), section 4), so on the `standard`
track the number of tries per spend is a cost a design can lower with more selections, paid
for in bytes, without lowering its level, as long as its rounds stay worth at least the floor.

## 6. What the count leaves out

- **Setup.** Building an instance is free in this epoch: nine-byte signatures and their
  recovered keys cost a few hundred curve operations. A mechanism with real setup work (the
  polyglot digest's 2^46 hashes per pool element) must have it counted before it can be judged.
- **Memory and hardware.** A compression is a compression. The paper's measured 320 MH/s on ten
  GPUs is recorded in [REFERENCES.md](REFERENCES.md) for scale, not used.
- **Smarter grinders.** A grinder that does better than the reference on some layout is a
  finding about the work model. Report it in Discussions with the prefix `[Contract]`; the
  model changes by epoch, not by submission.
- **Hash-type bytes.** The honest spender uses the canonical hash types above (assumption A3
  for rounds). Varying the byte for extra attempts is outside the model on both sides. What it
  is worth to an attacker is an open question ([SECURITY-MODEL.md](SECURITY-MODEL.md),
  section 6).
