# Design: instances, the evaluator and what it checks

This is the technical contract of the Binohash challenge. The security level is defined in
[SECURITY-MODEL.md](SECURITY-MODEL.md), the work count in [WORK-MODEL.md](WORK-MODEL.md), and
the counting conventions in [CONVENTIONS.md](CONVENTIONS.md).

## 1. Roles

| Part | Path | Trust |
| --- | --- | --- |
| Builders | `builders/` | Untrusted submission code. Turns build knobs into an instance file. |
| Instance | `instance.json` | Untrusted data. Never committed; named by its SHA-256. |
| Evaluator | `evaluator/bh/` | Trusted. Checks the instance, runs lanes, counts. Standard library only. |
| Specs | `specs/` | Trusted. One file per track: the model, the floor and the validation sizes. |
| Tests | `tests/` | Trusted. Engine tests, model tests and defects the evaluator must refuse. |
| Core comparison | `tools/core/` | Trusted. Replays spends through Bitcoin Core's consensus library. |

The builders decide what the script is. The evaluator decides whether it is a Binohash
instance at the claimed level and what it costs. Nothing a builder says is believed: a claim
is either re-derived from the script bytes or exercised by executing the script.

## 2. The instance file

`bh-instance-v1`, JSON, at most 2 MiB. Unknown or missing keys are refused.

```json
{
 "schema": "bh-instance-v1",
 "locking": "<hex>",
 "locking_test": "<hex>",
 "puzzles": [
  {"id": "pin1", "role": "pin", "key_at": 49, "size_at": 46, "dlog": "<hex>", "dlog_test": "<hex>"},
  {"id": "round0", "role": "round", "key_at": 4115, "size_at": 4084, "dlog": "<hex>", "dlog_test": "<hex>"}
 ],
 "rounds": [
  {"puzzle": "round0", "t": 8, "slots": "any",
   "pool": [3841, 3831], "commit": [2700, 2679], "keys": ["<hex>"], "preimages": ["<hex>"]}
 ],
 "witness": [
  {"puzzle": "round0"}, {"key": [0, 0]}, {"pre": [0, 7]},
  {"index": [0, 7], "enc": "rank", "add": 8}, {"puzzle": "pin1"}
 ]
}
```

| Field | Meaning |
| --- | --- |
| `locking` | The production locking script. Bytes, opcodes and work are counted from it. |
| `locking_test` | The test twin: the same script with easier puzzles, which the judge can grind. |
| `puzzles[].key_at`, `size_at` | Offsets in the locking script of the pushes holding the puzzle's public key and its signature size. |
| `puzzles[].dlog`, `dlog_test` | The discrete logarithm of the key in the production and test scripts, 32 bytes. |
| `puzzles[].role` | `pin` or `round`. There are four pinning puzzles or none; each round names one round puzzle. |
| `rounds[].pool`, `commit` | Offsets of the pushes holding element `j`'s signature and its commitment. |
| `rounds[].keys`, `preimages` | Element `j`'s public key (if the witness supplies keys) and its commitment's preimage. |
| `rounds[].slots` | The order in which an honest spender lists a selection: `any`, `ascending` or `descending` by element number. |
| `witness` | The unlocking script, bottom of the stack first, as a list of items (below). |

Witness items:

| Item | Pushes |
| --- | --- |
| `{"puzzle": id}` | The signature that solves puzzle `id`. |
| `{"index": [r, i], "enc": "rank" \| "abs", "mul": m, "add": k}` | A number naming the element in slot `i` of round `r`: `m * e + k`, where `e` is the element's number (`abs`) or its position among the elements not chosen in earlier slots (`rank`). `m` defaults to 1 and `k` to 0. |
| `{"key": [r, i]}` | The public key of the element in slot `i`. |
| `{"pre": [r, i]}` | The preimage of the element in slot `i`. |
| `{"push": hex}` | Fixed bytes. |

**Instances are specimens.** The preimages of every commitment are in the file, so that the
judge can open any selection. A judged instance must never hold funds. A deployment generates
its own secrets; its script differs from the specimen in the commitment bytes and nothing else.

**The twin rule.** `locking_test` must have the length of `locking` and may differ from it only
inside the data of the size and key pushes of the declared puzzles. The evaluator checks each
side's key against its disclosed logarithm and computes each side's work. Because every other
byte is the same, what the test script does at 8 bits per puzzle is what the production script
does at 40. The test difficulty must lie between the spec's `testBitsMin` and `testBitsMax`.

**Straight-line scripts.** `OP_IF`, `OP_NOTIF`, `OP_ELSE`, `OP_ENDIF`, `OP_RETURN`, the reserved
opcodes and the locktime opcodes are refused. Every operation then executes on every spend, so
one execution's trace names every check the script makes, and the audit of section 5 covers the
whole script. Conditional execution is a contract change (section 8).

## 3. Running it

`benchmark.sh` runs two processes and nothing passes between them but the instance file.

1. **Build, untrusted.** `evaluator/run_builder.py` imports `builders`, calls
   `build(knobs)` with the manifest's `BINO_*` knobs and writes `instance.json`. It runs under
   bubblewrap (Linux) or `sandbox-exec` (macOS): read-only filesystem, no network, an
   unprivileged user, one writable scratch directory. Builders do no input or output of their
   own, and the intake filter refuses source that imports anything but a short list of pure
   modules ([VALIDATION.md](../../../spec/VALIDATION.md)).
2. **Evaluate, trusted.** `evaluate.sh` runs `bh.evaluate` in a fresh interpreter that imports
   no builder code. It reads the instance as hostile data and writes `score.json`.

In the judge workflow the two run in different jobs; only the second holds the ledger key.

## 4. Static checks

Before any execution. Each refusal names its stage.

| Stage | Refuses |
| --- | --- |
| `format` | Anything that is not exactly the format of section 2. |
| `limits` | A script over 10,000 bytes, a push over 520 bytes, an opcode that always fails. |
| `straight-line` | The opcodes listed in section 2. |
| `twin` | A test script that differs outside the puzzles' size and key pushes, or a test difficulty the judge cannot grind. |
| `puzzle-key` | A puzzle key that is not `d*G` for its disclosed `d`. |
| `puzzle-size` | A size no signature with nonce `r_min` can have, or a puzzle that accepts the `SIGHASH_SINGLE` bug digest. |
| `pin-cover` | A number of pinning puzzles other than four or zero, or two whose accepted sighashes overlap. |
| `nonce-space` | A pool element that is not a strictly encoded signature, repeats within or across pools, or occurs more than once in the script. |
| `binding` | A commitment under 20 bytes or shared between elements; a preimage under 16 bytes. |
| `structure` | A declared offset that is not a push; shared pushes between puzzles or elements. |

## 5. Lanes

A lane is one transaction chosen by the judge from the lane seed. Every lane uses the
reference shape: three inputs with the Binohash input second, one `OP_RETURN` output, so the
input's index is not below the number of outputs and the `SIGHASH_SINGLE` bug applies.

On **every lane** the judge:

1. **Probes the selection space.** For sampled selections (and, on the first lane, the two ends
   of every pool) it executes the declared witness and requires the round's multisig to receive
   exactly that selection, with every selected element inside the scriptCode being signed, and
   distinct selections to give distinct sighashes.
2. **Grinds an honest spend of the test twin itself.** The four pinning puzzles in the order of
   Binohash 3.1.1 (one sighash mode each, each varying a field the earlier modes do not sign),
   then each round by sampling selections until one solves its puzzle. If a round has no
   solution it pins another transaction, as a spender would.
3. **Executes that spend with real signature verification** and requires acceptance. This is
   completeness: an honest spender can spend.
4. **Reads the structure from the trace.** The interpreter tags every stack item with where it
   came from, and marks an equality as enforced when the script fails unless it holds. From
   the recorded checks, counting only enforced equalities, the judge requires: each pinning puzzle verified a
   spender signature under its declared key, and that signature's size was compared with the
   declared constant; each round's puzzle key took part in exactly one `OP_CHECKMULTISIG` of
   `t+1` signatures against `t+1` keys; the signature opposite the puzzle key is a size-checked
   spender signature; the other `t` are distinct pushes of the round's pool; and each of them
   was opened by hashing a witness item and comparing it with that element's commitment.
5. **Checks the production script refuses that spend.** Its puzzles are harder.
6. **Checks the `SIGHASH_SINGLE` bug is forced.** With one more output the same spend must fail,
   even for a spender who can satisfy any signature check they control.
7. **Looks for undeclared signatures.** A signature-shaped push that no pool declares and no
   check against a constant key consumes is refused: the spender, who knows every preimage,
   could select it.

On **audit lanes** the judge then plays a dishonest spender. The interpreter runs in *oracle
mode*: a signature check passes whenever the spender controls the signature or the key (they
can grind the one and recover the other), an equality check passes when both sides come from
the unlocking script (they choose both), and a hash of an unlocking item equals any declared
commitment it is compared with (the spender made the commitments and can open every one).
Checks between constants of the script stay real. Starting from the honest spend, the judge alters the unlocking script:

- every index set to every value from -2 to past the deepest stack item, one at a time;
- the same with a pad of well-formed signatures planted beneath the witness, deeper than any
  pool, so an index that escapes its pool finds attacker material for both the signature and
  its commitment;
- several indexes changed at once;
- items exchanged, dropped and repeated;
- preimages replaced by random bytes, by another element's preimage, by nothing;
- keys replaced; puzzle signatures replaced by ones of another hash type, a byte shorter, a
  byte longer, by a pool signature, by nothing.

Every altered spend that is **accepted** must still show the full structure of step 4. One that
does not is a counterexample: the instance is refused at stage `soundness` and the unlocking
script is printed. Separately, each puzzle signature is replaced by a well-formed one that
signs nothing and executed with real verification; acceptance refuses the instance.

Finally, **every pool element**, not only sampled ones: its preimage must open its commitment
under the hash the trace showed, and its key must verify its signature.

With `--core`, the honest and altered spends of the first lanes are replayed through Bitcoin
Core's consensus library with the verdicts the reference engine reached. A disagreement stops
the run as a fault of the evaluator.

## 6. Counting

All counts are exact functions of the instance; lanes validate, they do not measure. The same
instance gives the same counts under every seed (a test requires it).

| Count | Definition |
| --- | --- |
| `bytes` | Length of `locking`, plus the largest unlocking script the witness can produce at production signature sizes. |
| `opcodes` | The interpreter's operation count for the locking script on an honest spend: opcodes above `OP_16`, plus the key count of each `OP_CHECKMULTISIG`. It is the same on every lane, or the instance is refused. |
| `work_bits` | [WORK-MODEL.md](WORK-MODEL.md). |
| `security_bits` | [SECURITY-MODEL.md](SECURITY-MODEL.md). Must reach the spec's `floorBits`. |
| `stack_peak` | Peak main-plus-alt stack items on an honest spend. Reported; consensus allows 1,000. |

## 7. What passing does and does not show

Shown, for the judged instance:

- It respects the consensus limits, and an honest spender can spend the test twin for every
  sampled transaction, by the reference engine's reading of consensus and, where `--core` ran,
  by Bitcoin Core's.
- Its puzzles cost what the evaluator says, given assumption A1.
- Every spend the audit constructed and the script accepted had the declared structure.

Not shown:

- **That no accepted spend lacks the structure.** The audit is a search, not a proof. It covers
  single alterations exhaustively over the index range and combinations by sampling. A freedom
  that needs a particular combination of several altered items can be missed. Final candidates
  need a written argument ([VALIDATION.md](../../../spec/VALIDATION.md#final-candidates)).
- **That the production puzzles are solvable in practice.** Nobody grinds 2^40 here. The twin
  rule is the argument that the production script behaves as the test script does.
- **Anything about relay, mining or fees.** These spends are non-standard (Binohash 8.2).
- **Anything beyond BH-SEC-1's assumptions**, in particular A3.

## 8. What the evaluator knows, and extending it

The evaluator understands one puzzle kind (the signature-size puzzle with nonce `r_min`), one
selection mechanism (pool pushes removed from the scriptCode by `OP_CHECKMULTISIG`), one binding
(a hash of a witness item compared with a constant) and two index encodings. Inside that, the
script is free: layout, stack choreography, pool sizes, round count, puzzle sizes, hash
choice, `OP_CODESEPARATOR` placement, which data lives in the script and which in the witness.

A mechanism outside it cannot be judged by this epoch. Known examples: the polyglot digest of
Binohash appendix D (a pool element that is itself a hash output cannot be given an easy test
twin); pools shared between rounds; sub-byte puzzle difficulty; hash-to-signature puzzles;
conditional execution. Each needs evaluator support, a soundness argument and tests that break
it on purpose, and arrives as a new contract epoch
([VALIDATION.md](../../../spec/VALIDATION.md#changing-the-contract)). Propose one in
Discussions with the prefix `[Contract]`.
