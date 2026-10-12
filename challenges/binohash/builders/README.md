# Builders

This directory is the editable surface of the challenge. A builder is a Python function that
turns build knobs into an instance: the production locking script, its test twin and the
description of an honest unlocking script ([spec/DESIGN.md](../spec/DESIGN.md), section 2).

```python
def build(knobs: dict[str, str]) -> dict: ...   # a bh-instance-v1 object
```

`builders/__init__.py` dispatches on `BINO_BUILDER`. Register a new builder there.

## Rules

- **Deterministic.** The same knobs give the same bytes on every machine. Derive anything
  random-looking from fixed labels (`kit.specimen_bytes`).
- **No input or output.** The trusted runner writes the file. Builders may import `bh` (the
  evaluator's script, curve and transaction modules, as a library) and `collections`,
  `dataclasses`, `decimal`, `enum`, `fractions`, `functools`, `hashlib`, `hmac`, `itertools`,
  `math`, `operator`, `struct`, `typing`. Names such as `open`, `eval`, `getattr` and any
  double-underscore attribute are refused at intake.
- **Recorded instances stay byte-identical.** New behaviour goes behind a new builder name or
  a new knob whose default reproduces the old bytes.
- **Specimens only.** Every commitment's preimage is in the instance file. Nothing built here
  may hold funds.

## Shipped

| Builder | File | What it builds |
| --- | --- | --- |
| `paper` | [`paper.py`](paper.py) | The paper's construction: Appendix A pinning, Appendix B rounds. |
| `late` | [`late.py`](late.py) | The same construction with every commitment table first and each pool directly before its loop, round 0 last. Fewer compressions per grinding attempt. |

### Knobs of `paper` and `late`

| Knob | Default | Meaning |
| --- | --- | --- |
| `BINO_ROUNDS` | `120:8,120:8` | `n:t` per round: pool size and selections. |
| `BINO_PIN_BYTES` | `5` | A pinning signature is `60 - this` bytes: 8 bits of work per byte. |
| `BINO_ROUND_BYTES` | `5` per round | The same for each round's puzzle signature. |
| `BINO_CLAMP` | `all` | `late` only. `later` omits `<n> OP_MIN` in the round that runs first (the last one listed). See the notes of `standard/late-unclamped` for why that round and no other. |

Counts for `n:t` rounds: `13 + sum(11 t + 5)` operations; about `31 n + 230` bytes of locking
script per round plus 201 for pinning.

## The kit

[`kit.py`](kit.py) has the parts any builder needs:

| | |
| --- | --- |
| `Asm` | Appends opcodes and pushes and returns the offset of each push, which is what the instance's `key_at`, `size_at`, `pool` and `commit` fields hold. |
| `dummy_signatures(count, skip)` | Distinct nine-byte `SIGHASH_SINGLE` signatures, each with the key it verifies under when the bug fixes the sighash. |
| `specimen_bytes(label)` | Reproducible stand-ins for secrets. |
| `hash160`, `R_MIN_INVERSE`, `Z_BUG` | The commitment hash, the round puzzle's discrete logarithm, the bug digest as a number. |

## Writing a builder

1. Assemble the script twice, at the production sizes and at the test size, from the same
   function, so the two differ only in size and key pushes. `paper.assemble` is the pattern.
2. Record offsets as you push. Do not compute them afterwards.
3. Describe the witness bottom of the stack first. For an index, `rank` is the element's
   position among those not yet selected and `abs` its number in the pool; `add` is a constant
   your script expects on top.
4. Run it: `python3 challenge.py run binohash <submission dir> -- --stage screen`. A refusal at
   `honest-spend` usually means a depth is off by one; at `structure` the script does not make a
   check the instance declares; at `soundness` it makes it but an altered spend gets around it.
5. Check the stack depths by executing, not by counting: `bh.interp.verify(..., oracle=True,
   trace=Trace())` on a placeholder spend shows which pushes reached each check.
