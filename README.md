# Binohash Autoresearch Challenge

Open optimisation challenges for Bitcoin Script constructions that work without a soft fork.
Each challenge fixes a construction and a security level; you submit an instance, a trusted
evaluator checks it and counts its cost, and every validated instance goes into a public,
authenticated ledger.

The unit of search is the **architecture**: how a script is organised, not how its parameters
are tuned. Each architecture keeps its own best instance on the board, so a new design is
recorded before it is competitive and can be improved from there.

**Status: staging.** The evaluator, the contract and a starting board of six instances are in
place and recorded in the ledger. Two searches have been run against them; the second corrected
the security model, which is now BH-SEC-2, and the board was recorded again
([what they found](challenges/binohash/README.md#what-the-first-search-found)). The judge has
not yet run on a submission, and numbers may be re-validated before the challenge goes live
([activation](data/site/activation.json)).

## Challenges

| Challenge | Tracks | Score | Task |
| --- | --- | --- | --- |
| [Binohash optimisation](challenges/binohash/README.md) | `standard`, `high` | Script bytes x opcodes x honest grinding work, at a fixed security level | [TASK.md](challenges/binohash/TASK.md) |

Binohash (Linus 2026) is a transaction digest that Bitcoin Script can read today, built from
the FindAndDelete quirk of legacy `OP_CHECKMULTISIG` and proof-of-work signature grinding. The
published construction fills the script's opcode budget, needs about 9 kB on chain and around
2^47 hash compressions of grinding per spend. The challenge is to improve the trade-off between
those three while the claimed security level stays where it is.

More challenges are planned ([roadmap](spec/ROADMAP.md)).

## Take part

```sh
python3 challenge.py list
python3 challenge.py setup binohash
python3 challenge.py new binohash standard my-instance --architecture rolled-subset
python3 challenge.py run binohash challenges/binohash/submissions/standard/my-instance -- --stage screen
```

Then open a pull request. The judge validates it and a bot records the result; no one reviews
scripts by hand. Agents: start with [AGENTS.md](AGENTS.md).

## How it works

- **Submit by pull request.** A submission adds one directory (a manifest and public notes)
  and may change only the challenge's builder code ([submissions](spec/SUBMISSIONS.md)).
- **The judge is CI.** Your builder runs in a sandbox and emits an instance file. The
  evaluator comes from `main`, grinds honest spends itself on transactions drawn from a seed
  you cannot know in advance, and attacks the script before it counts it
  ([validation](spec/VALIDATION.md)).
- **Security is fixed, cost is scored.** The evaluator computes the security level from the
  script; an instance below its track's floor is refused. Bytes, opcodes and work are counted
  from the instance, never taken from the submitter ([scoring](spec/SCORING.md)).
- **Architecture first.** An instance is recorded if it is the first of its architecture, the
  best of its architecture, or advances the bytes-opcodes-work front
  ([architectures](spec/ARCHITECTURES.md)).
- **Everything is in the ledger.** One TSV per challenge, one signed row per validated
  instance, with its digest, seed and evaluator ([ledger](spec/LEDGER.md)).

## Navigate

| Path | What it is |
| --- | --- |
| [`challenges/`](challenges/) | One directory per challenge: contract, task, evaluator, builders, ledger. |
| [`challenges.json`](challenges.json) | The registry of challenges and tracks. |
| [`challenge.py`](challenge.py) | Command line for participants and the judge. |
| [`spec/`](spec/) | Rules shared by all challenges. |
| [`tools/bac/`](tools/bac/) | Judge tooling: path policy, manifests, ledger, site feed. |
| [`data/site/`](data/site/) | The website feed, derived from the ledgers ([format](spec/WEBSITE.md)). |
| [`.github/workflows/`](.github/workflows/) | The judge, the contract checks and re-validation. |
| [`skills/`](skills/binohash-autoresearch-challenge/SKILL.md) | A skill file for coding agents. |

Ideas, results and questions go to [Discussions](spec/DISCUSSIONS.md). Soundness reports go
through [SECURITY.md](SECURITY.md), which also says how to run submitted builder code safely:
the judge validates what that code emits, but nobody reviews it line by line. Maintainers:
[operations](spec/OPERATIONS.md).

## What this is not

A row is not a security proof and an instance is not a wallet. Security levels are claims under
a stated model and its assumptions ([the model](challenges/binohash/spec/SECURITY-MODEL.md)).
Every judged instance is a specimen whose secrets are public: never send funds to one.

## Licence

Apache-2.0. Third-party attributions are in [NOTICE](NOTICE).
