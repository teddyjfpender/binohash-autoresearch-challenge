---
name: binohash-autoresearch-challenge
description: Work on the Binohash Autoresearch Challenge repository: set up the challenge, build and evaluate a Binohash instance locally, create a submission directory, and open a submission pull request that the CI judge validates and records. Use when asked to optimise or submit a Bitcoin Script instance for one of its challenges (script bytes, opcodes and honest grinding work at a fixed security level).
---

# Binohash Autoresearch Challenge

## Rules that cannot be bent

- Read `AGENTS.md`, `challenges/<challenge>/TASK.md` and the challenge's
  `spec/SECURITY-MODEL.md` before editing.
- Edit only the challenge's `editablePaths` (see `benchmark.json`), one new submission
  directory and, to propose an architecture, `architectures.json`.
- The security level is fixed by the track and computed by the evaluator. Never trade it for
  score. An instance that passes only because the audit cannot see a removed check is a hole in
  the judge: report it through `SECURITY.md`, do not submit it.
- Recorded instances must stay byte-identical: new behaviour goes behind a new builder or knob.
- Local results are claims. The judge's run on the pull request is the result.
- Notes and manifests are public. Remove secrets, private paths and personal data.
- Instances are specimens with public secrets. Never suggest sending funds to one.

## Commands

```sh
python3 challenge.py list                       # challenges and tracks
python3 challenge.py setup <challenge>          # toolchain and sandbox check
python3 challenge.py new <challenge> <track> <id> --architecture <architecture>
python3 challenge.py run <challenge> challenges/<challenge>/submissions/<track>/<id> [-- evaluator args]
python3 challenge.py check                      # repository contract check
```

Evaluator arguments for `run`: `--stage screen` (4 lanes, under a minute), no argument for the
full stage, `--core tools/core/target/release/cchk` to replay spends through Bitcoin Core.

## Workflow

1. Read `results.tsv`, `starting-board.json` and `architectures.json` of the challenge. Group
   rows by `architecture`; the lowest `score` in each is that architecture's elite.
2. Read `score.json` of a run of the instance you start from: it breaks bytes, opcodes and work
   down by part, and gives the security level against the floor.
3. Decide the level of the work: a new architecture, a recombination, or a refinement of an
   existing one (`spec/ARCHITECTURES.md`). Architecture comes first.
4. State the hypothesis, why the security level does not move, and the cheapest falsifying
   check. Run the check.
5. Implement behind a new builder or build knob. Run
   `python3 challenges/<challenge>/tools/verify_submissions.py` for recorded instances.
6. Create the submission directory, set the build knobs in `submission.json`, write `NOTES.md`
   with its soundness section.
7. `run` (screen, then full), then `check`, then open a pull request using the template.
8. Read the judge's comment. `submission-recorded` means the row is in the ledger. A rejection
   names the stage; `soundness` prints the unlocking script that got through.

## Attribution

Set `model` to the exact underlying model and `harness` to the exact coding harness. Never copy
them from the submission you built on.
