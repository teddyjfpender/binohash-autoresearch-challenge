# Operations

For maintainers.

## One-time setup

1. **Ledger key.** Generate 32 random bytes as hex and store them as the repository secret
   `BAC_LEDGER_KEY`. Keep an offline copy. The key seeds lanes and signs ledger rows; anyone
   who holds it can predict seeds and write rows.

   ```sh
   python3 -c "import secrets; print(secrets.token_hex(32))" | gh secret set BAC_LEDGER_KEY
   ```

2. **Repository settings.**
   - Enable Discussions with the categories Ideas, Show and tell, Q&A and General.
   - Actions: give workflows read and write permission (Settings, Actions, General). They do
     not need permission to create or approve pull requests.
   - Allow squash merging. If `main` is protected, let `github-actions[bot]` bypass it: the
     bot merges recorded submissions and pushes ledger commits.
   - Enable private vulnerability reporting.
3. **Starting board.** On a checkout of `main`, with the Core comparison built:

   ```sh
   (cd challenges/binohash && ./setup.sh --core)
   BAC_LEDGER_KEY=… python3 challenge.py genesis binohash --core tools/core/target/release/cchk
   python3 challenge.py check --signed
   ```

   `genesis` rebuilds every candidate of `starting-board.json`, requires the catalogued digest,
   validates it in full under a ledger-key seed, appends the signed `historical` rows, switches
   the tracks' pending baselines to those rows and rebuilds the site feed. Commit
   `results.tsv`, `benchmark.json` and `data/site`. It runs builder code through
   `benchmark.sh`, sandboxed where a sandbox exists; run it on Linux. `--jobs N` evaluates `N`
   instances side by side, each in its own scratch directory; `challenge.py measure`, which
   fills in the catalogue's public-lane measurements, takes the same option.

## Routine

- **Submissions** need no action unless they wait for review. For those, read the registry
  entry against [ARCHITECTURES.md](ARCHITECTURES.md) and the soundness section of the notes
  against the challenge's design, then either add the label `architecture-approved` (the judge
  re-runs and records) or ask for changes. The approval covers the commit that was labelled: a
  later push removes the label and needs a new one.
- **Re-judging.** Add the label `rejudge` to run the judge again on an unchanged pull request.
- **Ledger audit.** The *Ledger audit* workflow verifies the MAC chains weekly, on every push to
  `main` that changes a ledger, and after each row the judge records. Locally:
  `BAC_LEDGER_KEY=… python3 challenge.py verify-ledger`.

## Recovery

The judge merges a submission and then pushes its ledger row. If the row could not be pushed
(the job says so on the pull request), the code is on `main` without a row. Re-run the failed
`record` job from the Actions page first. If that is no longer possible, record the row from
the run's `evaluate` output on a checkout of `main`:

```sh
BAC_LEDGER_KEY=… python3 challenge.py record <challenge> --row row.json
python3 challenge.py check --signed
```

with the row's `commit` set to the merge commit, then commit `results.tsv` and `data/site` and
push. Never edit or reorder existing rows.

## Changing trusted code

A change under a challenge's `trustedPaths` changes its verifier digest; later rows carry the
new one. Before merging: the challenge's tests pass, including every defect the evaluator must
refuse, and the Core comparison passes on the pinned vectors. If the change alters what is
accepted or how it is counted, it is a new contract epoch ([VALIDATION.md](VALIDATION.md)).
After a change that should not move any count, re-validate the best row of each track.

## Re-validating recorded instances

- **One instance, on a runner.** The *Re-validate a recorded instance* workflow rebuilds it in
  the build sandbox, validates it with the current evaluator and the ledger key, and requires
  the result to equal its ledger row (seed, digest, counts). A row recorded by an earlier
  evaluator is expected to reproduce under the current one; the two verifier digests are
  printed.
- **All digests, locally.** `challenges/binohash/tools/verify_submissions.py` rebuilds every
  ledger row and starting-board candidate from its `submission.json` alone and checks the
  instance digest. Run it after a change to the builders that should not move any recorded
  instance. It runs builder code; use `tools/ci/pins_sandboxed.sh` for code you have not read.

## Rotating the ledger key

Rotate if the key may have leaked. Seeds of recorded rows stay valid evidence (they were
unknown when the instances were made). Re-sign the chain with the new key, commit the ledger
and record the rotation in the commit message; rows are not otherwise changed.

## Adding a challenge

See [ROADMAP.md](ROADMAP.md). The judge workflow's `build` and `evaluate` jobs are per
challenge; copy them for the new challenge's toolchain and keep the same job boundaries.
