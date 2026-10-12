# Validation and trust

The judge is a set of GitHub Actions workflows plus the trusted code of each challenge. This
document says what is trusted, what is not, and what a recorded row does and does not show.

## Trust boundaries

| Part | Trusted | Why |
| --- | --- | --- |
| Workflows, `tools/bac`, `challenge.py` | Yes | Always taken from the base branch, never from a pull request. |
| A challenge's `trustedPaths` (evaluator, specs, tests, tools) | Yes | Outside the editable surface; changes need maintainer review. |
| A challenge's `editablePaths` (builders) | No | Submission code. Run only in the build stage, never in the evaluator's process. |
| The instance file a builder emits | No | Parsed defensively by the evaluator. Every field is re-derived or exercised. |
| `submission.json`, `NOTES.md` | No | Read as data. Build knobs are restricted to a pattern and a safe character set. |

The judge workflow runs on `pull_request_target`, so its definition comes from `main` and every
script it calls comes from the pull request's base commit, never from the pull request. Its
jobs are separated by what they may touch:

| Job | Runs submission code | Token | Secrets | Output |
| --- | --- | --- | --- | --- |
| `intake` | No. Reads the pull request with `git show`. | read | none | policy verdict, manifest |
| `build` | Yes, inside bubblewrap: read-only filesystem, no network, unprivileged uid. | read | none | the instance file |
| `evaluate` | No. Base-branch code only. | read | ledger key | ledger row, standing |
| `record` | No. | write | ledger key | comment, merge, ledger commit |

`record` relies only on job outputs of `intake` and `evaluate`. The instance is handed from
`build` to `evaluate` as a workflow artifact and is parsed as hostile data; no artifact is
trusted, so a compromised `build` job cannot forge a result.

## Builder code on main

A merged submission's builder code is on `main` because its instance passed the judge, not
because a person read it. The intake job parses the source without running it and refuses
anything that imports beyond a short list of pure modules, names `open`, `eval`, `getattr` and
the like, or touches a double-underscore attribute. That is a filter, not a proof. The boundary
is the sandbox: every job that runs builder code does so confined and with no secret, and
workflows that hold the ledger key take only the instance file from such a job. The same care
applies to anyone running the code locally ([SECURITY.md](../SECURITY.md)).

## Lanes and seeds

An instance is validated on lanes (a challenge defines what a lane is; for Binohash, one
judge-chosen spending transaction and everything done with it). The seed is derived from the
instance's digest under the ledger key ([LEDGER.md](LEDGER.md)). A submitter cannot know it
before the judge runs and gets a different one for every change to the instance, so searching
for a script whose sampled transactions, selections and alterations happen to miss a fault is
not possible. The seed is published in the row, so the run can be repeated exactly.

Binohash runs two stages, set in its specs:

| Stage | Lanes | Audit lanes | Core comparison |
| --- | ---: | ---: | --- |
| Screen | 4 | 1 | no |
| Full | 48 | 3 | the spends of the first 8 lanes |

On every lane the evaluator grinds and verifies an honest spend and checks the script's
structure from the execution trace. On audit lanes it also alters the spend in tens of
thousands of ways as a spender who can satisfy any signature check they control. The checks are
described in `challenges/binohash/spec/DESIGN.md`. Every check must pass on every lane.

The counts a row carries do not depend on the lanes. They are exact functions of the instance.

## Two engines

The **reference engine** is the evaluator's own legacy script interpreter, written to be read,
with provenance tracking that the audit needs. **Core** is Bitcoin Core's consensus library,
through `tools/core`. The full stage replays honest and altered spends through Core with the
verdicts the reference engine reached with real signature verification, and stops on any
disagreement as a fault of the evaluator. A row's `engine` column says which engines passed it.

## What a row shows

- The named instance passed every static check and every lane under the named evaluator.
- Its bytes, opcodes, work and security level are the evaluator's, not the submitter's.
- For the spends replayed, Bitcoin Core's consensus rules accept the honest spends of the test
  twin and refuse the altered ones.

## What a row does not show

- **Not a security proof.** `security_bits` is a level under a stated model and its
  assumptions. The audit that supports it is a search over alterations of an honest spend; it
  can miss a freedom that needs a combination it did not try.
- **Not the model's correctness.** A row inherits every assumption of the challenge's security
  model, including assumptions about parties outside the script.
- **Not a production spend.** The judge grinds the test twin. That the production script
  behaves the same at full difficulty follows from the twin rule, not from execution.
- **Not a statement about relay, mining, fees or hardware.** Only the counted metrics are
  compared.
- **Not novelty.** The declared architecture is checked against the registry's rules by a
  maintainer when it is new, not against the literature.

## Final candidates

A ledger row is enough for an instance to stand on the board. It is not enough for the
instance a challenge names as its final result on a track: the one quoted in a paper, a
release note or the site's headline once the challenge is live. That instance must have, in
the repository:

1. **A written soundness argument**, check by check: for each requirement of the challenge's
   design and security model, why the script meets it for every unlocking script, not only the
   ones the audit tried. Where a machine-checked proof exists it replaces the prose; where it
   does not, the argument says so.
2. **Independent review of that argument** by someone other than its author, recorded with the
   reviewer's name and the commit reviewed.
3. **Its ledger row with the Core comparison**, and a full-stage re-validation under the
   current evaluator.
4. **A spend of the production script**, ground at full difficulty and accepted by Bitcoin
   Core's consensus library, for at least one transaction.

A result is never described as proved beyond what item 1 actually proves.

## Changing the contract

A spec, a security or work model, an acceptance rule, the score or the evaluator's behaviour
changes only through a reviewed pull request that starts a new contract epoch (`contractEpoch`
in `benchmark.json`). Rows of an earlier epoch are kept and marked by their `verifier_sha256`;
they are never edited. A confirmed soundness bug is handled the same way, with affected rows
re-validated. Support for a mechanism the evaluator does not yet know is a contract change
too: it comes with the evaluator code, the security argument and tests that break the mechanism
on purpose and show the evaluator notices.
