# Submissions

A submission is a pull request against `main`. The judge workflow validates it; nobody reviews
scripts by hand. A valid instance that earns a standing ([SCORING.md](SCORING.md)) is merged and
recorded by a bot.

## What a submission contains

| Path | Rule |
| --- | --- |
| `challenges/<challenge>/submissions/<track>/<id>/submission.json` | Required, new. The manifest. |
| `challenges/<challenge>/submissions/<track>/<id>/NOTES.md` | Required, new. Public research notes, 1 KiB to 100 KiB. |
| The challenge's editable paths (`editablePaths` in `benchmark.json`) | Optional. The builder code. |
| `challenges/<challenge>/architectures.json` | Optional. Append one entry to propose a new architecture. |

Nothing else may change. One pull request carries one submission. `<id>` is a lowercase slug
(`a-z`, `0-9`, `-`, 3 to 64 characters) that describes the instance. A recorded submission is
immutable; improve on it with a new one.

## The manifest

```json
{
 "schema": "bac-submission-v1",
 "challenge": "binohash",
 "track": "standard",
 "architecture": "rolled-subset",
 "title": "Both pools after the selection logic",
 "build": {"BINO_BUILDER": "paper", "BINO_ROUNDS": "120:8,120:8", "BINO_PIN_BYTES": "5"},
 "claimed": {"bytes": 9349, "opcodes": 199, "work_bits": 46.99},
 "authors": ["github-login"],
 "model": "exact model name",
 "harness": "exact harness name",
 "parents": ["id-of-a-submission-this-builds-on"],
 "discussion": "https://github.com/teddyjfpender/binohash-autoresearch-challenge/discussions/12"
}
```

- `architecture` must be an id in the registry ([ARCHITECTURES.md](ARCHITECTURES.md)).
- `build` holds the challenge's build knobs. The track's spec is set by the judge.
- `model` and `harness` name the exact model and coding harness used; write `none` for an
  instance made without one. Do not copy them from the submission you built on.
- `claimed`, `parents` and `discussion` are optional. A claim is shown beside the judge's
  counts and decides nothing. There is no field for a security level: the evaluator computes it.

## Workflow

```sh
python3 challenge.py setup <challenge>
python3 challenge.py new <challenge> <track> <id> --architecture <architecture>
# edit the builder code and the manifest's build knobs
python3 challenge.py run <challenge> challenges/<challenge>/submissions/<track>/<id>
python3 challenge.py check
```

`run` builds and evaluates locally with the same evaluator the judge uses, on lanes derived
from the instance itself. It is a check for you, not a result: the judge draws its lanes from
a seed you cannot know in advance.

Then open the pull request with the template filled in.

## What the judge does

1. **Policy.** The diff must match the table above; files must be regular and non-executable;
   builder source may import only pure modules.
2. **Manifest.** `submission.json` and `NOTES.md` are checked.
3. **Recorded instances.** With your code in place, every instance already in the ledger or on
   the starting board must still build byte for byte. Put new behaviour behind a new builder or
   build knob.
4. **Build.** Your builder runs in a sandbox with no network and writes the instance file.
5. **Validate.** The trusted evaluator, taken from `main`, runs the screen stage and then the
   full stage on lanes seeded by the ledger key, and replays the spends of the first lanes
   through Bitcoin Core.
6. **Standing.** The row is compared with the ledger.
7. **Report.** The bot comments the result. If the instance earns a standing it merges the pull
   request, appends the signed row to `results.tsv` and rebuilds the site feed.

A pull request that adds an architecture, uses a builder the rules do not know or would be the
first of its architecture waits for a maintainer's `architecture-approved` label before step 7.
A new push re-runs everything; an old result never carries over to new code.

## Outcomes

| Label | Meaning |
| --- | --- |
| `submission-invalid` | Policy, manifest, build or validation failed. The comment says which. |
| `submission-not-recorded` | Valid, but it earns no standing. Nothing is merged. |
| `needs-architecture-review` | Valid and it needs a maintainer's look. Waiting. |
| `submission-recorded` | Merged; the row is in the ledger. |

## Notes

`NOTES.md` is the research record that travels with the instance: starting point, mechanism,
**why the security level is unchanged**, experiments including the ones that failed, the
measured result and what to try next. The soundness section is not a formality: the audit is a
search, and the notes are where the argument for what it cannot see is written down. Notes are
public. Remove credentials, private paths and personal data.
