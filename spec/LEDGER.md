# The results ledger

Each challenge has one `results.tsv`: tab-separated, a header row, no quoting, one row per
validated instance, in time order. It is the only source of the leaderboard and of the site
feed. Rows are appended by the judge workflow's bot and are never edited by hand.

## Columns

| Column | Meaning |
| --- | --- |
| `unix_time` | When the instance was first recorded (seconds since the epoch, UTC). |
| `track` | The track, e.g. `standard` or `high`. |
| `spec` | The pinned specification the instance was validated against. |
| `architecture` | The declared architecture, an id from `architectures.json`. |
| `bytes` | Locking script plus the largest honest unlocking script, in bytes. |
| `opcodes` | The interpreter's operation count for the locking script on an honest spend. |
| `work_bits` | log2 of the expected SHA-256 compressions for one honest spend, 3 decimals. |
| `score` | The challenge score, lower is better: `bytes x opcodes x 2^(work_bits - 40)`, exact from the row's own cells. |
| `security_bits` | The security level the evaluator computed, 3 decimals. At or above the track's floor. |
| `lanes` | Lanes of the full validation. |
| `engine` | The engines that passed the instance, e.g. `reference-48+core-20`. |
| `seed` | The 32-byte lane seed of the full validation, hex. |
| `instance_sha256` | SHA-256 of the instance file. |
| `verifier_sha256` | Digest of the trusted evaluator that passed the instance. |
| `commit` | The commit the instance builds from; `genesis` for the starting board. |
| `pr` | The pull request number, empty for historical rows. |
| `author`, `model`, `harness` | Who submitted, and the model and harness they declared. |
| `submission` | `<track>/<id>` of the submission directory, which holds the manifest and notes. |
| `kind` | `submission`, or `historical` for the starting board. |
| `standing` | Why the row was recorded: `new-architecture`, `architecture-elite`, `front`. |
| `status` | `OK`. Only validated instances are recorded. |
| `note` | The submission's title. |
| `mac` | Chained HMAC-SHA256 of the row under the ledger key. |

## How a row is authenticated

- **The instance is named by content.** `instance_sha256` identifies the exact file: the
  production script, the test twin and the witness description. Rebuilding at `commit` with the
  submission's build knobs must reproduce it byte for byte.
- **The judge is named by content.** `verifier_sha256` is one digest over every trusted file of
  the challenge (`python3 challenge.py verifier-digest <challenge>`). Rows passed by different
  versions of the evaluator are distinguishable.
- **The lanes could not be chosen by the submitter.** `seed` is
  `HMAC-SHA256(ledger key, "bac-lane-seed-v1|instance digest")`. It is unknown until the judge
  runs and different for every instance, so a submitter cannot search for a script whose
  sampled transactions and alterations miss a fault. It is published, so anyone can repeat the
  exact run: `./evaluate.sh --root <dir> --spec <spec> --seed <seed>`.
- **The row could not be forged.** `mac` is
  `HMAC-SHA256(ledger key, "bac-ledger-row-v1|previous mac|row cells")`, chained from an
  all-zero value. Adding, changing, reordering or removing a row breaks the chain. Only the
  judge workflow holds the key; `python3 challenge.py verify-ledger` checks the chain.

Anyone can check a row without the key by rebuilding the instance and re-running the evaluator
with the published seed. The key is needed only to check that the row was written by the judge.

## The starting board

The instances a challenge starts from are listed in its `starting-board.json` with
measurements on public lanes. Those are evidence, not rows. A maintainer records them with
`python3 challenge.py genesis <challenge>`: each is rebuilt, must reproduce its catalogued
digest, is validated in full under a ledger-key seed and is appended with `kind = historical`
and `commit = genesis`. Until then a staging track's baseline is *pending* and the track has
no baseline score ([SCORING.md](SCORING.md)).

Historical rows count exactly as submissions do. Each has a submission directory with the
build knobs that reproduce it.

## Reading it

- **Leaderboard by architecture:** the lowest `score` per `(track, architecture)`.
- **Trade-off front:** per track, the rows no other row matches or beats on all of `bytes`,
  `opcodes` and `work_bits`.
- **Improvement over time:** the running minimum of `score` in `unix_time` order, per track or
  per architecture.

`data/site/<challenge>/leaderboard.json` holds exactly these three views, rebuilt from the
ledger on every recorded row ([WEBSITE.md](WEBSITE.md)).

## What the chain does and does not show

Each row's `mac` covers the row and the previous row's `mac`, so a row cannot be changed,
inserted or reordered without the key. The chain alone does not show that rows were not removed
from the end. That is covered by the repository history: the ledger is append-only on `main`,
the contract check refuses a pull request that touches it, and the feed states the row count
and the last row's `mac` (`ledgerRows`, `ledgerHead`), so a shortened ledger is visible.
