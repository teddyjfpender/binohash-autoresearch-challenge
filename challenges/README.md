# Challenges

| Challenge | Tracks | Status |
| --- | --- | --- |
| [Binohash optimisation](binohash/README.md) | `standard`, `high` | staging |

Every challenge directory has the same parts:

| File | Purpose |
| --- | --- |
| `README.md` | What the challenge is and why it matters. |
| `TASK.md` | The task for an optimisation agent. |
| `benchmark.json` | The contract: tracks, editable and trusted paths, validation, acceptance. |
| `architectures.json` | The architecture registry ([rules](../spec/ARCHITECTURES.md)). |
| `targets.json` | Published points for context. |
| `results.tsv` | The ledger of validated instances ([format](../spec/LEDGER.md)). |
| `starting-board.json` | The instances the board starts from, until the judge has recorded them. |
| `submissions/` | One directory per submission ([rules](../spec/SUBMISSIONS.md)). |
| `spec/` | The challenge's technical specification, security model included. |

Planned challenges are listed in the [roadmap](../spec/ROADMAP.md).
