# Website feed

A site reads this repository at one immutable commit of `main` through
`data/site/sources.json`. Everything under `data/site/` except `activation.json` and
`<challenge>/challenge.json` is derived from the ledgers by `python3 challenge.py site`; the
contract check fails if it is stale.

## Files

| File | Schema | Content |
| --- | --- | --- |
| `data/site/sources.json` | `bac-site-sources-v1` | Paths of every file below, per challenge. |
| `data/site/activation.json` | `bac-site-activation-v1` | `status` (`staging`, `live`, `closed`) and the gates behind it. Authored. |
| `challenges.json` | `bac-registry-v1` | The challenges and their tracks. |
| `challenges/<id>/benchmark.json` | `bac-benchmark-v1` | The contract: metric, tracks, paths, validation, acceptance. |
| `challenges/<id>/architectures.json` | `bac-architectures-v1` | The architecture registry. |
| `challenges/<id>/targets.json` | `bac-targets-v1` | Published points, with their conventions. |
| `challenges/<id>/results.tsv` | [LEDGER.md](LEDGER.md) | One row per validated instance. |
| `data/site/<id>/leaderboard.json` | `bac-leaderboard-v1` | Per track: best instance, architecture elites, front, history, targets. |
| `data/site/<id>/challenge.json` | `bac-site-content-v1` | Display copy: titles, summaries, rules, how to take part. Authored. |
| `challenges/<id>/starting-board.json` | `bac-starting-board-v1` | Optional (`startingBoard` in `sources.json`). The instances the board starts from, with measurements on public lanes. |

## `leaderboard.json`

```
{ schema, challenge, metric, ledger, ledgerRows, ledgerHead,
  tracks: [ { track, title, spec, securityFloorBits, instances,
              best,                       // lowest score in the track
              baseline,                   // the track's baseline instance (a ledger row), or null while pending
              belowBaseline,              // 1 - best.score / baseline.score
              architectures: [ { id, name, parent, instances, firstUnixTime,
                                 elite, fewestBytes, fewestOpcodes, leastWork,
                                 history } ],   // running best score of the architecture
              front,                      // (bytes, opcodes, workBits) Pareto front
              history,                    // running best score of the track
              targets } ] }
```

Every instance object has the same keys: `unixTime`, `track`, `architecture`, `bytes`,
`opcodes`, `workBits`, `score`, `securityBits`, `lanes`, `engine`, `instanceSha256`,
`verifierSha256`, `commit`, `pr`, `author`, `model`, `harness`, `submission`, `kind`,
`standing`, `note`.

## Conventions

- `score` is `bytes x opcodes x 2^(workBits - 40)`. Lower is better for `score`, `bytes`,
  `opcodes` and `workBits`. `benchmark.json` states the metric's name, formula, components and
  units, so nothing about units needs to be hard-coded.
- `securityBits` is not a ranking axis. It is at or above the track's `securityFloorBits` for
  every row; show it, with the model's name, wherever a score is shown.
- The primary grouping is `architecture`; instances are the secondary level.
- Improvement over time is `history`: each entry is an instance that lowered the running best.
- Pull request and author data are also available live from the GitHub API through `pr`.
- While `activation.json` says `staging`, numbers may be re-validated and should be shown as
  provisional. A track whose `baseline` is null has no recorded baseline yet.
- The starting board's `local` measurements are not ledger rows: public lanes, no ledger-key
  seed, no signature. A site may show them for a track that has no rows yet, and must label
  them as measured and not yet recorded. Once a track has rows, show the rows.
