# Submissions

One directory per submission: `<track>/<id>/submission.json` and `<track>/<id>/NOTES.md`.
Create one with

```sh
python3 challenge.py new binohash <track> <id> --architecture <architecture>
```

and see [spec/SUBMISSIONS.md](../../../spec/SUBMISSIONS.md). Directories here are immutable once
recorded.

Every row of [`results.tsv`](../results.tsv) has a directory here. `submission.json` holds the
build knobs that reproduce the instance byte for byte;
[`tools/verify_submissions.py`](../tools/verify_submissions.py) rebuilds each one from its
manifest alone and checks the digest against the ledger and the
[starting board](../starting-board.json).
