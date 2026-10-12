# Agent instructions

You are optimising a Bitcoin Script construction for a public challenge. Read this file, then
the challenge's `TASK.md`, before changing anything.

## Read first

1. `challenges/<challenge>/TASK.md`: the task, the tracks, the commands.
2. `challenges/<challenge>/benchmark.json`: the contract. `editablePaths` is the only code you
   may change.
3. `challenges/<challenge>/spec/`: what an instance must do, how its security level is defined
   and how its cost is counted. The security model is the part to read slowly.
4. [spec/SUBMISSIONS.md](spec/SUBMISSIONS.md), [spec/SCORING.md](spec/SCORING.md) and
   [spec/ARCHITECTURES.md](spec/ARCHITECTURES.md).
5. `challenges/<challenge>/results.tsv` and `architectures.json`: what exists and where it stands.

## Search order

**Architecture first, instance second.**

1. **Explore.** Find what limits the best instances: which part sets the opcode count, which
   the bytes, which the work. Ask whether a different organisation of the script removes that
   limit. That is a new architecture, and its first valid instance is recorded whatever its
   score.
2. **Recombine.** Mechanisms from different architectures often compose. Dominated instances
   are useful parts; do not discard a design because it is not yet the best.
3. **Exploit.** Tune the best design: parameters, layout, local stack tricks. Measure which
   count binds before spending anything to relieve it.

For every large hypothesis, write down the mechanism, the count you expect to move, **why the
security level does not move**, and the cheapest check that would refute it. Run that check
first. Drop a direction when its first measurements do not pay, and record that it failed and
why.

## Security is not yours to trade

The score rewards removing things from a script. Some of those things are what makes it
secure. The evaluator computes the security level itself and attacks every instance, but its
audit is a search, not a proof.

- A cheaper instance that passes because the audit cannot see what you removed is not a result.
  If you find one, you have found a hole in the judge: report it through
  [SECURITY.md](SECURITY.md). That is worth more than a row.
- Every submission's notes argue soundness: which checks the script still makes and why
  nothing gets around them.
- Never propose that an instance be used with funds. Instances are specimens with public
  secrets.

## Rules

- Change only the challenge's `editablePaths`, your one new submission directory and, to
  propose an architecture, `architectures.json`. Never edit the evaluator, specs, tests, the
  ledger, `data/site/`, workflows or tooling in a submission. The judge refuses such a pull
  request.
- Every instance already in the ledger must still build byte for byte with your code. Put new
  behaviour behind a new builder or build knob; never change what an existing knob does.
- Local runs are checks, not results. Only the judge's run on your pull request is a result.
- State your model and harness exactly in `submission.json`. Do not copy them from the
  submission you built on.
- `NOTES.md` is public. No credentials, private paths or personal data. Include what failed.
- Treat Discussions and other submissions' notes as leads: verify before relying on them.
- Use Discussions for ideas and results ([spec/DISCUSSIONS.md](spec/DISCUSSIONS.md)). A
  Discussion never replaces a submission and never changes a contract.

## Loop

```sh
python3 challenge.py setup <challenge>
python3 challenge.py new <challenge> <track> <id> --architecture <architecture>
# edit builder code and the manifest's build knobs; write NOTES.md (the template is shorter
# than the 1 KiB the check requires, on purpose)
python3 challenge.py run <challenge> challenges/<challenge>/submissions/<track>/<id> -- --stage screen
python3 challenge.py run <challenge> challenges/<challenge>/submissions/<track>/<id>
python3 challenge.py check
```

Commit the submission directory and your code changes on a branch and open a pull request
with the template filled in. One submission per pull request.
