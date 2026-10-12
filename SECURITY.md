# Security

The judge must never record an instance whose real security is below the level the ledger
states, or whose honest spends do not work. If you find a way to make such an instance pass,
to learn a lane seed before validation, to alter a ledger row, or to run code outside the
build sandbox, please report it privately:

- use GitHub's **Report a vulnerability** on this repository (Security tab), and
- include a minimal reproduction and the commit you tested.

The cases that matter most here:

- an instance the evaluator accepts although a spender has more selections, or cheaper
  puzzles, than the evaluator counts;
- an accepted spend that skips a check the instance declares, which the audit did not find;
- a disagreement between the reference engine and Bitcoin Core;
- a flaw in the security model itself: an attack cheaper than `security_bits` on an instance
  that satisfies every stated assumption.

Do not open a public issue, discussion or pull request for such a report. A confirmed soundness
bug is fixed in a new contract epoch; affected ledger rows are marked and re-validated, never
silently removed ([spec/VALIDATION.md](spec/VALIDATION.md)).

A weakness of Binohash that the stated assumptions already name (for example that it is not
quantum-safe, or that it needs a downstream verifier to enforce hash types) is not a report;
it is the model. A proposal to change the model belongs in Discussions with the prefix
`[Contract]`.

## Instances are specimens

Every judged instance publishes the preimages of all its commitments, so that the judge can
open any selection. Anyone can spend an output locked by one. **Never send funds to a script
from this repository.**

## Running the code yourself

A challenge's editable paths (for Binohash, `challenges/binohash/builders/`) hold code written
by submitters. The judge validates the instance that code emits and screens the source for
anything but pure computation, but nobody reviews it line by line before it merges. Treat it
as untrusted on `main` as much as in a pull request:

- `./benchmark.sh` runs it in a sandbox (read-only filesystem, no network, unprivileged user)
  where bubblewrap is available, which is Linux. It warns when it runs unconfined.
- On macOS it uses `sandbox-exec`, which denies writes and network access but leaves the
  filesystem readable. Use a container or a virtual machine for code you have not read.
- `tools/ci/pins_sandboxed.sh` rebuilds the recorded instances the same way. Running
  `tools/verify_submissions.py` or the test `test_pins.py` directly runs builder code
  unconfined.

Everything else in the repository (the evaluator, the judge, the workflows) changes only
through maintainer-reviewed pull requests.
