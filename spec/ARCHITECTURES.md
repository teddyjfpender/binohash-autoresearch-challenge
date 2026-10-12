# Architectures: the primary unit of search

A challenge here is searched at two levels, in this order.

1. **Architecture.** How the script is organised: which tables it holds, how a selection is
   made and bound, and which mechanism ties a selection to the transaction. Two instances have
   different architectures when no change of parameters turns one into the other.
2. **Instance.** One point within an architecture: its pool sizes, puzzle sizes, round count,
   layout and local stack choreography. This is exploitation of a design that already exists.

Most challenge platforms keep a single best result and reward whatever beats it. That makes the
search greedy: a new design that is not yet the best is discarded, even when it is the one that
would win after tuning. This repository keeps every architecture's best instance instead, and
records an instance when it advances its own architecture or the track's trade-off front
([SCORING.md](SCORING.md)).

## The registry

Each challenge has an `architectures.json`. An entry states:

| Field | Meaning |
| --- | --- |
| `id` | Lowercase slug, permanent. |
| `name` | Short display name. |
| `mechanism` | What the architecture does, in enough detail to implement. |
| `distinguishing` | The structural property that separates it from every other entry. |
| `parent` | The architecture it specialises or was derived from, if any. |
| `references` | Primary sources for the construction. |

Three words are kept apart throughout. An **architecture** is a registry entry: a way of
organising the script, and the unit the board is ranked by. A **builder** is the code that
emits instances, selected by a build knob; one builder may serve several architectures and one
architecture may have several builders. An **instance** is one emitted script with its test
twin, named by its digest.

Every submission declares exactly one architecture from the registry. Where a challenge states
rules that derive the architecture from the build knobs, the declaration must agree with them.
The registry is kept small on purpose: a handful of designs a reader can tell apart, not one
entry per variant.

## What is and is not a new architecture

A new architecture changes the organisation of the script. These do **not** qualify:

- a new name, seed or parameter value;
- a different pool size, selection count, round count or puzzle size of an existing mechanism;
- the same tables and the same selection loop in a different order or position in the script;
- a local stack trick that makes one step cheaper without changing what the tables hold;
- a combination of existing knobs of one architecture.

A useful test: state the property in `distinguishing`, and say which existing entry the
instance would belong to without it. If no such property can be stated, the work is a
refinement, and it is welcome as one.

## A new architecture is not a new mechanism

An architecture reorganises a script within what the challenge's evaluator can judge. A
**mechanism** the evaluator does not know (a different puzzle, a different way to vary the
sighash, a different binding) cannot be validated by the current contract at all, whatever the
registry says. It needs evaluator support and a security argument first, and arrives as a new
contract epoch ([VALIDATION.md](VALIDATION.md#changing-the-contract)). The challenge's design
document lists what its evaluator knows.

## Proposing one

1. Open a Discussion in **Ideas** with level "New architecture": the mechanism, the cost it
   removes, why the security level is unchanged and the cheapest falsifying check.
2. In the submission pull request, append the entry to `architectures.json` and declare it in
   `submission.json`.
3. The judge validates the instance as usual. Because the registry changed, the pull request is
   labelled `needs-architecture-review` and waits for a maintainer, who checks the entry
   against the rules above, reads the soundness section of the notes, and either adds
   `architecture-approved` or asks for the submission to be filed under an existing
   architecture.

The first validated instance of an approved architecture is recorded whatever its score. That
is the point: a new design gets a place on the board before it is competitive.
