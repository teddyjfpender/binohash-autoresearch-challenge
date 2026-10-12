# Late pools, a 6-byte round puzzle in place of 6-byte pinning

The lowest score found on the `high` track in the first search: 1.55 times below the baseline.
The 48 bits that the paper's configuration puts into four pinning puzzles are put into one round
puzzle instead.

## Goal and starting point

`high/late-pools-pin6`. Its work is 2^52.2, all of it pinning: three 48-bit puzzles once, and a
fourth for each of the 3.5 transactions tried per spend, 6.5 puzzles of 2^48 in all.

## Mechanism

The paper raises the level from its standard configuration by making all four pinning
signatures a byte shorter. That is four puzzles made 256 times harder, of which the attacker
pays for one per transaction.

Here pinning stays at 5 bytes (2^40 each) and round 0's puzzle goes to 6 bytes (2^48):

| | Selections | Puzzle | Solutions per transaction |
| --- | ---: | ---: | ---: |
| Round 0: 128-choose-10, 6-byte signature | 2^47.7 | 2^48.0 | 0.80 |
| Round 1: 154-choose-6, 5-byte signature | 2^34.0 | 2^40.0 | 0.015 |

Round 1 is scarce on purpose: one transaction in 65 has a solution. The spender searches it
first, at 2^34 attempts and one 40-bit pinning puzzle per transaction tried, and reaches the
48-bit round only with a transaction that has passed. The expensive puzzle is then attempted
about 2^48 times at 9 compressions, which is round 0's position at the end of the script.

The attacker follows the same route and the model charges them for it: transactions are
abandoned after round 1, so a transaction costs them about 2^42 and not round 0's 2^47.7. What
they cannot avoid is that a digest now carries a 48-bit and a 40-bit puzzle, 88 bits against
the baseline's 80, of which the birthday bound still leaves `W - E/2`, 24.2 and 23.0 bits. The
evaluator's level is 89.23 bits, from the exhaustive birthday; the stored-digest attack is half
a bit further out.

Ten selections and six fit the opcode budget exactly as eight and eight do: 199.

## Soundness

The script is `late.py`'s with these parameters; the structural argument of
`standard/late-pools` applies. Two things are specific to this instance and worth a reader's
attention:

- **The two attacks of BH-SEC-1 are half a bit apart here** (89.23 and 89.73), and the level is
  0.8 bits above the floor. A better attack on instances with one very scarce round would land
  here first.
- **A scarce round is not the mistake the first model made.** There the scarce round was cheap
  (32 bits) and credited with the cost of a large pool that most transactions never reached.
  Here the model abandons transactions as the attacker would, and what remains is the puzzles'
  own 88 bits plus pinning.

## Experiments

An exact count over round shapes with a 6-byte and a 5-byte round puzzle, 5-byte pinning,
selections 7 to 10 and 5 to 8, pools 90 to 200.

| | Bytes | Opcodes | Work | Security |
| --- | ---: | ---: | ---: | ---: |
| `paper-pin6` | 9,345 | 199 | 2^52.246 | 88.411 |
| `late-pools-pin6` | 9,289 | 199 | 2^52.235 | 88.411 |
| this | 10,634 | 199 | 2^51.423 | 89.231 |

Score 5,810,524,983 against 9,033,284,929. It does not dominate the baseline: 0.82 bits less
work for 1,289 bytes more.

What did not work:

- **The 48-bit round first in the script.** Its attempts then rehash the other pool: 34
  compressions instead of 9, and 2^53.1.
- **Two 6-byte rounds.** 2^49 of work per round before any retry.
- **6-byte pinning with unequal pools.** Nothing below equal pools of 120.

## Result and next steps

Work is one 48-bit puzzle at 9 compressions, 2^51.2, plus 2^48.8 for everything else: 120
transactions tried per spend, a 40-bit pinning puzzle each. To go
lower, the attempt has to get cheaper (9 compressions is the pool's tail, the loop and the
transaction's own tail) or the level has to come from somewhere that is not a 48-bit puzzle.
The security slack of 0.8 bits could be spent on a few more elements in round 1.

## Attribution

Built with Claude Opus 5.5 in Claude Code, directed by the repository's maintainer.
