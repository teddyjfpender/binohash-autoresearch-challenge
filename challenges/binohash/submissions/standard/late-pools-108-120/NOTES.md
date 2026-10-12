# Late pools, 108-choose-8 and 120-choose-8

The smallest instance found on the `standard` track: 428 bytes below the baseline, with less
work than the baseline as well.

## Goal and starting point

`standard/late-pools`. That instance has 0.02 bits of slack above the floor. This one asks what
the smallest script at the floor looks like when the layout gain is spent on bytes.

## Mechanism

Fewer selections raise the level under BH-SEC-1 and make a round fail more often. Round 0's pool
is cut from 120 to 108 elements (2^38.4 selections, a solution 27% of the time); round 1 keeps
120. The level rises to 81.64 and 6.9 transactions are tried per spend instead of 3.5. The late
layout pays for that: at 9 compressions per attempt, round 0 is cheap to fail in, and it is
searched first.

Twelve elements fewer is 372 bytes of script; with the 56 bytes the layout and the shorter
preimages save, 8,921 bytes.

## Soundness

The script is `late-pools` with a smaller pool in one round; the argument there applies
unchanged. The level is the evaluator's, 0.14 bits above the floor.

## Experiments

From the same exact-count search as `late-pools-120-172`, taking the smallest instance at or
above the floor instead of the lowest score.

| | Bytes | Opcodes | Work | Security |
| --- | ---: | ---: | ---: | ---: |
| `paper-two-round` | 9,349 | 199 | 2^46.740 | 81.521 |
| `late-pools` | 9,293 | 199 | 2^46.081 | 81.521 |
| this | 8,921 | 199 | 2^46.244 | 81.643 |

Score 134,554,401. Against the baseline it is better on bytes and work at equal opcodes.
Against `late-pools` it trades 0.16 bits of work for 372 bytes.

Smaller pools still pass the floor (the level keeps rising) but the tries per spend grow
quickly: at 100 elements a round-0 solution exists 15% of the time and 12 transactions are
tried per spend. Where the product of bytes
and work turns is close to 108.

## Result and next steps

The byte count is 31 per pool element and nothing else in the script is large. Going much
below this needs fewer bytes per element, which in this epoch means fewer elements, which
means more selections per round, which the opcode budget does not allow with pinning in place.

## Attribution

Built with Claude Opus 5.5 in Claude Code, directed by the repository's maintainer.
