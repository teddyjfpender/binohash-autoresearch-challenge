"""Puzzle work, the security level and honest work: the numbers the board is ranked by."""
import math
import unittest
from decimal import Decimal

import support  # noqa: F401
from bh import secp256k1 as ec
from bh.judge import Rng
from bh.model import SizePuzzle, _level, _restricted_birthday, blocks, compressions, exp2, honest_work, log2, overlap, s_range, security_bits

D_MIN = pow(ec.R_MIN, -1, ec.N)


class Puzzle(unittest.TestCase):
    def test_a_byte_costs_eight_bits(self):
        for short in range(1, 8):
            bits = float(SizePuzzle(D_MIN, 60 - short).bits)
            self.assertAlmostEqual(bits, 8 * short + 0.0056, places=3)

    def test_intervals_hold_exactly_the_accepted_sighashes(self):
        puzzle = SizePuzzle(D_MIN, 59)
        intervals = puzzle.z_intervals()
        self.assertEqual(sum(b - a for a, b in intervals), puzzle.count)
        rng = Rng(b"\x01" * 32, "intervals")
        probes = [int.from_bytes(rng.bytes(32), "big") % ec.N for _ in range(2000)]
        for a, b in intervals:
            probes += [a - 1, a, a + 1, b - 1, b, b + 1]
        for z in probes:
            z %= ec.N
            self.assertEqual(puzzle.solve(z) is not None, any(a <= z < b for a, b in intervals))

    def test_all_four_ways_to_be_short_are_real_signatures(self):
        puzzle = SizePuzzle(D_MIN, 59)
        key = ec.mul(D_MIN)
        lo, hi = s_range(31)
        kinds = set()
        for a, b in puzzle.z_intervals():
            z = (a + b) // 2
            r, s = puzzle.solve(z)
            self.assertTrue(ec.verify(key, z, r, s))
            self.assertEqual(len(ec.der_encode(r, s, 1)), 59)
            u = 2 * (z + puzzle.offset) % ec.N
            kinds.add((lo <= u < hi, 2 * ((z + puzzle.offset) % ec.N) >= ec.N))
        self.assertEqual(len(kinds), 4)

    def test_acceptance_rate_matches_the_count(self):
        puzzle = SizePuzzle(D_MIN, 59)
        rng = Rng(b"\x02" * 32, "rate")
        trials = 60000
        hits = sum(puzzle.solve(int.from_bytes(rng.bytes(32), "big")) is not None for _ in range(trials))
        expected = trials * puzzle.count / ec.N
        self.assertLess(abs(hits - expected), 5 * math.sqrt(expected))

    def test_appendix_a_keys_have_disjoint_targets(self):
        def pin(i, bits):
            return SizePuzzle(-(1 << (256 - bits + i)) * D_MIN % ec.N, 60 - (bits - 2) // 8)
        for bits in (10, 42, 50):
            sets = [pin(i, bits).z_intervals() for i in range(1, 5)]
            for i in range(4):
                for j in range(i):
                    self.assertFalse(overlap(sets[i], sets[j]))
        self.assertTrue(overlap(pin(1, 42).z_intervals(), pin(1, 42).z_intervals()))


def uncapped(pin: Decimal, rounds) -> Decimal:
    """The level before the pinning cap, for a cheapest pinning puzzle of `pin` bits."""
    return log2(_level(exp2(pin), rounds))


class Security(unittest.TestCase):
    def test_one_round_is_the_papers_formula(self):
        single = uncapped(Decimal(40), [(2 ** 40, Decimal(40))])
        self.assertAlmostEqual(float(single), 20 + math.log2(2 * 2 ** 40), places=9)  # section 4.6

    def test_two_rounds_are_the_papers_formula_with_abandoned_transactions(self):
        # Section 5.3 charges both rounds for every transaction. An attacker skips the second
        # round when the first has no solution, which happens with probability 1/e here.
        # Searching a little less than all of each round does slightly better still.
        got = uncapped(Decimal(40), [(2 ** 40, Decimal(40))] * 2)
        reached = 1 - math.exp(-1)
        paper = 40 + math.log2(2 ** 40 * (2 + reached))
        self.assertLessEqual(float(got), paper)
        self.assertAlmostEqual(float(got), paper, places=2)
        self.assertLess(got, 40 + math.log2(3 * 2 ** 40))

    def test_searching_part_of_an_oversized_round_helps_the_attacker(self):
        # Found by the first agent search, twice. A round with far more selections than its
        # puzzle needs seemed to make every transaction dear to search. An attacker who searches
        # the same 2^k selections in every transaction pays 2^k per transaction and loses only
        # the square root of the shrinkage in pairs.
        w = Decimal(40)
        rounds = [(2 ** 40, w), (2 ** 56, w)]
        reached = 1 - math.exp(-1)
        exhaustive = math.log2(2 ** 40 + 2 ** 40 + reached * 2 ** 56) + 40 - 20 + 40 - 28
        self.assertLess(float(log2(_restricted_birthday(exp2(w), rounds))), exhaustive - 5)
        # Two pool shapes the first board recorded above the old floor of 81.5.
        w5 = SizePuzzle(D_MIN, 55).bits
        for pools in (((120, 8), (172, 8)), ((116, 8), (128, 9))):
            level = uncapped(w5, [(math.comb(n, t), w5) for n, t in pools])
            self.assertLess(level, Decimal("81.1"), pools)

    def test_pinning_is_worth_no_more_than_two_of_its_puzzles(self):
        # Four pinning puzzles force four sighash modes only while one mode cannot serve two of
        # them. That is 2^(Wa + Wb) work, so no level above it is credited.
        rounds = [(2 ** 56, Decimal(56))] * 2
        self.assertEqual(security_bits([Decimal(40)] * 4, rounds), Decimal(80))
        self.assertEqual(security_bits([Decimal(48), Decimal(40), Decimal(48), Decimal(32)], rounds), Decimal(72))
        self.assertGreater(security_bits([Decimal(56)] * 4, rounds), Decimal(110))
        # Below the cap, the cheapest puzzle is what a fresh transaction costs.
        small = [(2 ** 40, Decimal(40))] * 2
        self.assertEqual(security_bits([Decimal(48)] * 4, small), uncapped(Decimal(48), small))

    def test_a_scarce_cheap_round_buys_nothing(self):
        # Found by the first parameter search: a 32-bit round with few selections next to a
        # plentiful 40-bit round. Every transaction seems to cost the big round's 2^47 selections,
        # but seven in eight are abandoned after the small round.
        rounds = [(math.comb(110, 11), Decimal(40)), (math.comb(88, 6), Decimal(32))]
        self.assertLess(security_bits(None, rounds), 73)

    def test_selections_beyond_the_puzzle_do_not_add_security(self):
        # Stored digests are tested on fresh transactions at one evaluation each, so without
        # pinning the level cannot pass the sum of the puzzles, however large a pool is.
        for e in (40, 46, 52, 60):
            level = security_bits(None, [(2 ** 40, Decimal(40)), (2 ** e, Decimal(40))])
            self.assertLess(level, 80.1)
        pinned = [uncapped(Decimal(40), [(2 ** 40, Decimal(40)), (2 ** e, Decimal(40))]) for e in (44, 52, 60, 70)]
        self.assertEqual(pinned, sorted(pinned, reverse=True))

    def test_published_configurations(self):
        w = SizePuzzle(D_MIN, 55).bits
        space = math.comb(120, 8)
        # The paper's standard configuration pins with 5-byte puzzles and sits on the cap.
        self.assertEqual(f"{uncapped(w, [(space, w)] * 2):.3f}", "81.521")
        self.assertEqual(f"{security_bits([w] * 4, [(space, w)] * 2):.3f}", "80.011")
        six = SizePuzzle(D_MIN, 54).bits
        self.assertEqual(f"{security_bits([six] * 4, [(space, w)] * 2):.3f}", "88.411")


class Work(unittest.TestCase):
    def test_compressions_per_attempt(self):
        self.assertEqual(blocks(0), 1)
        self.assertEqual(blocks(55), 1)
        self.assertEqual(blocks(56), 2)
        self.assertEqual(compressions(8203, 8200), 2)  # only the last block and the outer hash
        self.assertEqual(compressions(8203, 0), blocks(8203) + 1)

    def test_a_plentiful_round_costs_one_puzzle(self):
        work = honest_work([], [(2 ** 60, Decimal(40), 1)])
        self.assertAlmostEqual(float(work["bits"]), 40.0, places=6)
        self.assertAlmostEqual(float(work["rounds_solvable"]), 1.0, places=9)

    def test_a_retry_repeats_one_pinning_puzzle_not_four(self):
        pins = [(Decimal(40), 2), (Decimal(40), 3), (Decimal(40), 3), (Decimal(40), 3)]
        scarce = honest_work(pins, [(2 ** 39, Decimal(40), 9)] * 2)
        p = 1 - math.exp(-0.5)
        self.assertAlmostEqual(float(scarce["expected_tries"]), 1 / p ** 2, places=6)
        per_try = 3 + p * 9 + p * p * 9
        self.assertAlmostEqual(float(scarce["bits"]), 40 + math.log2(8 + per_try / p ** 2), places=6)
        plenty = honest_work(pins, [(2 ** 46, Decimal(40), 9)] * 2)
        self.assertAlmostEqual(float(plenty["bits"]), 40 + math.log2(11 + 18), places=3)

    def test_the_cheaper_round_is_searched_first(self):
        work = honest_work([], [(2 ** 39, Decimal(40), 71), (2 ** 39, Decimal(40), 9)])
        self.assertEqual(work["round_order"], [1, 0])


if __name__ == "__main__":
    unittest.main()
