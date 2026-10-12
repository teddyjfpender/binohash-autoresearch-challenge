# References

## The construction

- R. Linus, *Binohash: Transaction Introspection Without Softforks*, 2026.
  <https://robinlinus.com/binohash.pdf>. Discussion:
  <https://delvingbitcoin.org/t/binohash-transaction-introspection-without-softforks/2288>.
  The construction, its parameters and its security accounting. Sections cited in this
  repository refer to this document. Published figures used as targets: about 199 opcodes and
  8,028 bytes of locking script for two rounds of 120-choose-8; about 84 bits of collision
  resistance for 44.6 bits of honest work at W1 = W2 = 42; about 92 and 52.6 at 6-byte pinning;
  measured 320 MH/s on ten RTX 4090 for the round search.
- L. Reyzin and N. Reyzin, *Better than BiBa: Short One-Time Signatures with Fast Signing and
  Verifying*, ACISP 2002. The subset one-time signature the commitments implement.
- N. Heninger, T. Scholl and D. Shumow, Crypto 2019 rump session: the point `(1/2)G` and its
  21-byte x-coordinate, the `r_min` every size puzzle here relies on.
- P. Todd, *SIGHASH_SINGLE bug*, 2013. <https://bitcointalk.org/index.php?topic=260595.0>.
- BIP 66 (strict DER), BIP 143 (which removed FindAndDelete for SegWit), BIP 147 (NULLDUMMY),
  BIP 54 (which leaves FindAndDelete consensus-valid).

## Related constructions

- E. Heilman, *Signing a Bitcoin Transaction with Lamport Signatures (no OP_CAT)*, bitcoin-dev,
  2024. The earlier signature-size approach.
- A. Borco, *Bitcoin PoW-locked outputs*, 2024. <https://github.com/adambor/btc-pow-locked-outputs>.
  Signature-size proof of work, including difficulty finer than one byte.
- A. M. Levy, *Quantum-Safe Bitcoin Transactions Without Softforks* (QSB), 2026. Replaces the size puzzle by a hash-to-signature
  puzzle that does not rest on assumption A1; outside this challenge's contract.

## Reproductions and tooling

- solving-bitcoin, *bitcoin-scripts*: a library and knowledge base of Bitcoin Script
  primitives. <https://github.com/solving-bitcoin/bitcoin-scripts>. Its
  `src/introspection/binohash.rs` reproduces the deterministic core (FindAndDelete at opcode
  boundaries followed by the legacy sighash); its open problem OP-011 asks for the full
  protocol. This repository's evidence vocabulary and cost boundaries follow its
  `knowledge/evidence.md` and `knowledge/cost-model.md` ([CONVENTIONS.md](CONVENTIONS.md)).
- aaron-recompile, *binohash-experiments*. <https://github.com/aaron-recompile/binohash-experiments>.
- Bitcoin Core's consensus library, through the Rust crate `bitcoinconsensus` 0.106.0+26.0
  (`tools/core`).
