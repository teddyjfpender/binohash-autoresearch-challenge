# Core comparison

`cchk` replays spends through Bitcoin Core's own script interpreter, as packaged in the
`bitcoinconsensus` crate, pinned in `Cargo.lock` to the consensus library of Bitcoin Core 26.0
(libbitcoinconsensus). The evaluator's reference engine is an independent Python implementation of the
same rules; this tool is how the two are compared.

```sh
cargo build --release --locked --manifest-path tools/core/Cargo.toml
./benchmark.sh --stage screen --core tools/core/target/release/cchk
```

With `--core`, the evaluator hands Core every spend of its first lanes: the honest spend and
several altered ones, each with the verdict the reference engine reached with real signature
verification. Any disagreement rejects the run, as a fault of the evaluator and not of the
instance. A row's `engine` column then reads `reference-<lanes>+core-<spends>`.

What this shows: for those spends the reference engine and Core agree. What it does not show:
that they agree on every script. It is not a regtest of a funded transaction, and it says
nothing about relay policy; Binohash spends are non-standard and need a miner that accepts them
(Binohash, section 8.2).
