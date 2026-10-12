//! Replays spends through Bitcoin Core's script interpreter (libbitcoinconsensus).
//!
//! Reads lines `name locking_script_hex spending_tx_hex input_index expected(0|1)` on standard
//! input and prints one line per spend: `PASS` when Core's verdict equals the expected one,
//! `FAIL` otherwise. The last line is `unexpected results: N`; the exit status is 0 only when N
//! is 0 and every line parsed. The flags are the consensus rules for a pre-Taproot script:
//! P2SH, strict DER, NULLDUMMY, CHECKLOCKTIMEVERIFY, CHECKSEQUENCEVERIFY and witness.
use bitcoinconsensus::{verify_with_flags, VERIFY_ALL_PRE_TAPROOT};
use std::io::{self, BufRead};

fn main() {
    let mut bad = 0usize;
    let mut seen = 0usize;
    for line in io::stdin().lock().lines() {
        let line = line.expect("readable input");
        let fields: Vec<&str> = line.split_whitespace().collect();
        if fields.is_empty() {
            continue;
        }
        seen += 1;
        let parsed = (|| {
            if fields.len() != 5 {
                return None;
            }
            let locking = hex::decode(fields[1]).ok()?;
            let spend = hex::decode(fields[2]).ok()?;
            let index: usize = fields[3].parse().ok()?;
            let expected = match fields[4] {
                "1" => true,
                "0" => false,
                _ => return None,
            };
            Some((locking, spend, index, expected))
        })();
        let Some((locking, spend, index, expected)) = parsed else {
            bad += 1;
            println!("FAIL {} unreadable line", fields[0]);
            continue;
        };
        let verdict = verify_with_flags(&locking, 0, &spend, None, index, VERIFY_ALL_PRE_TAPROOT);
        let valid = verdict.is_ok();
        if valid != expected {
            bad += 1;
        }
        println!(
            "{} {} core={}",
            if valid == expected { "PASS" } else { "FAIL" },
            fields[0],
            if valid { "VALID".to_string() } else { format!("INVALID({:?})", verdict.err().unwrap()) }
        );
    }
    println!("spends: {}", seen);
    println!("unexpected results: {}", bad);
    std::process::exit(if bad == 0 { 0 } else { 1 });
}
