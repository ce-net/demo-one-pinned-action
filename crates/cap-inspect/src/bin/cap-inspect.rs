//! `cap-inspect <chain.hex|-> --root <ed25519:hex|hex> [--now <unix>] [--cal]`
//!
//! Decodes a cap v3 chain, prints every link, runs the verifier's checks one by one with
//! `verify_chain_v3` last, and with `--cal` prints the chain as CAL source. Exit 0 = valid,
//! 1 = refused (the reason is printed), 2 = usage.

use std::io::Read;
use std::process::ExitCode;

use cap_inspect::{cal, inspect, trace, utc, Pins};
use ce_net_proto::v3::{Key, TokenV3};

fn usage() -> ExitCode {
    eprintln!("usage: cap-inspect <chain.hex|-> --root <ed25519:hex> [--now <unix-secs>] [--cal]");
    ExitCode::from(2)
}

fn main() -> ExitCode {
    let a: Vec<String> = std::env::args().skip(1).collect();
    let Some(src) = a.first() else { return usage() };
    let mut root = None;
    let mut now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0);
    let mut show_cal = false;
    let mut i = 1;
    while i < a.len() {
        match a[i].as_str() {
            "--root" => {
                i += 1;
                let h = a.get(i).map(|s| s.trim_start_matches("ed25519:").to_string()).unwrap_or_default();
                match hex::decode(&h).ok().and_then(|b| <[u8; 32]>::try_from(b).ok()) {
                    Some(k) => root = Some(Key::Ed25519(k)),
                    None => return usage(),
                }
            }
            "--now" => {
                i += 1;
                match a.get(i).and_then(|s| s.parse().ok()) {
                    Some(n) => now = n,
                    None => return usage(),
                }
            }
            "--cal" => show_cal = true,
            _ => return usage(),
        }
        i += 1;
    }
    let Some(root) = root else { return usage() };
    let text = if src == "-" {
        let mut s = String::new();
        let _ = std::io::stdin().read_to_string(&mut s);
        s
    } else {
        match std::fs::read_to_string(src) {
            Ok(s) => s,
            Err(e) => {
                eprintln!("{src}: {e}");
                return ExitCode::from(2);
            }
        }
    };
    let t = match TokenV3::from_hex(text.trim()) {
        Ok(t) => t,
        Err(e) => {
            println!("REFUSED decode: {e}");
            return ExitCode::from(1);
        }
    };
    let names = |k: &Key| (k == &root).then(|| "root".to_string());
    let v = inspect(&t, &names);
    println!("chain: {} bytes, {} link(s), checked at {}", v.bytes, v.links.len(), utc(now));
    for l in &v.links {
        println!("  link {}: {} -> {}  allow [{}]  {}  until {}", l.index, l.issuer, l.audience, l.abilities.join(", "), l.resource, if l.not_after == 0 { "-".into() } else { utc(l.not_after) });
        for c in &l.caveats {
            println!("          {c}");
        }
        if let Some(d) = &l.delegate {
            println!("          may grant {d}");
        }
    }
    let (checks, verdict) = trace(&t, &[root], now);
    println!("trace:");
    for c in &checks {
        println!("  [{}] {}: {}", if c.ok { " ok " } else { "FAIL" }, c.check, c.detail);
    }
    if show_cal {
        println!("--- CAL ---\n{}", cal(&t, &names, &Pins::default()).source);
    }
    match verdict {
        Ok(()) => {
            println!("VALID");
            ExitCode::SUCCESS
        }
        Err(e) => {
            println!("REFUSED {e}");
            ExitCode::from(1)
        }
    }
}
