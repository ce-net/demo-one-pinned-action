//! The demo end to end, as the page drives it: mint a key for one line, then every attempt, signed
//! by the browser key from the link fragment. Only the first append passes; each widening is
//! refused by the verifier with the CAL clause it comes from.

use base64::Engine;
use ce_net_proto::v3::sign::Signer;
use ce_net_proto::v3::Sig;
use one_action_door::{Attempt, Door, Outcome};

fn seed_of(link: &str) -> [u8; 32] {
    let g = link.split("#g=").nth(1).unwrap();
    let s = g.split('.').next().unwrap();
    base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(s).unwrap().try_into().unwrap()
}

fn run(door: &mut Door, key: &Signer, a: Attempt, chain: &str, line: &str, now: u64) -> Outcome {
    let p = door.prepare(a, chain, line, now).unwrap();
    let Sig::Ed25519(sig) = key.sign_bytes(&hex::decode(&p.sign_hex).unwrap()) else { panic!() };
    let o = door.finish(&p.draft, &hex::encode(sig), now).unwrap();
    println!("{:<11} allowed={} by={} clause={:?} line={:?}\n            error={:?}\n            minter={:?}", o.attempt, o.allowed, o.by, o.clause, o.clause_line, o.error, o.minter);
    o
}

#[test]
fn exactly_one_action() {
    let dir = std::env::temp_dir().join(format!("one-action-test-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    let mut door = Door::open(&dir).unwrap();
    let now = 1_800_000_000;
    let line = "hello from a stranger";
    let m = door.mint("https://ce-net.com/demos/one-action/", line, 600, now).unwrap();
    println!("{}", m.cal.source);
    let key = Signer::ed25519(&seed_of(&m.link));
    let chain = &m.chain_hex;

    let o = run(&mut door, &key, Attempt::OtherOp, chain, line, now);
    assert!(!o.allowed);
    assert_eq!(o.clause.as_deref(), Some("program.op"));
    assert!(o.error.unwrap().contains("is not program step 0"));

    let o = run(&mut door, &key, Attempt::Unpinned, chain, line, now);
    assert!(!o.allowed);
    assert_eq!(o.clause.as_deref(), Some("pin.build"));

    let o = run(&mut door, &key, Attempt::OtherLine, chain, line, now);
    assert!(!o.allowed);
    assert_eq!(o.clause.as_deref(), Some("program.request"));

    let o = run(&mut door, &key, Attempt::LongerTtl, chain, line, now);
    assert!(!o.allowed);
    assert_eq!(o.clause.as_deref(), Some("link1.until"));
    assert!(o.error.unwrap().contains("caveats are broader than the parent"));
    assert!(o.minter.unwrap().contains("caveats are broader"));

    let o = run(&mut door, &key, Attempt::Wider, chain, line, now);
    assert!(!o.allowed);
    assert_eq!(o.clause.as_deref(), Some("link1.delegate"));
    assert!(o.error.unwrap().contains("abilities exceed the parent's grant"));

    // Nothing above spent the use: the one allowed action still lands.
    let o = run(&mut door, &key, Attempt::Append, chain, line, now);
    assert!(o.allowed, "{:?}", o.error);
    let e = o.entry.unwrap();
    assert_eq!(e.line, line);
    assert_eq!(e.fingerprint, m.fingerprint);

    let o = run(&mut door, &key, Attempt::Replay, chain, line, now + 1);
    assert!(!o.allowed);
    assert_eq!(o.clause.as_deref(), Some("link1.uses"));
    assert!(o.error.unwrap().contains("used up"));

    // A stranger's key cannot use the chain at all.
    let thief = Signer::ed25519(&[7; 32]);
    let p = door.prepare(Attempt::Append, chain, line, now).unwrap();
    let Sig::Ed25519(sig) = thief.sign_bytes(&hex::decode(&p.sign_hex).unwrap()) else { panic!() };
    let o = door.finish(&p.draft, &hex::encode(sig), now).unwrap();
    assert!(!o.allowed && o.by == "door");

    // After expiry the allowed call is refused by time.
    let m2 = door.mint("https://ce-net.com/demos/one-action/", "late", 60, now).unwrap();
    let k2 = Signer::ed25519(&seed_of(&m2.link));
    let o = run(&mut door, &k2, Attempt::Append, &m2.chain_hex, "late", now + 120);
    assert!(!o.allowed);
    assert_eq!(o.clause.as_deref(), Some("link1.until"));

    assert_eq!(door.entries().len(), 1);
    let _ = std::fs::remove_dir_all(&dir);
}
