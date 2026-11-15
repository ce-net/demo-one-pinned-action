//! The demo door: a key that can do exactly one thing, and six tries to make it do more.
//!
//! [`Door::mint`] has the shape of `wire.ws-door` Mint (`page, ttl_s -> link, not_after,
//! browser_key`, the grant in the link's `#g=<seed>.<chain>` fragment) and mints a two-link cap v3
//! chain: the board owner grants the door "may grant `board.append:Append`", and the door grants a
//! fresh browser key one use of one program step: `Append` of one exact request body (this line,
//! `board.append@1`, this board build) on this node, for at most ten minutes.
//!
//! An attempt is two calls. [`Door::prepare`] builds what the attempt asks for (a call, or a child
//! link) and returns the exact bytes the holder must sign; the browser signs them with its key, and
//! [`Door::finish`] runs the real checks: `authorize_v3` at the board for a call, the minter's
//! `check_child` and then `verify_chain_v3` for a link. Refusals are the library's own words, and
//! [`cap_inspect::blame`] names the CAL clause they come from.

use std::collections::HashMap;
use std::io::Read;
use std::path::Path;

use base64::Engine;
use board_append::{Board, build_id, call_step};
use board_append_api::{AppendBody, Entry, OP_APPEND, OP_DELETE, line_ok};
use cap_inspect::{Cal, Check, Pins, blame, cal, key_str, trace};
use ce_net_proto::cap::Caveats;
use ce_net_proto::program::{Program, ResourceV3, Step};
use ce_net_proto::v3::mint::{Grant, extend, root_token};
use ce_net_proto::v3::narrow::{Parent, check_child};
use ce_net_proto::v3::sign::{Signer, verify_bytes};
use ce_net_proto::v3::{AudienceSet, Caveat, CapabilityV3, Delegate, Key, Link, Sig, TokenV3, UsePer, cap_bytes};
use serde::Serialize;
use sha2::{Digest, Sha256};

pub const ABILITY: &str = "board.append:Append";
pub const MIN_TTL: u32 = 60;
pub const MAX_TTL: u32 = 600;
/// The repository file whose hash is the board build.
pub const BUILD_REF: &str = "repo:demo-one-pinned-action/crates/board-append/src/lib.rs";
/// Domain of the bytes a holder signs to make a call.
pub const CALL_DOMAIN: &[u8] = b"one-action-call-v1";

pub fn random32() -> [u8; 32] {
    let mut b = [0u8; 32];
    std::fs::File::open("/dev/urandom").and_then(|mut f| f.read_exact(&mut b)).expect("/dev/urandom");
    b
}

fn nonce() -> u64 {
    u64::from_le_bytes(random32()[..8].try_into().unwrap())
}

pub fn b64u(b: &[u8]) -> String {
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(b)
}

fn load_seed(p: &Path) -> Result<[u8; 32], String> {
    if let Ok(s) = std::fs::read_to_string(p) {
        return hex::decode(s.trim()).ok().and_then(|b| b.try_into().ok()).ok_or_else(|| format!("{}: not a 32-byte hex seed", p.display()));
    }
    let s = random32();
    std::fs::write(p, hex::encode(s)).map_err(|e| format!("{}: {e}", p.display()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(p, std::fs::Permissions::from_mode(0o600));
    }
    Ok(s)
}

/// The six things a viewer can try.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Attempt {
    /// The one thing the key allows.
    Append,
    /// Same body, op `Delete`.
    OtherOp,
    /// Same op and line, but the board named only as `cell:board.append@1`: no build pin.
    Unpinned,
    /// A child link that lives 30 days instead of minutes.
    LongerTtl,
    /// A child link that grants `board.append:*`.
    Wider,
    /// The allowed call again, after it was used.
    Replay,
    /// Append, but a different line.
    OtherLine,
}

impl Attempt {
    pub fn parse(s: &str) -> Option<Attempt> {
        Some(match s {
            "append" => Attempt::Append,
            "other-op" => Attempt::OtherOp,
            "unpinned" => Attempt::Unpinned,
            "longer-ttl" => Attempt::LongerTtl,
            "wider" => Attempt::Wider,
            "replay" => Attempt::Replay,
            "other-line" => Attempt::OtherLine,
            _ => return None,
        })
    }

    pub fn name(&self) -> &'static str {
        match self {
            Attempt::Append => "append",
            Attempt::OtherOp => "other-op",
            Attempt::Unpinned => "unpinned",
            Attempt::LongerTtl => "longer-ttl",
            Attempt::Wider => "wider",
            Attempt::Replay => "replay",
            Attempt::OtherLine => "other-line",
        }
    }

    fn is_link(&self) -> bool {
        matches!(self, Attempt::LongerTtl | Attempt::Wider)
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct Minted {
    /// `<page>#g=<seed>.<chain>`, as wire.ws-door Mint returns it.
    pub link: String,
    pub not_after: u64,
    pub browser_key: String,
    pub chain_hex: String,
    pub fingerprint: String,
    pub root: String,
    pub cal: Cal,
    pub line: String,
}

/// What the holder is asked to sign.
#[derive(Debug, Clone, Serialize)]
pub struct Prepared {
    pub draft: String,
    /// Hex of the exact bytes to sign with the browser key.
    pub sign_hex: String,
    /// What is being asked, in words.
    pub asks: String,
    /// For a link attempt: the minter's refusal (`check_child`, run before any signature).
    pub minter: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct Outcome {
    pub attempt: &'static str,
    pub allowed: bool,
    /// `authorize_v3`, `verify_chain_v3`, `board` or `door` (signature on the call).
    pub by: String,
    pub error: Option<String>,
    pub minter: Option<String>,
    /// The CAL clause the refusal comes from, and its line in the chain's CAL source.
    pub clause: Option<String>,
    pub clause_line: Option<usize>,
    pub cal: Cal,
    pub trace: Vec<Check>,
    pub entry: Option<Entry>,
    /// The chain that was judged (for a link attempt, the forged longer chain) to re-check offline.
    pub chain_hex: String,
    pub asks: String,
}

struct Draft {
    at: u64,
    attempt: Attempt,
    token: TokenV3,
    holder: Key,
    sign: Vec<u8>,
    asks: String,
    /// Call attempts.
    op: String,
    body: Option<AppendBody>,
    run: u32,
    /// Link attempts.
    child: Option<CapabilityV3>,
    minter: Option<String>,
}

pub struct Door {
    owner: Signer,
    door: Signer,
    board: Board,
    drafts: HashMap<String, Draft>,
    /// Lines minted, by request hash: printed beside the pinned hash in CAL.
    bodies: HashMap<[u8; 32], String>,
    mints: Vec<u64>,
}

impl Door {
    /// Keys and board under `dir`: `owner.key` (the board owner, the chain's root, and this node's
    /// id), `door.key`, `board/`.
    pub fn open(dir: &Path) -> Result<Door, String> {
        std::fs::create_dir_all(dir).map_err(|e| format!("{}: {e}", dir.display()))?;
        let owner = Signer::ed25519(&load_seed(&dir.join("owner.key"))?);
        let door = Signer::ed25519(&load_seed(&dir.join("door.key"))?);
        let Key::Ed25519(node) = owner.key() else { unreachable!() };
        let board = Board::open(&dir.join("board"), node)?;
        Ok(Door { owner, door, board, drafts: HashMap::new(), bodies: HashMap::new(), mints: Vec::new() })
    }

    pub fn root(&self) -> Key {
        self.owner.key()
    }

    pub fn entries(&self) -> Vec<Entry> {
        self.board.entries()
    }

    fn names(&self, t: &TokenV3) -> impl Fn(&Key) -> Option<String> + use<> {
        let owner = self.owner.key();
        let door = self.door.key();
        let you = match t.links.get(1) {
            Some(Link::V3 { cap, .. }) => Some(cap.audience),
            _ => None,
        };
        move |k: &Key| {
            if *k == owner {
                Some("board owner (root)".into())
            } else if *k == door {
                Some("ws-door".into())
            } else if Some(*k) == you {
                Some("you".into())
            } else {
                Some("a friend".into())
            }
        }
    }

    pub fn cal_of(&self, t: &TokenV3) -> Cal {
        let names = self.names(t);
        let pins = Pins { bodies: self.bodies.iter().map(|(h, b)| (*h, b.clone())).collect(), build: Some((BUILD_REF.into(), build_id())) };
        cal(t, &names, &pins)
    }

    /// Mint one key for one line: wire.ws-door Mint, the one-action profile.
    pub fn mint(&mut self, page: &str, line: &str, ttl_s: u32, now: u64) -> Result<Minted, String> {
        if !(MIN_TTL..=MAX_TTL).contains(&ttl_s) {
            return Err(format!("ttl_s {ttl_s} not in {MIN_TTL}..={MAX_TTL}"));
        }
        if !(page.starts_with("https://") || page.starts_with("http://")) || page.contains('#') {
            return Err("page must be an http(s) URL without a fragment".into());
        }
        line_ok(line)?;
        self.mints.retain(|t| now < t + 60);
        if self.mints.len() >= 60 {
            return Err("too many keys this minute; try again in a minute".into());
        }
        self.mints.push(now);
        let seed = random32();
        let browser = Signer::ed25519(&seed);
        let node = self.board.node();
        let body = AppendBody::new(&build_id(), line);
        let program = Program::new(vec![call_step(&node, OP_APPEND, &body)]);
        let resource = ResourceV3::Node(node);
        let delegate = |depth| Some(Delegate { abilities: vec![ABILITY.into()], audience: AudienceSet::Any, depth });
        let root = Grant {
            audience: self.door.key(),
            abilities: vec![],
            resource: resource.clone(),
            caveats: Caveats { not_after: now + ttl_s as u64 + 60, ..Caveats::default() },
            ext: vec![],
            delegate: delegate(2),
            nonce: nonce(),
        };
        let leaf = Grant {
            audience: browser.key(),
            abilities: vec![ABILITY.into()],
            resource,
            caveats: Caveats { not_after: now + ttl_s as u64, ..Caveats::default() },
            ext: vec![Caveat::Uses { max: 1, per: UsePer::Link }, Caveat::Programs(vec![program.id()])],
            delegate: delegate(1),
            nonce: nonce(),
        };
        let mut t = extend(&root_token(&self.owner, root).map_err(|e| e.0)?, &self.door, leaf).map_err(|e| e.0)?;
        t.programs = vec![program];
        let bytes = t.encode();
        self.bodies.insert(body.sha256(), String::from_utf8_lossy(&body.bytes()).into_owned());
        if self.bodies.len() > 10_000 {
            self.bodies.clear();
        }
        Ok(Minted {
            link: format!("{page}#g={}.{}", b64u(&seed), b64u(&bytes)),
            not_after: now + ttl_s as u64,
            browser_key: key_str(&browser.key()),
            chain_hex: t.to_hex(),
            fingerprint: board_append_api::fingerprint(&bytes),
            root: key_str(&self.owner.key()),
            cal: self.cal_of(&t),
            line: line.into(),
        })
    }

    /// Build the attempt and the bytes the holder signs.
    pub fn prepare(&mut self, attempt: Attempt, chain_hex: &str, line: &str, now: u64) -> Result<Prepared, String> {
        self.drafts.retain(|_, d| now < d.at + 300);
        if self.drafts.len() > 20_000 {
            return Err("busy; try again".into());
        }
        let t = TokenV3::from_hex(chain_hex.trim()).map_err(|e| e.0)?;
        let Some(Link::V3 { cap: leaf, .. }) = t.links.last() else { return Err("the chain has no v3 leaf".into()) };
        let holder = leaf.audience;
        let id = hex::encode(&random32()[..12]);
        let fp = Sha256::digest(t.encode());
        let mut d = Draft { at: now, attempt, token: t.clone(), holder, sign: vec![], asks: String::new(), op: OP_APPEND.into(), body: None, run: 0, child: None, minter: None };
        if attempt.is_link() {
            let mut child = leaf.clone();
            child.issuer = holder;
            child.audience = Key::Ed25519(random32());
            child.parent = Some(t.links.last().unwrap().id());
            child.nonce = nonce();
            child.delegate = None;
            match attempt {
                Attempt::LongerTtl => {
                    child.caveats.not_after = leaf.caveats.not_after + 30 * 86_400;
                    d.asks = format!("Give a friend this key, valid until {} instead of {}.", cap_inspect::utc(child.caveats.not_after), cap_inspect::utc(leaf.caveats.not_after));
                }
                _ => {
                    child.abilities = vec!["board.append:*".into()];
                    d.asks = "Give a friend board.append:* (every op on the board) instead of board.append:Append.".into();
                }
            }
            d.minter = check_child(&child, &Parent::of(t.links.last().unwrap())).err().map(|e| format!("refusing to mint: {e}"));
            d.sign = cap_bytes(&child);
            d.child = Some(child);
        } else {
            line_ok(line)?;
            let (op, body, run, asks): (&str, AppendBody, u32, String) = match attempt {
                Attempt::Append => (OP_APPEND, AppendBody::new(&build_id(), line), 0, format!("Append \"{line}\" to board.append@1 (pinned build).")),
                Attempt::OtherOp => (OP_DELETE, AppendBody::new(&build_id(), line), 0, "Call Delete on the board instead of Append.".to_string()),
                Attempt::Unpinned => (OP_APPEND, AppendBody::new("", line), 0, "Call cell:board.append@1 by name, without the build pin (whatever version is deployed).".to_string()),
                Attempt::OtherLine => {
                    let other = format!("{} (edited)", line.chars().take(120).collect::<String>());
                    let a = format!("Append a different line: \"{other}\".");
                    (OP_APPEND, AppendBody::new(&build_id(), &other), 0, a)
                }
                _ => (OP_APPEND, AppendBody::new(&build_id(), line), 1, format!("Append \"{line}\" again: a second use of the same key.")),
            };
            let mut m = Vec::new();
            m.extend_from_slice(&(CALL_DOMAIN.len() as u64).to_le_bytes());
            m.extend_from_slice(CALL_DOMAIN);
            m.extend_from_slice(&fp);
            m.extend_from_slice(&Sha256::digest(op.as_bytes()));
            m.extend_from_slice(&body.sha256());
            m.extend_from_slice(&run.to_le_bytes());
            m.extend_from_slice(id.as_bytes());
            d.sign = m;
            d.op = op.into();
            d.body = Some(body);
            d.run = run;
            d.asks = asks;
        }
        let p = Prepared { draft: id.clone(), sign_hex: hex::encode(&d.sign), asks: d.asks.clone(), minter: d.minter.clone() };
        self.drafts.insert(id, d);
        Ok(p)
    }

    /// Run the attempt with the holder's signature over the prepared bytes.
    pub fn finish(&mut self, draft: &str, sig_hex: &str, now: u64) -> Result<Outcome, String> {
        let d = self.drafts.remove(draft).ok_or("unknown or expired attempt; prepare it again")?;
        let sig: [u8; 64] = hex::decode(sig_hex.trim()).ok().and_then(|b| b.try_into().ok()).ok_or("signature must be 64 bytes of hex")?;
        let sig = Sig::Ed25519(sig);
        let roots = [self.owner.key()];
        let mut o = Outcome {
            attempt: d.attempt.name(),
            allowed: false,
            by: String::new(),
            error: None,
            minter: d.minter.clone(),
            clause: None,
            clause_line: None,
            cal: self.cal_of(&d.token),
            trace: vec![],
            entry: None,
            chain_hex: d.token.to_hex(),
            asks: d.asks.clone(),
        };
        if let Some(child) = d.child {
            // A holder that ignores the minter signs the wider link by hand; the verifier decides.
            let mut forged = d.token.clone();
            forged.links.push(Link::V3 { cap: child, sig });
            let (checks, verdict) = trace(&forged, &roots, now);
            o.trace = checks;
            o.chain_hex = forged.to_hex();
            o.cal = self.cal_of(&forged);
            o.by = "verify_chain_v3".into();
            match verdict {
                Ok(()) => o.allowed = true,
                Err(e) => {
                    o.clause = Some(blame(&e, &forged, None, None));
                    o.error = Some(e);
                }
            }
        } else {
            let (checks, _) = trace(&d.token, &roots, now);
            o.trace = checks;
            let body = d.body.expect("a call draft has a body");
            if let Err(e) = verify_bytes(&d.holder, &d.sign, &sig) {
                o.by = "door".into();
                o.error = Some(format!("the call is not signed by the chain's holder ({e})"));
                o.clause = Some("link1.to".into());
            } else {
                let asked = call_step(&self.board.node(), &d.op, &body);
                let granted: Option<Step> = d.token.programs.first().and_then(|p| p.steps.first().cloned());
                match self.board.call(&roots, now, &d.holder, &d.op, &body, d.run, &d.token) {
                    Ok(e) => {
                        o.allowed = true;
                        o.by = "authorize_v3".into();
                        o.entry = Some(e);
                        o.trace.push(Check { check: "authorize_v3 at the board".into(), ok: true, detail: "authorized; the use is burned".into() });
                    }
                    Err(r) => {
                        o.by = r.by.into();
                        let mut c = blame(&r.error, &d.token, Some(&asked), granted.as_ref());
                        if c == "program.request" && body.build != build_id() {
                            c = "pin.build".into();
                        }
                        o.clause = Some(c);
                        o.trace.push(Check { check: "authorize_v3 at the board".into(), ok: r.by != "authorize_v3", detail: if r.by == "authorize_v3" { r.error.clone() } else { "authorized".into() } });
                        if r.by == "board" {
                            o.trace.push(Check { check: "board.append@1 own checks".into(), ok: false, detail: r.error.clone() });
                        }
                        o.error = Some(r.error);
                    }
                }
            }
        }
        o.clause_line = o.clause.as_ref().and_then(|c| o.cal.clauses.iter().find(|x| &x.id == c).map(|x| x.line));
        Ok(o)
    }
}
