//! `board.append@1`: the cell. A board is a file of lines; a line lands only when a cap v3 chain
//! authorizes this exact call at this node (`authorize_v3`: chain, resource, holder, program step,
//! then the counted-use burn log). Nothing here interprets the chain on its own: every refusal is
//! the verifier's.
//!
//! The build id is the SHA-256 of this file. A capability pins it inside the request it binds, so
//! a chain minted for this build is refused by any other build of the board, and the board refuses
//! a request that names another build.

use std::collections::HashSet;
use std::fs::OpenOptions;
use std::io::{BufRead, Write};
use std::path::{Path, PathBuf};

use board_append_api::{API, AppendBody, Entry, OP_APPEND, fingerprint, line_ok};
use ce_net_proto::program::{Hash, NodeKey, Step};
use ce_net_proto::v3::authorize::{Charge, Request, authorize_v3};
use ce_net_proto::v3::uses::BurnLog;
use ce_net_proto::v3::verify::{Node, Roots};
use ce_net_proto::v3::{Key, TokenV3};
use sha2::{Digest, Sha256};

/// This cell's source, hashed: the exact version a capability pins.
pub const SOURCE: &str = include_str!("lib.rs");

/// `sha256:<hex>` of [`SOURCE`].
pub fn build_id() -> String {
    format!("sha256:{}", hex::encode(Sha256::digest(SOURCE.as_bytes())))
}

/// The step a call is, as a program names it.
pub fn call_step(node: &NodeKey, op: &str, body: &AppendBody) -> Step {
    Step::Call { on: *node, api: API.into(), op: op.into(), req_sha256: body.sha256() }
}

/// A refusal: which check said no, and its exact words.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Refusal {
    /// `authorize_v3` (the verifier) or `board` (this cell's own check after the gate).
    pub by: &'static str,
    pub error: String,
}

pub struct Board {
    node: NodeKey,
    dir: PathBuf,
    burn: BurnLog,
    /// `(leaf, program, run)` already executed (CAPABILITY-PROGRAMS 6.4 rule 4).
    runs: HashSet<(Hash, Hash, u32)>,
}

impl Board {
    /// Open the board kept in `dir` for node `node`.
    pub fn open(dir: &Path, node: NodeKey) -> Result<Board, String> {
        std::fs::create_dir_all(dir).map_err(|e| format!("board dir: {e}"))?;
        let burn = BurnLog::open(&dir.join("uses.log"))?;
        let mut runs = HashSet::new();
        if let Ok(f) = std::fs::File::open(dir.join("runs.log")) {
            for l in std::io::BufReader::new(f).lines().map_while(Result::ok) {
                let b = hex::decode(l.trim()).unwrap_or_default();
                if b.len() == 68 {
                    let run = u32::from_le_bytes(b[64..68].try_into().unwrap());
                    runs.insert((b[..32].try_into().unwrap(), b[32..64].try_into().unwrap(), run));
                }
            }
        }
        Ok(Board { node, dir: dir.into(), burn, runs })
    }

    pub fn node(&self) -> NodeKey {
        self.node
    }

    /// Every line, oldest first.
    pub fn entries(&self) -> Vec<Entry> {
        let Ok(f) = std::fs::File::open(self.dir.join("board.jsonl")) else { return Vec::new() };
        std::io::BufReader::new(f).lines().map_while(Result::ok).filter_map(|l| serde_json::from_str(&l).ok()).collect()
    }

    /// One call of `op` with `body`, run `run` of the chain's program, by `requester` (the key
    /// that signed this call), under chain `t`. The gate is `authorize_v3`; only after it passes
    /// does the board look at the body.
    #[allow(clippy::too_many_arguments)]
    pub fn call(&mut self, roots: &[Key], now: u64, requester: &Key, op: &str, body: &AppendBody, run: u32, t: &TokenV3) -> Result<Entry, Refusal> {
        let gate = |e: String| Refusal { by: "authorize_v3", error: e };
        let program = t.programs.first().map(|p| p.id()).ok_or_else(|| gate("the token carries no program body".into()))?;
        let req = call_step(&self.node, op, body);
        let node = Node { id: self.node, tags: &[], host: None };
        let roots = Roots { keys: roots, owners: &[] };
        let runs = &mut self.runs;
        let burn = &mut self.burn;
        let dir = &self.dir;
        let self_id = self.node;
        let mut charge = |c: &Charge| -> Result<(), String> {
            let key = (c.leaf, c.program.map(|p| p.0).unwrap_or([0; 32]), c.program.map(|p| p.1).unwrap_or(0));
            if runs.contains(&key) {
                return Err("this step already ran in this run".into());
            }
            burn.charge(&self_id, now, c)?;
            runs.insert(key);
            let mut rec = Vec::with_capacity(68);
            rec.extend_from_slice(&key.0);
            rec.extend_from_slice(&key.1);
            rec.extend_from_slice(&key.2.to_le_bytes());
            let _ = append_line(&dir.join("runs.log"), &hex::encode(rec));
            Ok(())
        };
        let v = authorize_v3(&node, &roots, now, requester, &Request::Execute { program, run, step: 0, req: &req }, t, &|_, _| false, &mut charge).map_err(gate)?;
        // The gate passed. The board's own checks: it has one op for strangers, and one build.
        let own = |e: String| Refusal { by: "board", error: e };
        if op != OP_APPEND {
            return Err(own(format!("board.append has no op {op} for a capability holder")));
        }
        if body.build != build_id() {
            return Err(own(format!("this board is build {}, the request names {}", build_id(), body.build)));
        }
        line_ok(&body.line).map_err(own)?;
        let holder = match v.holder {
            Key::Ed25519(k) => format!("ed25519:{}", hex::encode(k)),
            Key::P256(k) => format!("p256:{}", hex::encode(k)),
        };
        let e = Entry { at: now, line: body.line.clone(), fingerprint: fingerprint(&t.encode()), holder, build: build_id() };
        append_line(&self.dir.join("board.jsonl"), &serde_json::to_string(&e).unwrap()).map_err(own)?;
        Ok(e)
    }
}

fn append_line(p: &Path, s: &str) -> Result<(), String> {
    let mut f = OpenOptions::new().create(true).append(true).open(p).map_err(|e| format!("{}: {e}", p.display()))?;
    writeln!(f, "{s}").and_then(|_| f.sync_data()).map_err(|e| format!("{}: {e}", p.display()))
}
