//! `board.append@1`: one public board, one line per call. This crate is the contract only: the
//! exact request bytes a capability pins, the entry the board keeps, and the op names.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

pub const API: &str = "board.append";
pub const MAJOR: u32 = 1;
/// The ce-ref of the cell by name and major version: what a caller writes before pinning a build.
pub const CELL_REF: &str = "cell:board.append@1";
/// Longest line the board accepts (bytes).
pub const MAX_LINE: usize = 140;

/// Ops the cell answers. Only `Append` is ever granted to a stranger.
pub const OP_APPEND: &str = "Append";
pub const OP_READ: &str = "Read";
pub const OP_DELETE: &str = "Delete";

/// The body of one call. Its canonical bytes are what a capability pins by SHA-256, so a chain
/// bound to one body authorizes that body and nothing else: this line, this cell, this build.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AppendBody {
    /// `board.append@1`.
    pub cell: String,
    /// `sha256:<hex>` of the board cell's source, the exact version the caller means.
    pub build: String,
    pub line: String,
}

impl AppendBody {
    pub fn new(build: &str, line: &str) -> AppendBody {
        AppendBody { cell: format!("{API}@{MAJOR}"), build: build.into(), line: line.into() }
    }

    /// Canonical bytes: compact JSON, fields in declared order.
    pub fn bytes(&self) -> Vec<u8> {
        serde_json::to_vec(self).expect("a struct of strings always serializes")
    }

    pub fn sha256(&self) -> [u8; 32] {
        Sha256::digest(self.bytes()).into()
    }
}

/// A line that is acceptable on a public board: 1..=140 bytes, printable, one line.
pub fn line_ok(line: &str) -> Result<(), String> {
    if line.trim().is_empty() {
        return Err("the line is empty".into());
    }
    if line.len() > MAX_LINE {
        return Err(format!("the line is longer than {MAX_LINE} bytes"));
    }
    if line.chars().any(|c| c.is_control()) {
        return Err("the line holds a control character".into());
    }
    Ok(())
}

/// One line on the board.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Entry {
    /// Unix seconds.
    pub at: u64,
    pub line: String,
    /// `ce3:<16 hex>`: SHA-256 of the capability chain that wrote it.
    pub fingerprint: String,
    /// `ed25519:<hex>` of the key that held the chain.
    pub holder: String,
    /// The board build that accepted it.
    pub build: String,
}

/// SHA-256 of a token's bytes, as the board prints it.
pub fn fingerprint(token_bytes: &[u8]) -> String {
    format!("ce3:{}", &hex::encode(Sha256::digest(token_bytes))[..16])
}
