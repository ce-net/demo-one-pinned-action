//! `one-action-door serve [--addr 127.0.0.1:7811] [--data ./data]`: the page and its api.
//!
//! GET  /                     the page (also /demos/one-action/)
//! GET  /api/board            the board: last 50 lines, the build, the root key
//! POST /api/mint             {page, line, ttl_s} -> Minted (wire.ws-door Mint shape, one-action profile)
//! POST /api/prepare          {attempt, chain_hex, line} -> {draft, sign_hex, asks, minter}
//! POST /api/finish           {draft, sig_hex} -> Outcome (verdict, verifier error, CAL clause, trace)
//! GET  /api/source/board     the board cell's source: hash it to check the pinned build

use std::path::PathBuf;
use std::sync::Arc;

use axum::extract::State;
use axum::http::{StatusCode, header};
use axum::response::{Html, IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use one_action_door::{Attempt, Door};
use serde::Deserialize;
use serde_json::json;
use tokio::sync::Mutex;

const PAGE: &str = include_str!("../../../web/index.html");

type S = Arc<Mutex<Door>>;

fn now() -> u64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)
}

fn bad(e: String) -> Response {
    (StatusCode::BAD_REQUEST, Json(json!({ "error": e }))).into_response()
}

#[derive(Deserialize)]
struct MintReq {
    page: String,
    line: String,
    #[serde(default = "ttl")]
    ttl_s: u32,
}
fn ttl() -> u32 {
    600
}

#[derive(Deserialize)]
struct PrepareReq {
    attempt: String,
    chain_hex: String,
    line: String,
}

#[derive(Deserialize)]
struct FinishReq {
    draft: String,
    sig_hex: String,
}

async fn page() -> Html<&'static str> {
    Html(PAGE)
}

async fn board(State(s): State<S>) -> Response {
    let d = s.lock().await;
    let mut e = d.entries();
    let n = e.len();
    e.reverse();
    e.truncate(50);
    Json(json!({ "lines": e, "count": n, "build": board_append::build_id(), "root": cap_inspect::key_str(&d.root()) })).into_response()
}

async fn mint(State(s): State<S>, Json(r): Json<MintReq>) -> Response {
    match s.lock().await.mint(&r.page, &r.line, r.ttl_s, now()) {
        Ok(m) => Json(m).into_response(),
        Err(e) => bad(e),
    }
}

async fn prepare(State(s): State<S>, Json(r): Json<PrepareReq>) -> Response {
    let Some(a) = Attempt::parse(&r.attempt) else { return bad(format!("unknown attempt {}", r.attempt)) };
    match s.lock().await.prepare(a, &r.chain_hex, &r.line, now()) {
        Ok(p) => Json(p).into_response(),
        Err(e) => bad(e),
    }
}

async fn finish(State(s): State<S>, Json(r): Json<FinishReq>) -> Response {
    match s.lock().await.finish(&r.draft, &r.sig_hex, now()) {
        Ok(o) => Json(o).into_response(),
        Err(e) => bad(e),
    }
}

async fn source() -> Response {
    ([(header::CONTENT_TYPE, "text/plain; charset=utf-8")], board_append::SOURCE).into_response()
}

/// The page may be served from another origin (ce-net.com) than the door: allow it, and only it,
/// to call the api. `ONE_ACTION_ORIGIN` names it (default https://ce-net.com).
async fn cors(req: axum::extract::Request, next: axum::middleware::Next) -> Response {
    let allowed = std::env::var("ONE_ACTION_ORIGIN").unwrap_or_else(|_| "https://ce-net.com".into());
    let ok = req.headers().get(header::ORIGIN).and_then(|o| o.to_str().ok()) == Some(allowed.as_str());
    let mut r = if req.method() == axum::http::Method::OPTIONS { StatusCode::NO_CONTENT.into_response() } else { next.run(req).await };
    if ok {
        let h = r.headers_mut();
        h.insert(header::ACCESS_CONTROL_ALLOW_ORIGIN, allowed.parse().unwrap());
        h.insert(header::ACCESS_CONTROL_ALLOW_METHODS, "GET, POST".parse().unwrap());
        h.insert(header::ACCESS_CONTROL_ALLOW_HEADERS, "content-type".parse().unwrap());
    }
    r
}

async fn health() -> Response {
    Json(json!({ "ok": true, "version": env!("CARGO_PKG_VERSION"), "build": board_append::build_id() })).into_response()
}

#[tokio::main]
async fn main() {
    let a: Vec<String> = std::env::args().skip(1).collect();
    if a.first().map(String::as_str) != Some("serve") {
        eprintln!("usage: one-action-door serve [--addr 127.0.0.1:7811] [--data ./data]");
        std::process::exit(2);
    }
    let mut addr = std::env::var("ONE_ACTION_ADDR").unwrap_or_else(|_| "127.0.0.1:7811".into());
    let mut data = PathBuf::from(std::env::var("ONE_ACTION_DATA").unwrap_or_else(|_| "data".into()));
    let mut i = 1;
    while i + 1 < a.len() {
        match a[i].as_str() {
            "--addr" => addr = a[i + 1].clone(),
            "--data" => data = a[i + 1].clone().into(),
            _ => {}
        }
        i += 2;
    }
    let door = Door::open(&data).unwrap_or_else(|e| {
        eprintln!("one-action-door: {e}");
        std::process::exit(1)
    });
    eprintln!("one-action-door: root {}  board build {}  on http://{addr}/", cap_inspect::key_str(&door.root()), board_append::build_id());
    let s: S = Arc::new(Mutex::new(door));
    let app = Router::new()
        .route("/", get(page))
        .route("/demos/one-action", get(page))
        .route("/demos/one-action/", get(page))
        .route("/api/health", get(health))
        .route("/api/board", get(board))
        .route("/api/mint", post(mint))
        .route("/api/prepare", post(prepare))
        .route("/api/finish", post(finish))
        .route("/api/source/board", get(source))
        .layer(axum::middleware::from_fn(cors))
        .with_state(s);
    let l = tokio::net::TcpListener::bind(&addr).await.unwrap_or_else(|e| {
        eprintln!("one-action-door: bind {addr}: {e}");
        std::process::exit(1)
    });
    axum::serve(l, app).await.unwrap();
}
