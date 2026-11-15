# One pinned action

A stranger gets a key that can do exactly one thing: append one line to a public board, on one exact
build of the board cell, once, within ten minutes. The page offers six ways to widen it. Each one is
refused while you watch. The refusal text comes from the verifier on the server, and the page marks the
line of the key's policy (written in CAL) that caused it.

| Try | Refused by | Verifier's words | CAL line |
|---|---|---|---|
| Other op (Delete) | `authorize_v3` | `the request is not program step 0` | `call cell:board.append@1 Append` |
| Unpinned ref (any build) | `authorize_v3` | `the request is not program step 0` | `use cell:board.append@1 = repo:… sha256:…` |
| Other line | `authorize_v3` | `the request is not program step 0` | `request sha256:…` |
| Longer TTL (re-delegate for 30 days) | minter, then `verify_chain_v3` | `link 2: caveats are broader than the parent` | `until …` |
| Re-delegate wider (`board.append:*`) | minter, then `verify_chain_v3` | `link 2: abilities exceed the parent's grant` | `may grant board.append:Append …` |
| Replay after use | `authorize_v3` (burn log) | `capability used up` | `uses 1 per link` |
| Someone else's key | door (holder signature) | `the call is not signed by the chain's holder` | `to ed25519:…` |

The one allowed append lands on the board together with the chain's fingerprint (`ce3:<16 hex>`).

## Run it in under 5 minutes

You need Rust 1.85 or newer. The open capability crate [`ce-net-proto`](https://github.com/ce-net/ce-net-proto) comes in as a pinned git dependency.

```sh
git clone https://github.com/ce-net/demo-one-pinned-action
cd demo-one-pinned-action
cargo test --release                                          # the whole story as one test: 1 allowed, every widening refused
cargo run --release -p one-action-door -- serve --addr 127.0.0.1:7811 --data ./data
# open http://127.0.0.1:7811/   (or http://127.0.0.1:7811/?tour=hello to watch it press every button)
```

## Check a chain yourself

From the page, download `chain.hex` (the forged chain of a refused attempt also works) and `root.pub`, then:

```sh
cargo run --release -p cap-inspect -- chain.hex --root "$(cat root.pub)" --now <unix time> --cal
```

`cap-inspect` decodes every link, runs the verifier's checks one at a time (canonical form, each signature,
the root, each child inside its parent, each expiry), then `verify_chain_v3`, and prints the chain as CAL.
Exit 0 = valid, 1 = refused (reason printed). It runs offline and needs only the two files.

## How it is built

Every piece is a separate cell crate. The page and the door contain no policy logic.

| Crate | Cell | Job |
|---|---|---|
| `board-append-api` | `board.append@1` contract | The request body whose SHA-256 a key pins (`{cell, build, line}`), the entry, the op names |
| `board-append` | `board.append@1` | The board. A line lands only after `authorize_v3` passes: chain, node, holder, the exact program step, then the counted-use burn log. Its build id is the SHA-256 of its own source |
| `cap-inspect` | `cap.inspect@1` | Decodes a chain, renders it as CAL, traces the verifier's checks, and names the clause behind a refusal (`blame`) |
| `one-action-door` | the demo door | `Mint` takes the same `page, ttl_s` request as `wire.ws-door` Mint and returns the same answer: `link#g=<seed>.<chain>, not_after, browser_key`. Its one-action profile mints a cap v3 chain. Also the two-step attempt API and the page |

The key is a two-link cap v3 chain:

- link 0: the board owner (the root) gives the door `may grant board.append:Append`, on this node only.
- link 1: the door gives your browser key `allow board.append:Append`, `only` one program (a single
  `Call board.append Append` step pinned to the SHA-256 of the exact request body: your line, `board.append@1`,
  the board build), `uses 1 per link`, `until` ten minutes from now, and `may grant` the same to a friend at most 1 deep.

The browser key is created when you ask for a key. It travels in the URL fragment, which the browser never sends to a
server. To make a call, the page signs the exact bytes the door prepared with WebCrypto Ed25519. To re-delegate, it signs
the child link's `cap_bytes` and sends back only the signature.

## API

| | |
|---|---|
| `POST /api/mint` | `{page, line, ttl_s}` → `{link, not_after, browser_key, chain_hex, fingerprint, root, cal}` |
| `POST /api/prepare` | `{attempt, chain_hex, line}` → `{draft, sign_hex, asks, minter}`. `attempt` is one of `append`, `other-op`, `unpinned`, `other-line`, `longer-ttl`, `wider`, `replay` |
| `POST /api/finish` | `{draft, sig_hex}` → `{allowed, by, error, minter, clause, clause_line, cal, trace, entry, chain_hex}` |
| `GET /api/board` | the last 50 lines, the board build, the root key |
| `GET /api/source/board` | the board cell's source. Its SHA-256 is the pinned build |

## License

Apache-2.0. Author: Leif Rydenfalk.
