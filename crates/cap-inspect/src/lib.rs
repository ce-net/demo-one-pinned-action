//! `cap.inspect@1`: what a cap v3 chain says and why a verifier accepts or refuses it.
//!
//! - [`inspect`]: every link decoded (issuer, audience, abilities, resource, expiry, typed
//!   caveats, delegation right) and every program body.
//! - [`cal`]: the chain written as CAL source, one clause per line, each with an id.
//! - [`trace`]: the verifier's checks one by one (decode, canonical form, each signature, the
//!   root, each child inside its parent, each expiry) and then `verify_chain_v3` itself.
//! - [`blame`]: the CAL clause that a refusal comes from, given the verifier's own error text and
//!   the request that was refused.
//!
//! Every verdict here is computed by `ce-net-proto`; this crate only lays it out.

use ce_net_proto::cap::Resource;
use ce_net_proto::program::{Hash, ResourceV3, Step};
use ce_net_proto::v3::narrow::{Parent, check_child};
use ce_net_proto::v3::sign::verify_sig;
use ce_net_proto::v3::verify::{Roots, verify_chain_v3};
use ce_net_proto::v3::{AudienceSet, Caveat, CapabilityV3, Key, Link, Sig, TokenV3, UsePer, canon};
use serde::Serialize;

/// A readable name for a key, when the caller knows one.
pub type Names<'a> = &'a dyn Fn(&Key) -> Option<String>;

pub fn key_str(k: &Key) -> String {
    match k {
        Key::Ed25519(b) => format!("ed25519:{}", hex::encode(b)),
        Key::P256(b) => format!("p256:{}", hex::encode(b)),
    }
}

fn short(k: &Key, names: Names) -> String {
    let s = key_str(k);
    match names(k) {
        Some(n) => format!("{n} ({}…)", &s[..20]),
        None => format!("{}…", &s[..24]),
    }
}

/// UTC `YYYY-MM-DDTHH:MM:SSZ` (civil-from-days, no time crate).
pub fn utc(t: u64) -> String {
    let (d, s) = ((t / 86_400) as i64, t % 86_400);
    let z = d + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = yoe + era * 400 + if month <= 2 { 1 } else { 0 };
    format!("{year:04}-{month:02}-{day:02}T{:02}:{:02}:{:02}Z", s / 3600, s / 60 % 60, s % 60)
}

#[derive(Debug, Clone, Serialize)]
pub struct LinkView {
    pub index: usize,
    pub version: u8,
    pub id: String,
    pub issuer: String,
    pub audience: String,
    pub abilities: Vec<String>,
    pub resource: String,
    pub not_after: u64,
    pub caveats: Vec<String>,
    pub delegate: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct Inspected {
    pub bytes: usize,
    pub links: Vec<LinkView>,
    pub programs: Vec<String>,
}

fn resource_str(r: &ResourceV3) -> String {
    match r {
        ResourceV3::Any => "any node".into(),
        ResourceV3::Node(n) => format!("node:{}", hex::encode(n)),
        ResourceV3::Nodes(ns) => ns.iter().map(|n| format!("node:{}", hex::encode(n))).collect::<Vec<_>>().join(", "),
        ResourceV3::Tag(t) => format!("nodes tagged {t}"),
        ResourceV3::AllOf(ts) => format!("nodes tagged all of {}", ts.join(", ")),
    }
}

fn v1_resource(r: &Resource) -> ResourceV3 {
    ce_net_proto::v3::narrow::resource_from_v1(r)
}

fn caveat_str(c: &Caveat) -> String {
    match c {
        Caveat::Uses { max, per } => format!("uses {max} per {}", if *per == UsePer::Link { "link" } else { "action" }),
        Caveat::Limits(ls) => format!("limits {}", ls.iter().map(|l| format!("{}={}", l.name, l.max)).collect::<Vec<_>>().join(", ")),
        Caveat::Egress(rs) => format!("egress {} rule(s)", rs.len()),
        Caveat::Programs(ids) => format!("only program {}", ids.iter().map(|h| format!("program:{}", hex::encode(h))).collect::<Vec<_>>().join(", ")),
        Caveat::Requires(r) => format!("requires {} proof(s)", r.len()),
        Caveat::CoSign(c) => format!("co-signed by {} key(s)", c.len()),
        Caveat::Via(v) => format!("via {} broker(s)", v.len()),
    }
}

fn audience_str(a: &AudienceSet, names: Names) -> String {
    match a {
        AudienceSet::Any => "anyone".into(),
        AudienceSet::Keys(ks) => ks.iter().map(|k| short(k, names)).collect::<Vec<_>>().join(", "),
    }
}

pub fn inspect(t: &TokenV3, names: Names) -> Inspected {
    let links = t
        .links
        .iter()
        .enumerate()
        .map(|(i, l)| match l {
            Link::V3 { cap, .. } => LinkView {
                index: i,
                version: 3,
                id: hex::encode(l.id()),
                issuer: short(&cap.issuer, names),
                audience: short(&cap.audience, names),
                abilities: cap.abilities.clone(),
                resource: resource_str(&cap.resource),
                not_after: cap.caveats.not_after,
                caveats: cap.ext.iter().map(caveat_str).collect(),
                delegate: cap.delegate.as_ref().map(|d| format!("{} to {}, {} deep", d.abilities.join(", "), audience_str(&d.audience, names), d.depth)),
            },
            Link::V1(s) => LinkView {
                index: i,
                version: 1,
                id: hex::encode(l.id()),
                issuer: short(&Key::Ed25519(s.cap.issuer), names),
                audience: short(&Key::Ed25519(s.cap.audience), names),
                abilities: s.cap.abilities.clone(),
                resource: resource_str(&v1_resource(&s.cap.resource)),
                not_after: s.cap.caveats.not_after,
                caveats: vec![],
                delegate: Some("v1: any holder may re-delegate".into()),
            },
        })
        .collect();
    let programs = t.programs.iter().map(|p| format!("program:{} ({} step(s))", hex::encode(p.id()), p.steps.len())).collect();
    Inspected { bytes: t.encode().len(), links, programs }
}

/// One line of CAL with the id a refusal can point at.
#[derive(Debug, Clone, Serialize)]
pub struct Clause {
    /// `program.op`, `program.request`, `link1.allow`, `link1.until`, `link1.uses`, `link1.only`,
    /// `link1.delegate`, `link1.on`, `link0.from` ...
    pub id: String,
    /// 1-based line in [`Cal::source`].
    pub line: usize,
}

#[derive(Debug, Clone, Serialize)]
pub struct Cal {
    pub source: String,
    pub clauses: Vec<Clause>,
}

/// Extra names CAL prints beside pinned values: a step's request body and the cell build it pins.
#[derive(Default)]
pub struct Pins {
    /// `(req_sha256, the body as text)`.
    pub bodies: Vec<(Hash, String)>,
    /// `(ce-ref of the cell source, sha256:<hex>)`.
    pub build: Option<(String, String)>,
}

/// The chain as CAL: the program bodies it binds, then one `grant` block per link, root first.
pub fn cal(t: &TokenV3, names: Names, pins: &Pins) -> Cal {
    let mut out: Vec<String> = Vec::new();
    let mut clauses = Vec::new();
    let mut put = |out: &mut Vec<String>, id: Option<String>, s: String| {
        out.push(s);
        if let Some(id) = id {
            clauses.push(Clause { id, line: out.len() });
        }
    };
    put(&mut out, None, "# CAL source of one cap v3 chain, rendered by cap.inspect@1.".into());
    put(&mut out, None, "# Every name is a ce-ref pinned by hash or key; check it with `cap-inspect`.".into());
    if let Some((r, sha)) = &pins.build {
        put(&mut out, None, String::new());
        put(&mut out, Some("pin.build".into()), format!("use cell:board.append@1 = {r} {sha}"));
    }
    for (pi, p) in t.programs.iter().enumerate() {
        put(&mut out, None, String::new());
        put(&mut out, Some(format!("program{pi}")), format!("program append-once {{   # program:{}", hex::encode(p.id())));
        for s in &p.steps {
            match s {
                Step::Call { on, api, op, req_sha256 } => {
                    put(&mut out, Some("program.op".into()), format!("  call cell:{api}@1 {op}"));
                    put(&mut out, Some("program.on".into()), format!("    on node:{}", hex::encode(on)));
                    put(&mut out, Some("program.request".into()), format!("    request sha256:{}", hex::encode(req_sha256)));
                    if let Some((_, body)) = pins.bodies.iter().find(|(h, _)| h == req_sha256) {
                        put(&mut out, None, format!("    # request = {body}"));
                    }
                }
                other => put(&mut out, Some("program.step".into()), format!("  {other:?}")),
            }
        }
        put(&mut out, None, "}".into());
    }
    for (i, l) in t.links.iter().enumerate() {
        let Link::V3 { cap, .. } = l else {
            put(&mut out, None, String::new());
            put(&mut out, Some(format!("link{i}")), format!("# link {i} is a v1 link"));
            continue;
        };
        let c = |k: &str| Some(format!("link{i}.{k}"));
        put(&mut out, None, String::new());
        put(&mut out, c("grant"), format!("grant link{i} {{   # id {}", hex::encode(&l.id()[..8])));
        put(&mut out, c("from"), format!("  from {}{}", key_str(&cap.issuer), names(&cap.issuer).map(|n| format!("   # {n}")).unwrap_or_default()));
        put(&mut out, c("to"), format!("  to {}{}", key_str(&cap.audience), names(&cap.audience).map(|n| format!("   # {n}")).unwrap_or_default()));
        if cap.abilities.is_empty() {
            put(&mut out, c("allow"), "  allow nothing itself".into());
        } else {
            put(&mut out, c("allow"), format!("  allow {}", cap.abilities.join(", ")));
        }
        put(&mut out, c("on"), format!("  on {}", resource_str(&cap.resource)));
        if cap.caveats.not_after != 0 {
            put(&mut out, c("until"), format!("  until {}", utc(cap.caveats.not_after)));
        }
        for e in &cap.ext {
            let id = match e {
                Caveat::Uses { .. } => "uses",
                Caveat::Programs(_) => "only",
                _ => "caveat",
            };
            let s = match e {
                Caveat::Programs(ids) if ids.len() == 1 && t.programs.first().is_some_and(|p| p.id() == ids[0]) => "only append-once".into(),
                e => caveat_str(e),
            };
            put(&mut out, c(id), format!("  {s}"));
        }
        match &cap.delegate {
            Some(d) => put(&mut out, c("delegate"), format!("  may grant {} to {}, {} deep", d.abilities.join(", "), audience_str(&d.audience, names), d.depth)),
            None => put(&mut out, c("delegate"), "  final".into()),
        }
        put(&mut out, None, "}".into());
    }
    let mut source = out.join("\n");
    source.push('\n');
    Cal { source, clauses }
}

/// One check of the trace.
#[derive(Debug, Clone, Serialize)]
pub struct Check {
    pub check: String,
    pub ok: bool,
    pub detail: String,
}

fn ck(out: &mut Vec<Check>, check: impl Into<String>, r: Result<String, String>) {
    let (ok, detail) = match r {
        Ok(d) => (true, d),
        Err(e) => (false, e),
    };
    out.push(Check { check: check.into(), ok, detail });
}

/// The verifier's checks one at a time, then `verify_chain_v3` itself (the verdict).
pub fn trace(t: &TokenV3, roots: &[Key], now: u64) -> (Vec<Check>, Result<(), String>) {
    let mut out = Vec::new();
    ck(&mut out, "canonical form", canon::check_token(t).map(|_| format!("{} link(s), {} program(s)", t.links.len(), t.programs.len())).map_err(|e| e.0));
    for (i, l) in t.links.iter().enumerate() {
        let r = match l {
            Link::V3 { cap, sig: sig @ (Sig::Ed25519(_) | Sig::P256(_)) } => verify_sig(cap, sig).map(|_| "valid".to_string()),
            Link::V3 { .. } => Ok("WebAuthn: checked against the owner roots by the verifier".into()),
            Link::V1(s) => s.verify_sig().map(|_| "valid".to_string()).map_err(|e| e.to_string()),
        };
        ck(&mut out, format!("link {i}: signature"), r);
    }
    if let Some(Link::V3 { cap, .. }) = t.links.first() {
        let ok = roots.contains(&cap.issuer);
        ck(&mut out, "link 0: root is accepted", if ok { Ok(key_str(&cap.issuer)) } else { Err("capability chain does not root at an accepted authority".into()) });
    }
    for i in 1..t.links.len() {
        if let Link::V3 { cap, .. } = &t.links[i] {
            ck(&mut out, format!("link {i}: inside link {}", i - 1), check_child(cap, &Parent::of(&t.links[i - 1])).map(|_| "no wider than its parent".into()));
        }
    }
    for (i, l) in t.links.iter().enumerate() {
        let c = match l {
            Link::V3 { cap, .. } => &cap.caveats,
            Link::V1(s) => &s.cap.caveats,
        };
        ck(&mut out, format!("link {i}: time"), c.valid_at(now).map(|_| if c.not_after == 0 { "no expiry".into() } else { format!("valid until {}", utc(c.not_after)) }));
    }
    let verdict = verify_chain_v3(t, &Roots { keys: roots, owners: &[] }, now, &|_, _| false).map(|_| ());
    ck(&mut out, "verify_chain_v3", verdict.clone().map(|_| "chain is valid".into()));
    (out, verdict)
}

/// The clause a refusal comes from. `error` is the verifier's (or minter's) own text; `asked` and
/// `granted` are the step that was requested and the program step the chain binds, when the
/// refusal was of a call. `t` is the chain that was refused.
pub fn blame(error: &str, t: &TokenV3, asked: Option<&Step>, granted: Option<&Step>) -> String {
    let leaf = t.links.len().saturating_sub(1);
    // "link i: ..." from the verifier names the link; a child is judged against its parent.
    let link_no = error.strip_prefix("link ").and_then(|r| r.split(':').next()).and_then(|n| n.parse::<usize>().ok());
    let parent = link_no.map(|i| i.saturating_sub(1)).unwrap_or(leaf);
    let parent = parent.min(t.links.len().saturating_sub(1));
    let leaf_cap = |i: usize| match t.links.get(i) {
        Some(Link::V3 { cap, .. }) => Some(cap.clone()),
        _ => None,
    };
    if error.contains("used up") || error.contains("already ran") {
        return format!("link{leaf}.uses");
    }
    if error.contains("expired") || error.contains("not yet valid") {
        return format!("link{leaf}.until");
    }
    if error.contains("is not program step") {
        if let (Some(Step::Call { op: a, req_sha256: ra, on: na, .. }), Some(Step::Call { op: g, req_sha256: rg, on: ng, .. })) = (asked, granted) {
            if a != g {
                return "program.op".into();
            }
            if na != ng {
                return "program.on".into();
            }
            if ra != rg {
                return "program.request".into();
            }
        }
        return format!("link{leaf}.only");
    }
    if error.contains("does not grant") {
        return format!("link{leaf}.allow");
    }
    if error.contains("abilities exceed") || error.contains("audience is outside") || error.contains("depth exceeds") || error.contains("grantable") || error.contains("may not delegate") {
        return format!("link{parent}.delegate");
    }
    if error.contains("caveats are broader") {
        // which caveat: compare the refused child with its parent
        if let (Some(i), Some(p)) = (link_no, leaf_cap(parent)) {
            if let Some(c) = leaf_cap(i) {
                return format!("link{parent}.{}", broader_axis(&c, &p));
            }
        }
        if let Some(p) = leaf_cap(parent) {
            let _ = p;
        }
        return format!("link{parent}.until");
    }
    if error.contains("resource is broader") {
        return format!("link{parent}.on");
    }
    if error.contains("root") {
        return "link0.from".into();
    }
    format!("link{leaf}.grant")
}

/// The caveat axis on which `child` is looser than `parent`.
pub fn broader_axis(child: &CapabilityV3, parent: &CapabilityV3) -> &'static str {
    let (c, p) = (&child.caveats, &parent.caveats);
    if p.not_after != 0 && (c.not_after == 0 || c.not_after > p.not_after) {
        return "until";
    }
    for pe in &parent.ext {
        let same = child.ext.iter().find(|ce| ce.index() == pe.index());
        if same != Some(pe) {
            return match pe {
                Caveat::Uses { .. } => "uses",
                Caveat::Programs(_) => "only",
                _ => "grant",
            };
        }
    }
    "grant"
}
